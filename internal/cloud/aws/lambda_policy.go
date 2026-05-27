package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	smithy "github.com/aws/smithy-go"

	"github.com/stxkxs/matlock/internal/cloud"
)

// lambdaResourcePolicy is the JSON shape returned by lambda:GetPolicy.
type lambdaResourcePolicy struct {
	Version   string             `json:"Version"`
	ID        string             `json:"Id"`
	Statement []lambdaPolicyStmt `json:"Statement"`
}

// lambdaPolicyStmt mirrors the JSON shape; Principal/Condition are kept as
// RawMessage because AWS uses three different shapes for Principal
// ("*", {"AWS": "..."}, {"Service": "..."}) and Condition is nested maps.
type lambdaPolicyStmt struct {
	Sid       string          `json:"Sid"`
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Action    json.RawMessage `json:"Action"`
	Resource  json.RawMessage `json:"Resource"`
	Condition json.RawMessage `json:"Condition"`
}

// AuditLambdaPolicies enumerates Lambda functions and inspects each one's
// resource-based policy (lambda:GetPolicy) for patterns that grant invoke
// permission too widely. Identity-based permissions for the execution role
// are NOT checked here — that's IAMProvider's job.
//
// Patterns flagged:
//   - Principal: "*"                                           → CRITICAL public invoke
//   - Principal: {"AWS": "*"}                                  → CRITICAL public invoke
//   - Principal: {"Service": "..."} without SourceAccount      → HIGH confused deputy
//   - Principal: {"AWS": "arn:aws:iam::OTHER:..."}             → HIGH cross-account
//   - Action containing "*" or "lambda:*"                      → HIGH wildcard
//
// Functions without a resource policy (NoSuchEntity / ResourceNotFoundException)
// are silently skipped — they're only reachable via identity-based IAM.
func (p *Provider) AuditLambdaPolicies(ctx context.Context) ([]cloud.LambdaPolicyFinding, error) {
	var findings []cloud.LambdaPolicyFinding
	var marker *string
	for {
		page, err := p.lambda.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return findings, fmt.Errorf("list functions: %w", err)
		}
		for _, fn := range page.Functions {
			fnName := awssdk.ToString(fn.FunctionName)
			fnArn := awssdk.ToString(fn.FunctionArn)
			policyOut, err := p.lambda.GetPolicy(ctx, &lambda.GetPolicyInput{
				FunctionName: awssdk.String(fnName),
			})
			if err != nil {
				if isLambdaPolicyMissing(err) {
					continue // no resource policy — not a finding
				}
				continue // other errors (e.g. AccessDenied on one fn) shouldn't abort the scan
			}
			if policyOut.Policy == nil {
				continue
			}
			var doc lambdaResourcePolicy
			if err := json.Unmarshal([]byte(*policyOut.Policy), &doc); err != nil {
				continue
			}
			findings = append(findings, p.classifyLambdaPolicy(fnName, fnArn, doc)...)
		}
		if page.NextMarker == nil {
			break
		}
		marker = page.NextMarker
	}
	return findings, nil
}

func (p *Provider) classifyLambdaPolicy(fnName, fnArn string, doc lambdaResourcePolicy) []cloud.LambdaPolicyFinding {
	var findings []cloud.LambdaPolicyFinding
	region := p.cfg.Region
	myAccount := lambdaAccountFromArn(fnArn)

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		// Wildcard action — Action: "*" or lambda:*
		actions := toStringSlice(stmt.Action)
		for _, a := range actions {
			if a == "*" || a == "lambda:*" {
				findings = append(findings, cloud.LambdaPolicyFinding{
					Severity:     cloud.SeverityHigh,
					Type:         cloud.LambdaWildcardAction,
					Provider:     "aws",
					FunctionName: fnName,
					FunctionArn:  fnArn,
					Region:       region,
					StatementID:  stmt.Sid,
					Detail:       fmt.Sprintf("statement %q grants action %q on the function", stmt.Sid, a),
					Remediation:  fmt.Sprintf("aws lambda remove-permission --function-name %s --statement-id %s", fnName, stmt.Sid),
				})
			}
		}

		// Principal "*" → public invoke
		var pStr string
		if err := json.Unmarshal(stmt.Principal, &pStr); err == nil && pStr == "*" {
			findings = append(findings, cloud.LambdaPolicyFinding{
				Severity:     cloud.SeverityCritical,
				Type:         cloud.LambdaPublicInvoke,
				Provider:     "aws",
				FunctionName: fnName,
				FunctionArn:  fnArn,
				Region:       region,
				StatementID:  stmt.Sid,
				Detail:       "statement grants invoke to Principal: \"*\" — anyone can call this function",
				Remediation:  fmt.Sprintf("aws lambda remove-permission --function-name %s --statement-id %s", fnName, stmt.Sid),
			})
			continue
		}

		// Principal as object: {"AWS": "..."} or {"Service": "..."}
		var pObj map[string]json.RawMessage
		if err := json.Unmarshal(stmt.Principal, &pObj); err == nil {
			for kind, raw := range pObj {
				principals := toStringSlice(raw)
				for _, principal := range principals {
					switch kind {
					case "AWS":
						if principal == "*" {
							findings = append(findings, cloud.LambdaPolicyFinding{
								Severity:     cloud.SeverityCritical,
								Type:         cloud.LambdaPublicInvoke,
								Provider:     "aws",
								FunctionName: fnName,
								FunctionArn:  fnArn,
								Region:       region,
								StatementID:  stmt.Sid,
								Detail:       "statement grants invoke to {\"AWS\": \"*\"} — any AWS account can call this function",
								Remediation:  fmt.Sprintf("aws lambda remove-permission --function-name %s --statement-id %s", fnName, stmt.Sid),
							})
							continue
						}
						// arn:aws:iam::ACCOUNT:user/role — cross-account if ACCOUNT != my own
						acct := lambdaAccountFromArn(principal)
						if acct != "" && myAccount != "" && acct != myAccount {
							findings = append(findings, cloud.LambdaPolicyFinding{
								Severity:     cloud.SeverityHigh,
								Type:         cloud.LambdaCrossAccount,
								Provider:     "aws",
								FunctionName: fnName,
								FunctionArn:  fnArn,
								Region:       region,
								StatementID:  stmt.Sid,
								Detail:       fmt.Sprintf("statement grants invoke to cross-account principal %s (account %s, this function is in %s)", principal, acct, myAccount),
								Remediation:  "verify the cross-account trust is intentional; ensure the consuming account has a confused-deputy mitigation",
							})
						}
					case "Service":
						// service-principal invoke (e.g. apigateway, s3, events) — flag
						// when SourceAccount/SourceArn conditions are absent.
						if !hasSourceCondition(stmt.Condition) {
							findings = append(findings, cloud.LambdaPolicyFinding{
								Severity:     cloud.SeverityHigh,
								Type:         cloud.LambdaConfusedDeputy,
								Provider:     "aws",
								FunctionName: fnName,
								FunctionArn:  fnArn,
								Region:       region,
								StatementID:  stmt.Sid,
								Detail:       fmt.Sprintf("statement grants invoke to service %q without SourceAccount or SourceArn condition — confused-deputy risk", principal),
								Remediation:  fmt.Sprintf("aws lambda update-function-configuration or rewrite the permission to include a Condition with aws:SourceAccount = %s and/or aws:SourceArn", myAccount),
							})
						}
					}
				}
			}
		}
	}
	return findings
}

// isLambdaPolicyMissing detects the ResourceNotFoundException AWS returns when
// a function has no resource policy attached. Treated as "no finding" rather
// than as an error.
func isLambdaPolicyMissing(err error) bool {
	var notFound *lambdatypes.ResourceNotFoundException
	if errors.As(err, &notFound) {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "ResourceNotFoundException", "NoSuchEntity":
			return true
		}
	}
	return false
}

// lambdaAccountFromArn extracts the 12-digit account number from an ARN like
// arn:aws:lambda:us-east-1:123456789012:function:foo. Returns "" if not a
// recognizable ARN.
func lambdaAccountFromArn(arn string) string {
	// arn:partition:service:region:account-id:resource
	var parts [6]string
	idx := 0
	last := 0
	for i := 0; i < len(arn) && idx < 6; i++ {
		if arn[i] == ':' {
			parts[idx] = arn[last:i]
			idx++
			last = i + 1
		}
	}
	if idx < 5 {
		return ""
	}
	return parts[4]
}

// hasSourceCondition reports whether a Condition block contains
// aws:SourceAccount or aws:SourceArn (the keys that mitigate confused-deputy).
func hasSourceCondition(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	// Condition: { "StringEquals": { "aws:SourceAccount": "..." }, ... }
	var outer map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &outer); err != nil {
		return false
	}
	for _, inner := range outer {
		for key := range inner {
			switch key {
			case "aws:SourceAccount", "AWS:SourceAccount",
				"aws:SourceArn", "AWS:SourceArn":
				return true
			}
		}
	}
	return false
}
