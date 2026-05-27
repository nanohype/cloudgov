package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/stxkxs/matlock/internal/cloud"
)

// lambdaPolicyMock extends the existing mockLambda with per-function policy
// responses keyed by function name.
type lambdaPolicyMock struct {
	mockLambda
	functions []lambdatypes.FunctionConfiguration
	policies  map[string]string // function name -> JSON policy
	missing   map[string]bool   // function names that should return a "no policy" error
	listErr   error
}

func (m *lambdaPolicyMock) ListFunctions(_ context.Context, _ *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return &lambda.ListFunctionsOutput{Functions: m.functions}, nil
}

func (m *lambdaPolicyMock) GetPolicy(_ context.Context, in *lambda.GetPolicyInput, _ ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	name := awssdk.ToString(in.FunctionName)
	if m.missing[name] {
		return nil, &lambdatypes.ResourceNotFoundException{}
	}
	if p, ok := m.policies[name]; ok {
		return &lambda.GetPolicyOutput{Policy: awssdk.String(p)}, nil
	}
	return nil, errors.New("not found")
}

func fn(name string) lambdatypes.FunctionConfiguration {
	return lambdatypes.FunctionConfiguration{
		FunctionName: awssdk.String(name),
		FunctionArn:  awssdk.String("arn:aws:lambda:us-east-1:123456789012:function:" + name),
	}
}

func TestAuditLambdaPolicies_PublicInvoke(t *testing.T) {
	policy := `{"Version":"2012-10-17","Id":"default","Statement":[{"Sid":"open","Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction","Resource":"arn:aws:lambda:us-east-1:123456789012:function:public"}]}`
	p := &Provider{lambda: &lambdaPolicyMock{
		functions: []lambdatypes.FunctionConfiguration{fn("public")},
		policies:  map[string]string{"public": policy},
	}}
	got, err := p.AuditLambdaPolicies(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Type != cloud.LambdaPublicInvoke || got[0].Severity != cloud.SeverityCritical {
		t.Errorf("expected one CRITICAL PUBLIC_INVOKE finding, got %v", got)
	}
}

func TestAuditLambdaPolicies_AWSWildcard(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"any-aws","Effect":"Allow","Principal":{"AWS":"*"},"Action":"lambda:InvokeFunction","Resource":"*"}]}`
	p := &Provider{lambda: &lambdaPolicyMock{
		functions: []lambdatypes.FunctionConfiguration{fn("any-aws")},
		policies:  map[string]string{"any-aws": policy},
	}}
	got, _ := p.AuditLambdaPolicies(context.Background())
	if len(got) != 1 || got[0].Type != cloud.LambdaPublicInvoke {
		t.Errorf("expected PUBLIC_INVOKE for AWS:*, got %v", got)
	}
}

func TestAuditLambdaPolicies_CrossAccount(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"x-acct","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:role/SomeRole"},"Action":"lambda:InvokeFunction","Resource":"*"}]}`
	p := &Provider{lambda: &lambdaPolicyMock{
		functions: []lambdatypes.FunctionConfiguration{fn("xacct")},
		policies:  map[string]string{"xacct": policy},
	}}
	got, _ := p.AuditLambdaPolicies(context.Background())
	if len(got) != 1 || got[0].Type != cloud.LambdaCrossAccount || got[0].Severity != cloud.SeverityHigh {
		t.Errorf("expected HIGH CROSS_ACCOUNT_INVOKE finding, got %v", got)
	}
}

func TestAuditLambdaPolicies_SameAccountPrincipalIsSilent(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"ok","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/MyRole"},"Action":"lambda:InvokeFunction","Resource":"*"}]}`
	p := &Provider{lambda: &lambdaPolicyMock{
		functions: []lambdatypes.FunctionConfiguration{fn("same-acct")},
		policies:  map[string]string{"same-acct": policy},
	}}
	got, _ := p.AuditLambdaPolicies(context.Background())
	if len(got) != 0 {
		t.Errorf("same-account principal should be silent, got %v", got)
	}
}

func TestAuditLambdaPolicies_ServiceWithoutSourceConditionIsConfusedDeputy(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"apigw","Effect":"Allow","Principal":{"Service":"apigateway.amazonaws.com"},"Action":"lambda:InvokeFunction","Resource":"*"}]}`
	p := &Provider{lambda: &lambdaPolicyMock{
		functions: []lambdatypes.FunctionConfiguration{fn("api")},
		policies:  map[string]string{"api": policy},
	}}
	got, _ := p.AuditLambdaPolicies(context.Background())
	if len(got) != 1 || got[0].Type != cloud.LambdaConfusedDeputy {
		t.Errorf("expected CONFUSED_DEPUTY_RISK, got %v", got)
	}
}

func TestAuditLambdaPolicies_ServiceWithSourceConditionIsSilent(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"apigw-safe","Effect":"Allow","Principal":{"Service":"apigateway.amazonaws.com"},"Action":"lambda:InvokeFunction","Resource":"*","Condition":{"StringEquals":{"aws:SourceAccount":"123456789012"}}}]}`
	p := &Provider{lambda: &lambdaPolicyMock{
		functions: []lambdatypes.FunctionConfiguration{fn("safe-api")},
		policies:  map[string]string{"safe-api": policy},
	}}
	got, _ := p.AuditLambdaPolicies(context.Background())
	if len(got) != 0 {
		t.Errorf("aws:SourceAccount condition should suppress confused-deputy finding, got %v", got)
	}
}

func TestAuditLambdaPolicies_WildcardAction(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"wide","Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"lambda:*","Resource":"*","Condition":{"StringEquals":{"aws:SourceAccount":"123456789012"}}}]}`
	p := &Provider{lambda: &lambdaPolicyMock{
		functions: []lambdatypes.FunctionConfiguration{fn("wild")},
		policies:  map[string]string{"wild": policy},
	}}
	got, _ := p.AuditLambdaPolicies(context.Background())
	if len(got) != 1 || got[0].Type != cloud.LambdaWildcardAction {
		t.Errorf("expected WILDCARD_ACTION finding, got %v", got)
	}
}

func TestAuditLambdaPolicies_DenyStatementIgnored(t *testing.T) {
	// Even with Principal: "*", a Deny statement isn't a public-invoke
	// finding (it's actually doing the opposite).
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"deny","Effect":"Deny","Principal":"*","Action":"lambda:InvokeFunction","Resource":"*"}]}`
	p := &Provider{lambda: &lambdaPolicyMock{
		functions: []lambdatypes.FunctionConfiguration{fn("deny")},
		policies:  map[string]string{"deny": policy},
	}}
	got, _ := p.AuditLambdaPolicies(context.Background())
	if len(got) != 0 {
		t.Errorf("Deny statements should be ignored, got %v", got)
	}
}

func TestAuditLambdaPolicies_NoPolicyIsSilent(t *testing.T) {
	p := &Provider{lambda: &lambdaPolicyMock{
		functions: []lambdatypes.FunctionConfiguration{fn("no-policy")},
		missing:   map[string]bool{"no-policy": true},
	}}
	got, err := p.AuditLambdaPolicies(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("functions without a resource policy should produce no findings, got %v", got)
	}
}

func TestAuditLambdaPolicies_ListFunctionsErrorBubblesUp(t *testing.T) {
	p := &Provider{lambda: &lambdaPolicyMock{listErr: errors.New("auth")}}
	_, err := p.AuditLambdaPolicies(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLambdaAccountFromArn(t *testing.T) {
	tests := []struct{ in, want string }{
		{"arn:aws:lambda:us-east-1:123456789012:function:foo", "123456789012"},
		{"arn:aws:iam::999888777666:role/X", "999888777666"},
		{"not-an-arn", ""},
		{"arn:aws", ""},
	}
	for _, tt := range tests {
		got := lambdaAccountFromArn(tt.in)
		if got != tt.want {
			t.Errorf("lambdaAccountFromArn(%q): got %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestHasSourceCondition(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"with SourceAccount", `{"StringEquals":{"aws:SourceAccount":"123"}}`, true},
		{"with SourceArn", `{"ArnLike":{"aws:SourceArn":"arn:..."}}`, true},
		{"unrelated", `{"StringEquals":{"aws:RequestTag/env":"prod"}}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasSourceCondition([]byte(tt.in))
			if got != tt.want {
				t.Errorf("hasSourceCondition(%q): got %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
