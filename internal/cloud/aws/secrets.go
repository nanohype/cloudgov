package aws

import (
	"context"
	"encoding/base64"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/stxkxs/matlock/internal/cloud"
	"github.com/stxkxs/matlock/internal/secrets"
)

// ssmAPI is the narrow SSM Parameter Store surface used by this package.
type ssmAPI interface {
	DescribeParameters(ctx context.Context, params *ssm.DescribeParametersInput, optFns ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error)
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// cloudFormationAPI is the narrow CloudFormation surface used by this package.
type cloudFormationAPI interface {
	ListStacks(ctx context.Context, params *cloudformation.ListStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.ListStacksOutput, error)
	DescribeStacks(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
}

// ScanSecrets checks Lambda env vars, ECS task definitions, EC2 user data,
// SSM non-SecureString parameters, and CloudFormation outputs for leaked secrets.
func (p *Provider) ScanSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	var findings []cloud.SecretFinding

	if f, err := p.scanLambdaSecrets(ctx); err != nil {
		return nil, fmt.Errorf("lambda secrets: %w", err)
	} else {
		findings = append(findings, f...)
	}

	if f, err := p.scanECSSecrets(ctx); err != nil {
		return nil, fmt.Errorf("ecs secrets: %w", err)
	} else {
		findings = append(findings, f...)
	}

	if f, err := p.scanEC2UserDataSecrets(ctx); err != nil {
		return nil, fmt.Errorf("ec2 userdata secrets: %w", err)
	} else {
		findings = append(findings, f...)
	}

	if f, err := p.scanSSMSecrets(ctx); err != nil {
		return nil, fmt.Errorf("ssm secrets: %w", err)
	} else {
		findings = append(findings, f...)
	}

	if f, err := p.scanCloudFormationSecrets(ctx); err != nil {
		return nil, fmt.Errorf("cloudformation secrets: %w", err)
	} else {
		findings = append(findings, f...)
	}

	return findings, nil
}

func (p *Provider) scanLambdaSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	var findings []cloud.SecretFinding

	paginator := lambda.NewListFunctionsPaginator(p.lambda, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("list functions: %w", err)
		}
		for _, fn := range page.Functions {
			name := awssdk.ToString(fn.FunctionName)
			if fn.Environment == nil || fn.Environment.Variables == nil {
				continue
			}
			for key, val := range fn.Environment.Variables {
				for _, m := range secrets.Scan(val) {
					findings = append(findings, cloud.SecretFinding{
						Severity:     m.Severity,
						Type:         m.Type,
						Provider:     "aws",
						Resource:     "lambda:" + name,
						ResourceType: "lambda_env",
						Region:       p.cfg.Region,
						Key:          key,
						Match:        secrets.Redact(m.Value),
						Detail:       fmt.Sprintf("%s found in Lambda function %q env var %q", m.Name, name, key),
						Remediation:  fmt.Sprintf("Move secret from env var %q to AWS Secrets Manager or SSM SecureString", key),
					})
				}
			}
		}
	}
	return findings, nil
}

func (p *Provider) scanECSSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	var findings []cloud.SecretFinding

	paginator := ecs.NewListTaskDefinitionsPaginator(p.ecs, &ecs.ListTaskDefinitionsInput{
		Status: ecstypes.TaskDefinitionStatusActive,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("list task definitions: %w", err)
		}
		for _, arn := range page.TaskDefinitionArns {
			descOut, err := p.ecs.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
				TaskDefinition: awssdk.String(arn),
			})
			if err != nil {
				continue
			}
			td := descOut.TaskDefinition
			if td == nil {
				continue
			}
			tdName := awssdk.ToString(td.Family)
			for _, container := range td.ContainerDefinitions {
				cName := awssdk.ToString(container.Name)
				for _, env := range container.Environment {
					key := awssdk.ToString(env.Name)
					val := awssdk.ToString(env.Value)
					for _, m := range secrets.Scan(val) {
						findings = append(findings, cloud.SecretFinding{
							Severity:     m.Severity,
							Type:         m.Type,
							Provider:     "aws",
							Resource:     "ecs:" + tdName + "/" + cName,
							ResourceType: "ecs_env",
							Region:       p.cfg.Region,
							Key:          key,
							Match:        secrets.Redact(m.Value),
							Detail:       fmt.Sprintf("%s found in ECS task %q container %q env var %q", m.Name, tdName, cName, key),
							Remediation:  fmt.Sprintf("Use ECS secrets (valueFrom) referencing Secrets Manager instead of plaintext env var %q", key),
						})
					}
				}
			}
		}
	}
	return findings, nil
}

func (p *Provider) scanEC2UserDataSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	var findings []cloud.SecretFinding

	paginator := ec2.NewDescribeInstancesPaginator(p.ec2, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("describe instances: %w", err)
		}
		for _, res := range page.Reservations {
			for _, inst := range res.Instances {
				instID := awssdk.ToString(inst.InstanceId)
				attrOut, err := p.ec2.DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{
					InstanceId: awssdk.String(instID),
					Attribute:  ec2types.InstanceAttributeNameUserData,
				})
				if err != nil {
					continue
				}
				if attrOut.UserData == nil || attrOut.UserData.Value == nil {
					continue
				}
				decoded, err := base64.StdEncoding.DecodeString(awssdk.ToString(attrOut.UserData.Value))
				if err != nil {
					continue
				}
				userData := string(decoded)
				for _, m := range secrets.Scan(userData) {
					findings = append(findings, cloud.SecretFinding{
						Severity:     m.Severity,
						Type:         m.Type,
						Provider:     "aws",
						Resource:     "ec2:" + instID,
						ResourceType: "ec2_userdata",
						Region:       p.cfg.Region,
						Key:          "userData",
						Match:        secrets.Redact(m.Value),
						Detail:       fmt.Sprintf("%s found in EC2 instance %q user data", m.Name, instID),
						Remediation:  "Remove secrets from user data; use IAM instance profiles or Secrets Manager instead",
					})
				}
			}
		}
	}
	return findings, nil
}

func (p *Provider) scanSSMSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	var findings []cloud.SecretFinding

	paginator := ssm.NewDescribeParametersPaginator(p.ssm, &ssm.DescribeParametersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("describe parameters: %w", err)
		}
		for _, param := range page.Parameters {
			if param.Type == ssmtypes.ParameterTypeSecureString {
				continue
			}
			name := awssdk.ToString(param.Name)
			getOut, err := p.ssm.GetParameter(ctx, &ssm.GetParameterInput{
				Name: awssdk.String(name),
			})
			if err != nil {
				continue
			}
			val := awssdk.ToString(getOut.Parameter.Value)
			for _, m := range secrets.Scan(val) {
				findings = append(findings, cloud.SecretFinding{
					Severity:     m.Severity,
					Type:         m.Type,
					Provider:     "aws",
					Resource:     "ssm:" + name,
					ResourceType: "ssm_parameter",
					Region:       p.cfg.Region,
					Key:          name,
					Match:        secrets.Redact(m.Value),
					Detail:       fmt.Sprintf("%s found in SSM parameter %q (type %s, should be SecureString)", m.Name, name, param.Type),
					Remediation:  fmt.Sprintf("Recreate parameter %q as SecureString type", name),
				})
			}
		}
	}
	return findings, nil
}

func (p *Provider) scanCloudFormationSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	var findings []cloud.SecretFinding

	paginator := cloudformation.NewListStacksPaginator(p.cloudformation, &cloudformation.ListStacksInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("list stacks: %w", err)
		}
		for _, summary := range page.StackSummaries {
			stackName := awssdk.ToString(summary.StackName)
			descOut, err := p.cloudformation.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{
				StackName: awssdk.String(stackName),
			})
			if err != nil {
				continue
			}
			for _, stack := range descOut.Stacks {
				for _, output := range stack.Outputs {
					key := awssdk.ToString(output.OutputKey)
					val := awssdk.ToString(output.OutputValue)
					for _, m := range secrets.Scan(val) {
						findings = append(findings, cloud.SecretFinding{
							Severity:     m.Severity,
							Type:         m.Type,
							Provider:     "aws",
							Resource:     "cloudformation:" + stackName,
							ResourceType: "cloudformation_output",
							Region:       p.cfg.Region,
							Key:          key,
							Match:        secrets.Redact(m.Value),
							Detail:       fmt.Sprintf("%s found in CloudFormation stack %q output %q", m.Name, stackName, key),
							Remediation:  "Remove secrets from CloudFormation outputs; use dynamic references to Secrets Manager",
						})
					}
				}
			}
		}
	}
	return findings, nil
}
