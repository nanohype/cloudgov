package aws

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// A real-looking AWS secret pattern that secrets.Scan should detect.
const fakeAWSKey = "AKIAIOSFODNN7EXAMPLE"

type secretsMockLambda struct {
	functions []lambdatypes.FunctionConfiguration
}

func (m *secretsMockLambda) ListFunctions(_ context.Context, _ *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{Functions: m.functions}, nil
}
func (m *secretsMockLambda) ListTags(_ context.Context, _ *lambda.ListTagsInput, _ ...func(*lambda.Options)) (*lambda.ListTagsOutput, error) {
	return &lambda.ListTagsOutput{}, nil
}
func (m *secretsMockLambda) GetAccountSettings(_ context.Context, _ *lambda.GetAccountSettingsInput, _ ...func(*lambda.Options)) (*lambda.GetAccountSettingsOutput, error) {
	return &lambda.GetAccountSettingsOutput{}, nil
}
func (m *secretsMockLambda) GetPolicy(_ context.Context, _ *lambda.GetPolicyInput, _ ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	return &lambda.GetPolicyOutput{}, nil
}

type secretsMockECS struct {
	arns []string
	td   *ecstypes.TaskDefinition
}

func (m *secretsMockECS) ListClusters(_ context.Context, _ *ecs.ListClustersInput, _ ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{}, nil
}
func (m *secretsMockECS) DescribeClusters(_ context.Context, _ *ecs.DescribeClustersInput, _ ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error) {
	return &ecs.DescribeClustersOutput{}, nil
}
func (m *secretsMockECS) ListTaskDefinitions(_ context.Context, _ *ecs.ListTaskDefinitionsInput, _ ...func(*ecs.Options)) (*ecs.ListTaskDefinitionsOutput, error) {
	return &ecs.ListTaskDefinitionsOutput{TaskDefinitionArns: m.arns}, nil
}
func (m *secretsMockECS) DescribeTaskDefinition(_ context.Context, _ *ecs.DescribeTaskDefinitionInput, _ ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	if m.td == nil {
		return &ecs.DescribeTaskDefinitionOutput{}, nil
	}
	return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: m.td}, nil
}

type secretsMockEC2 struct {
	mockEC2
	instances []ec2types.Instance
	userData  string // base64-encoded
}

func (m *secretsMockEC2) DescribeInstances(_ context.Context, _ *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: m.instances}}}, nil
}
func (m *secretsMockEC2) DescribeInstanceAttribute(_ context.Context, _ *ec2.DescribeInstanceAttributeInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceAttributeOutput, error) {
	if m.userData == "" {
		return &ec2.DescribeInstanceAttributeOutput{}, nil
	}
	return &ec2.DescribeInstanceAttributeOutput{
		UserData: &ec2types.AttributeValue{Value: awssdk.String(m.userData)},
	}, nil
}

type secretsMockSSM struct {
	params  []ssmtypes.ParameterMetadata
	values  map[string]string
	listErr error
}

func (m *secretsMockSSM) DescribeParameters(_ context.Context, _ *ssm.DescribeParametersInput, _ ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return &ssm.DescribeParametersOutput{Parameters: m.params}, nil
}
func (m *secretsMockSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	v, ok := m.values[awssdk.ToString(in.Name)]
	if !ok {
		return nil, errors.New("not found")
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: awssdk.String(v)}}, nil
}

type secretsMockCFN struct {
	stacks  []cftypes.StackSummary
	descs   map[string][]cftypes.Output
	listErr error
}

func (m *secretsMockCFN) ListStacks(_ context.Context, _ *cloudformation.ListStacksInput, _ ...func(*cloudformation.Options)) (*cloudformation.ListStacksOutput, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return &cloudformation.ListStacksOutput{StackSummaries: m.stacks}, nil
}
func (m *secretsMockCFN) DescribeStacks(_ context.Context, in *cloudformation.DescribeStacksInput, _ ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
	name := awssdk.ToString(in.StackName)
	if outs, ok := m.descs[name]; ok {
		return &cloudformation.DescribeStacksOutput{Stacks: []cftypes.Stack{{Outputs: outs, StackName: awssdk.String(name)}}}, nil
	}
	return &cloudformation.DescribeStacksOutput{}, nil
}

func emptySecretsProvider() *Provider {
	return &Provider{
		lambda:         &secretsMockLambda{},
		ecs:            &secretsMockECS{},
		ec2:            &secretsMockEC2{},
		ssm:            &secretsMockSSM{},
		cloudformation: &secretsMockCFN{},
	}
}

func TestScanLambdaSecrets(t *testing.T) {
	p := emptySecretsProvider()
	p.lambda = &secretsMockLambda{functions: []lambdatypes.FunctionConfiguration{
		{
			FunctionName: awssdk.String("leaky"),
			Environment:  &lambdatypes.EnvironmentResponse{Variables: map[string]string{"AWS_KEY": fakeAWSKey}},
		},
	}}
	got, err := p.scanLambdaSecrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Fatalf("expected at least one finding, got %v", got)
	}
	if got[0].ResourceType != "lambda_env" || got[0].Provider != "aws" {
		t.Errorf("finding: %+v", got[0])
	}
}

func TestScanLambdaSecrets_NoEnv(t *testing.T) {
	p := emptySecretsProvider()
	p.lambda = &secretsMockLambda{functions: []lambdatypes.FunctionConfiguration{
		{FunctionName: awssdk.String("clean")},
	}}
	got, _ := p.scanLambdaSecrets(context.Background())
	if len(got) != 0 {
		t.Errorf("expected no findings, got %v", got)
	}
}

func TestScanECSSecrets(t *testing.T) {
	p := emptySecretsProvider()
	p.ecs = &secretsMockECS{
		arns: []string{"arn:td/1"},
		td: &ecstypes.TaskDefinition{
			Family: awssdk.String("backend"),
			ContainerDefinitions: []ecstypes.ContainerDefinition{
				{Name: awssdk.String("app"), Environment: []ecstypes.KeyValuePair{
					{Name: awssdk.String("AWS_KEY"), Value: awssdk.String(fakeAWSKey)},
				}},
			},
		},
	}
	got, err := p.scanECSSecrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 || got[0].ResourceType != "ecs_env" {
		t.Errorf("expected ecs_env finding, got %v", got)
	}
}

func TestScanEC2UserDataSecrets(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("#!/bin/sh\nexport AWS_KEY=" + fakeAWSKey))
	p := emptySecretsProvider()
	p.ec2 = &secretsMockEC2{
		instances: []ec2types.Instance{{InstanceId: awssdk.String("i-1")}},
		userData:  encoded,
	}
	got, err := p.scanEC2UserDataSecrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 || got[0].ResourceType != "ec2_userdata" {
		t.Errorf("expected ec2_userdata finding, got %v", got)
	}
}

func TestScanSSMSecrets_SecureStringSkipped(t *testing.T) {
	p := emptySecretsProvider()
	p.ssm = &secretsMockSSM{
		params: []ssmtypes.ParameterMetadata{
			{Name: awssdk.String("encrypted"), Type: ssmtypes.ParameterTypeSecureString},
			{Name: awssdk.String("plaintext"), Type: ssmtypes.ParameterTypeString},
		},
		values: map[string]string{"plaintext": fakeAWSKey},
	}
	got, err := p.scanSSMSecrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Key != "plaintext" {
		t.Errorf("expected one finding on plaintext param, got %v", got)
	}
}

func TestScanCloudFormationSecrets(t *testing.T) {
	p := emptySecretsProvider()
	p.cloudformation = &secretsMockCFN{
		stacks: []cftypes.StackSummary{{StackName: awssdk.String("mystack")}},
		descs: map[string][]cftypes.Output{
			"mystack": {{OutputKey: awssdk.String("ApiKey"), OutputValue: awssdk.String(fakeAWSKey)}},
		},
	}
	got, err := p.scanCloudFormationSecrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 || got[0].ResourceType != "cloudformation_output" {
		t.Errorf("expected cloudformation_output finding, got %v", got)
	}
}

func TestScanSecrets_AllDomains(t *testing.T) {
	p := emptySecretsProvider()
	got, err := p.ScanSecrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected no findings in empty environment, got %v", got)
	}
}

func TestScanSecrets_ErrorInOneDomainAborts(t *testing.T) {
	p := emptySecretsProvider()
	p.ssm = &secretsMockSSM{listErr: errors.New("auth")}
	_, err := p.ScanSecrets(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}
