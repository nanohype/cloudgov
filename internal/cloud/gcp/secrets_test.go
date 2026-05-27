package gcp

import (
	"context"
	"errors"
	"testing"

	awssdk "google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/run/v1"
)

const fakeAWSSecretKey = "AKIAIOSFODNN7EXAMPLE"

type mockCloudFunctions struct {
	functions []*awssdk.CloudFunction
	err       error
}

func (m *mockCloudFunctions) ListFunctions(_ context.Context, _ string) ([]*awssdk.CloudFunction, error) {
	return m.functions, m.err
}

type mockCloudRunV1 struct {
	services []*run.Service
	err      error
}

func (m *mockCloudRunV1) ListServices(_ context.Context, _ string) ([]*run.Service, error) {
	return m.services, m.err
}

func emptySecretsProvider() *Provider {
	return &Provider{
		projectID:      "p",
		compute:        &mockCompute{},
		cloudFunctions: &mockCloudFunctions{},
		cloudRunV1:     &mockCloudRunV1{},
	}
}

func TestScanCloudFunctionSecrets(t *testing.T) {
	p := emptySecretsProvider()
	p.cloudFunctions = &mockCloudFunctions{functions: []*awssdk.CloudFunction{
		{Name: "leaky", EnvironmentVariables: map[string]string{"AWS_KEY": fakeAWSSecretKey}},
	}}
	got, err := p.scanCloudFunctionSecrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 || got[0].ResourceType != "cloud_function_env" {
		t.Errorf("expected cloud_function_env finding, got %v", got)
	}
}

func TestScanCloudRunSecrets(t *testing.T) {
	p := emptySecretsProvider()
	p.cloudRunV1 = &mockCloudRunV1{services: []*run.Service{
		{Metadata: &run.ObjectMeta{Name: "svc-a"},
			Spec: &run.ServiceSpec{Template: &run.RevisionTemplate{Spec: &run.RevisionSpec{
				Containers: []*run.Container{{Env: []*run.EnvVar{{Name: "TOKEN", Value: fakeAWSSecretKey}}}},
			}}}},
	}}
	got, err := p.scanCloudRunSecrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 || got[0].ResourceType != "cloud_run_env" {
		t.Errorf("expected cloud_run_env finding, got %v", got)
	}
}

func TestScanComputeSecrets(t *testing.T) {
	val := "export AWS_KEY=" + fakeAWSSecretKey
	p := emptySecretsProvider()
	p.compute = &mockCompute{
		instances: map[string][]*compute.Instance{
			"zones/us-central1-a": {{
				Name: "vm",
				Zone: "zones/us-central1-a",
				Metadata: &compute.Metadata{Items: []*compute.MetadataItems{
					{Key: "startup-script", Value: &val},
				}},
			}},
		},
	}
	got, err := p.scanComputeSecrets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 || got[0].ResourceType != "compute_metadata" {
		t.Errorf("expected compute_metadata finding, got %v", got)
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

func TestScanSecrets_ErrorAborts(t *testing.T) {
	p := emptySecretsProvider()
	p.cloudFunctions = &mockCloudFunctions{err: errors.New("auth")}
	_, err := p.ScanSecrets(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}
