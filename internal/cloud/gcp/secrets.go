package gcp

import (
	"context"
	"fmt"

	cloudfunctions "google.golang.org/api/cloudfunctions/v1"
	run "google.golang.org/api/run/v1"

	"github.com/stxkxs/matlock/internal/cloud"
	"github.com/stxkxs/matlock/internal/secrets"
)

// cloudFunctionsAPI is the narrow Cloud Functions surface used by this package.
type cloudFunctionsAPI interface {
	ListFunctions(ctx context.Context, parent string) ([]*cloudfunctions.CloudFunction, error)
}

type cloudFunctionsAdapter struct{ svc *cloudfunctions.Service }

func (a *cloudFunctionsAdapter) ListFunctions(ctx context.Context, parent string) ([]*cloudfunctions.CloudFunction, error) {
	var out []*cloudfunctions.CloudFunction
	err := a.svc.Projects.Locations.Functions.List(parent).Pages(ctx, func(resp *cloudfunctions.ListFunctionsResponse) error {
		out = append(out, resp.Functions...)
		return nil
	})
	return out, err
}

// cloudRunV1API is the narrow Cloud Run v1 surface used here. Separate from
// cloudRunV2API in inventory.go because the v1 and v2 APIs expose different
// types (namespaces+services vs projects+locations+services).
type cloudRunV1API interface {
	ListServices(ctx context.Context, parent string) ([]*run.Service, error)
}

type cloudRunV1Adapter struct{ svc *run.APIService }

func (a *cloudRunV1Adapter) ListServices(ctx context.Context, parent string) ([]*run.Service, error) {
	resp, err := a.svc.Namespaces.Services.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp.Items, nil
}

// ScanSecrets checks Cloud Functions env, Cloud Run env, and Compute startup scripts for secrets.
func (p *Provider) ScanSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	var findings []cloud.SecretFinding

	if f, err := p.scanCloudFunctionSecrets(ctx); err != nil {
		return nil, fmt.Errorf("cloud functions secrets: %w", err)
	} else {
		findings = append(findings, f...)
	}

	if f, err := p.scanCloudRunSecrets(ctx); err != nil {
		return nil, fmt.Errorf("cloud run secrets: %w", err)
	} else {
		findings = append(findings, f...)
	}

	if f, err := p.scanComputeSecrets(ctx); err != nil {
		return nil, fmt.Errorf("compute secrets: %w", err)
	} else {
		findings = append(findings, f...)
	}

	return findings, nil
}

func (p *Provider) scanCloudFunctionSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	parent := fmt.Sprintf("projects/%s/locations/-", p.projectID)
	functions, err := p.cloudFunctions.ListFunctions(ctx, parent)
	if err != nil {
		return nil, fmt.Errorf("list functions: %w", err)
	}

	var findings []cloud.SecretFinding
	for _, fn := range functions {
		envVars := fn.EnvironmentVariables
		if len(envVars) == 0 {
			continue
		}
		for key, val := range envVars {
			for _, m := range secrets.Scan(val) {
				findings = append(findings, cloud.SecretFinding{
					Severity:     m.Severity,
					Type:         m.Type,
					Provider:     "gcp",
					Resource:     "cloud-function:" + fn.Name,
					ResourceType: "cloud_function_env",
					Region:       "",
					Key:          key,
					Match:        secrets.Redact(m.Value),
					Detail:       fmt.Sprintf("%s found in Cloud Function %q env var %q", m.Name, fn.Name, key),
					Remediation:  fmt.Sprintf("Move secret from env var %q to Secret Manager", key),
				})
			}
		}
	}
	return findings, nil
}

func (p *Provider) scanCloudRunSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	parent := fmt.Sprintf("namespaces/%s", p.projectID)
	services, err := p.cloudRunV1.ListServices(ctx, parent)
	if err != nil {
		return nil, fmt.Errorf("list cloud run services: %w", err)
	}

	var findings []cloud.SecretFinding
	for _, service := range services {
		if service.Spec == nil || service.Spec.Template == nil || service.Spec.Template.Spec == nil {
			continue
		}
		for _, container := range service.Spec.Template.Spec.Containers {
			for _, env := range container.Env {
				if env.Value == "" {
					continue
				}
				for _, m := range secrets.Scan(env.Value) {
					findings = append(findings, cloud.SecretFinding{
						Severity:     m.Severity,
						Type:         m.Type,
						Provider:     "gcp",
						Resource:     "cloud-run:" + service.Metadata.Name,
						ResourceType: "cloud_run_env",
						Region:       "",
						Key:          env.Name,
						Match:        secrets.Redact(m.Value),
						Detail:       fmt.Sprintf("%s found in Cloud Run service %q env var %q", m.Name, service.Metadata.Name, env.Name),
						Remediation:  fmt.Sprintf("Move secret from env var %q to Secret Manager and use secret volume mount", env.Name),
					})
				}
			}
		}
	}
	return findings, nil
}

func (p *Provider) scanComputeSecrets(ctx context.Context) ([]cloud.SecretFinding, error) {
	instancesByZone, err := p.compute.AggregatedInstances(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("list instances: %w", err)
	}

	var findings []cloud.SecretFinding
	for _, instances := range instancesByZone {
		for _, inst := range instances {
			if inst.Metadata == nil {
				continue
			}
			for _, item := range inst.Metadata.Items {
				if item.Value == nil {
					continue
				}
				val := *item.Value
				for _, m := range secrets.Scan(val) {
					findings = append(findings, cloud.SecretFinding{
						Severity:     m.Severity,
						Type:         m.Type,
						Provider:     "gcp",
						Resource:     "compute:" + inst.Name,
						ResourceType: "compute_metadata",
						Region:       inst.Zone,
						Key:          item.Key,
						Match:        secrets.Redact(m.Value),
						Detail:       fmt.Sprintf("%s found in Compute instance %q metadata key %q", m.Name, inst.Name, item.Key),
						Remediation:  "Remove secrets from instance metadata; use Secret Manager with appropriate IAM bindings",
					})
				}
			}
		}
	}
	return findings, nil
}
