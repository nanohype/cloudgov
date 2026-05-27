package gcp

import (
	"context"
	"fmt"

	"github.com/stxkxs/matlock/internal/cloud"
)

// AuditTags checks GCP compute instances and GCS buckets for missing required labels.
func (p *Provider) AuditTags(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	if p.projectID == "" {
		return nil, fmt.Errorf("GCP project ID is required")
	}
	if len(required) == 0 {
		return nil, nil
	}

	var findings []cloud.TagFinding

	instanceFindings, err := p.auditInstanceLabels(ctx, required)
	if err != nil {
		return nil, fmt.Errorf("instance labels: %w", err)
	}
	findings = append(findings, instanceFindings...)

	bucketFindings, err := p.auditBucketLabels(ctx, required)
	if err != nil {
		return nil, fmt.Errorf("bucket labels: %w", err)
	}
	findings = append(findings, bucketFindings...)

	return findings, nil
}

func (p *Provider) auditInstanceLabels(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	instancesByZone, err := p.compute.AggregatedInstances(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("list instances: %w", err)
	}

	var findings []cloud.TagFinding
	for _, instances := range instancesByZone {
		for _, inst := range instances {
			labelMap := make(map[string]struct{})
			for k := range inst.Labels {
				labelMap[k] = struct{}{}
			}
			missing := gcpMissingLabels(required, labelMap)
			if len(missing) == 0 {
				continue
			}
			zone := inst.Zone
			if idx := lastSlash(zone); idx >= 0 {
				zone = zone[idx+1:]
			}
			findings = append(findings, cloud.TagFinding{
				Severity:     cloud.SeverityMedium,
				Provider:     "gcp",
				ResourceID:   inst.Name,
				ResourceType: "compute:instance",
				Region:       zone,
				MissingTags:  missing,
				Detail:       fmt.Sprintf("instance %s missing labels: %v", inst.Name, missing),
			})
		}
	}
	return findings, nil
}

func (p *Provider) auditBucketLabels(ctx context.Context, required []string) ([]cloud.TagFinding, error) {
	gcs, err := p.newGCS(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage client: %w", err)
	}
	defer gcs.Close()

	buckets, err := gcs.ListBuckets(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	var findings []cloud.TagFinding
	for _, attrs := range buckets {
		labelMap := make(map[string]struct{})
		for k := range attrs.Labels {
			labelMap[k] = struct{}{}
		}
		missing := gcpMissingLabels(required, labelMap)
		if len(missing) == 0 {
			continue
		}
		findings = append(findings, cloud.TagFinding{
			Severity:     cloud.SeverityMedium,
			Provider:     "gcp",
			ResourceID:   attrs.Name,
			ResourceType: "gcs:bucket",
			Region:       attrs.Location,
			MissingTags:  missing,
			Detail:       fmt.Sprintf("bucket %s missing labels: %v", attrs.Name, missing),
		})
	}
	return findings, nil
}

func gcpMissingLabels(required []string, have map[string]struct{}) []string {
	var missing []string
	for _, label := range required {
		if _, ok := have[label]; !ok {
			missing = append(missing, label)
		}
	}
	return missing
}
