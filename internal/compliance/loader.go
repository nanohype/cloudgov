package compliance

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// LoadIAMReport reads an IAM scan JSON report from disk.
func LoadIAMReport(path string) ([]cloud.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read IAM report: %w", err)
	}
	var report struct {
		Findings []cloud.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse IAM report: %w", err)
	}
	return report.Findings, nil
}

// LoadStorageReport reads a storage audit JSON report from disk.
func LoadStorageReport(path string) ([]cloud.BucketFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read storage report: %w", err)
	}
	var report struct {
		Findings []cloud.BucketFinding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse storage report: %w", err)
	}
	return report.Findings, nil
}

// LoadNetworkReport reads a network audit JSON report from disk.
func LoadNetworkReport(path string) ([]cloud.NetworkFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read network report: %w", err)
	}
	var report struct {
		Findings []cloud.NetworkFinding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse network report: %w", err)
	}
	return report.Findings, nil
}

// LoadCertsReport reads a certs audit JSON report from disk.
func LoadCertsReport(path string) ([]cloud.CertFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certs report: %w", err)
	}
	var report struct {
		Findings []cloud.CertFinding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse certs report: %w", err)
	}
	return report.Findings, nil
}

// LoadTagsReport reads a tags audit JSON report from disk.
func LoadTagsReport(path string) ([]cloud.TagFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tags report: %w", err)
	}
	var report struct {
		Findings []cloud.TagFinding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse tags report: %w", err)
	}
	return report.Findings, nil
}
