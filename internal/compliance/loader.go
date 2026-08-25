package compliance

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// A scan report carries two things: what was found, and what could not be read.
// Reading only the first turns a partial scan into a compliant verdict — the
// control the scanner could not evaluate is indistinguishable from the control
// it evaluated and passed, and compliance is the surface where that distinction
// carries the most weight. Every loader returns both.
//
// LoadIAMReport reads an IAM scan JSON report from disk.
func LoadIAMReport(path string) ([]cloud.Finding, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read IAM report: %w", err)
	}
	var report struct {
		Findings   []cloud.Finding `json:"findings"`
		Incomplete []string        `json:"incomplete"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, nil, fmt.Errorf("parse IAM report: %w", err)
	}
	return report.Findings, report.Incomplete, nil
}

// LoadStorageReport reads a storage audit JSON report from disk.
func LoadStorageReport(path string) ([]cloud.BucketFinding, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read storage report: %w", err)
	}
	var report struct {
		Findings   []cloud.BucketFinding `json:"findings"`
		Incomplete []string              `json:"incomplete"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, nil, fmt.Errorf("parse storage report: %w", err)
	}
	return report.Findings, report.Incomplete, nil
}

// LoadNetworkReport reads a network audit JSON report from disk.
func LoadNetworkReport(path string) ([]cloud.NetworkFinding, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read network report: %w", err)
	}
	var report struct {
		Findings   []cloud.NetworkFinding `json:"findings"`
		Incomplete []string               `json:"incomplete"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, nil, fmt.Errorf("parse network report: %w", err)
	}
	return report.Findings, report.Incomplete, nil
}

// LoadCertsReport reads a certs audit JSON report from disk.
func LoadCertsReport(path string) ([]cloud.CertFinding, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read certs report: %w", err)
	}
	var report struct {
		Findings   []cloud.CertFinding `json:"findings"`
		Incomplete []string            `json:"incomplete"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, nil, fmt.Errorf("parse certs report: %w", err)
	}
	return report.Findings, report.Incomplete, nil
}

// LoadTagsReport reads a tags audit JSON report from disk.
func LoadTagsReport(path string) ([]cloud.TagFinding, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read tags report: %w", err)
	}
	var report struct {
		Findings   []cloud.TagFinding `json:"findings"`
		Incomplete []string           `json:"incomplete"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, nil, fmt.Errorf("parse tags report: %w", err)
	}
	return report.Findings, report.Incomplete, nil
}
