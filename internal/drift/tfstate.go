package drift

import (
	"encoding/json"
	"fmt"
	"os"
)

// TFStateV4 is a minimal representation of Terraform state v4.
type TFStateV4 struct {
	Version   int         `json:"version"`
	Resources []TFStateResource `json:"resources"`
}

// TFStateResource is a single resource in the state file.
type TFStateResource struct {
	Mode      string            `json:"mode"` // "managed" or "data"
	Type      string            `json:"type"` // "aws_security_group"
	Name      string            `json:"name"` // "web"
	Provider  string            `json:"provider"`
	Instances []TFStateInstance  `json:"instances"`
}

// TFStateInstance is a single instance of a resource.
type TFStateInstance struct {
	Attributes map[string]interface{} `json:"attributes"`
}

// ParsedResource holds parsed info for a single Terraform resource instance.
type ParsedResource struct {
	Address      string                 // "aws_security_group.web"
	Type         string                 // "aws_security_group"
	Provider     string                 // "aws" | "gcp" | "azure"
	ID           string                 // cloud resource ID from attributes
	Attributes   map[string]interface{} // full attributes map
}

// ParseTFState reads and parses a Terraform state v4 JSON file.
func ParseTFState(path string) ([]ParsedResource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tfstate: %w", err)
	}
	return ParseTFStateBytes(data)
}

// ParseTFStateBytes parses Terraform state v4 JSON bytes.
func ParseTFStateBytes(data []byte) ([]ParsedResource, error) {
	var state TFStateV4
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse tfstate JSON: %w", err)
	}
	if state.Version != 4 {
		return nil, fmt.Errorf("unsupported tfstate version %d (only v4 supported)", state.Version)
	}

	var resources []ParsedResource
	for _, res := range state.Resources {
		if res.Mode != "managed" {
			continue
		}
		provider := extractProvider(res.Provider, res.Type)
		for _, inst := range res.Instances {
			id := extractID(inst.Attributes)
			resources = append(resources, ParsedResource{
				Address:    res.Type + "." + res.Name,
				Type:       res.Type,
				Provider:   provider,
				ID:         id,
				Attributes: inst.Attributes,
			})
		}
	}
	return resources, nil
}

func extractProvider(providerStr, resourceType string) string {
	// Try to infer from resource type prefix
	switch {
	case len(resourceType) > 4 && resourceType[:4] == "aws_":
		return "aws"
	case len(resourceType) > 7 && resourceType[:7] == "google_":
		return "gcp"
	case len(resourceType) > 8 && resourceType[:8] == "azurerm_":
		return "azure"
	}
	return providerStr
}

func extractID(attrs map[string]interface{}) string {
	if id, ok := attrs["id"]; ok {
		if s, ok := id.(string); ok {
			return s
		}
	}
	return ""
}
