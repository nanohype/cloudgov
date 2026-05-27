package drift

import (
	"testing"
)

func TestParseTFStateBytes(t *testing.T) {
	data := []byte(`{
		"version": 4,
		"resources": [
			{
				"mode": "managed",
				"type": "aws_security_group",
				"name": "web",
				"provider": "registry.terraform.io/hashicorp/aws",
				"instances": [
					{
						"attributes": {
							"id": "sg-12345",
							"name": "web-sg",
							"description": "web security group"
						}
					}
				]
			},
			{
				"mode": "data",
				"type": "aws_ami",
				"name": "ubuntu",
				"provider": "registry.terraform.io/hashicorp/aws",
				"instances": [
					{
						"attributes": {
							"id": "ami-123"
						}
					}
				]
			},
			{
				"mode": "managed",
				"type": "google_compute_firewall",
				"name": "allow-http",
				"provider": "registry.terraform.io/hashicorp/google",
				"instances": [
					{
						"attributes": {
							"id": "projects/my-project/global/firewalls/allow-http",
							"name": "allow-http"
						}
					}
				]
			},
			{
				"mode": "managed",
				"type": "azurerm_network_security_group",
				"name": "example",
				"provider": "registry.terraform.io/hashicorp/azurerm",
				"instances": [
					{
						"attributes": {
							"id": "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-1",
							"name": "nsg-1"
						}
					}
				]
			}
		]
	}`)

	resources, err := ParseTFStateBytes(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Data sources should be excluded
	if len(resources) != 3 {
		t.Fatalf("got %d resources, want 3", len(resources))
	}

	// AWS resource
	if resources[0].Address != "aws_security_group.web" {
		t.Errorf("got address %q, want aws_security_group.web", resources[0].Address)
	}
	if resources[0].Provider != "aws" {
		t.Errorf("got provider %q, want aws", resources[0].Provider)
	}
	if resources[0].ID != "sg-12345" {
		t.Errorf("got ID %q, want sg-12345", resources[0].ID)
	}
	if resources[0].Type != "aws_security_group" {
		t.Errorf("got type %q, want aws_security_group", resources[0].Type)
	}

	// GCP resource
	if resources[1].Provider != "gcp" {
		t.Errorf("got provider %q, want gcp", resources[1].Provider)
	}

	// Azure resource
	if resources[2].Provider != "azure" {
		t.Errorf("got provider %q, want azure", resources[2].Provider)
	}
}

func TestParseTFStateBytesUnsupportedVersion(t *testing.T) {
	data := []byte(`{"version": 3, "resources": []}`)
	_, err := ParseTFStateBytes(data)
	if err == nil {
		t.Fatal("expected error for v3 state")
	}
}

func TestParseTFStateBytesInvalidJSON(t *testing.T) {
	_, err := ParseTFStateBytes([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseTFStateBytesEmpty(t *testing.T) {
	data := []byte(`{"version": 4, "resources": []}`)
	resources, err := ParseTFStateBytes(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 0 {
		t.Fatalf("got %d resources, want 0", len(resources))
	}
}

func TestExtractProvider(t *testing.T) {
	tests := []struct {
		providerStr  string
		resourceType string
		want         string
	}{
		{"registry.terraform.io/hashicorp/aws", "aws_security_group", "aws"},
		{"registry.terraform.io/hashicorp/google", "google_compute_firewall", "gcp"},
		{"registry.terraform.io/hashicorp/azurerm", "azurerm_network_security_group", "azure"},
		{"custom", "custom_resource", "custom"},
	}
	for _, tt := range tests {
		got := extractProvider(tt.providerStr, tt.resourceType)
		if got != tt.want {
			t.Errorf("extractProvider(%q, %q) = %q, want %q", tt.providerStr, tt.resourceType, got, tt.want)
		}
	}
}
