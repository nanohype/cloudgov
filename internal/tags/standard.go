package tags

import (
	"encoding/json"
	"fmt"
	"os"
)

// standardKind is the kind discriminator a resource-tagging standard file must
// declare. Guards against pointing --standard-file at the wrong JSON.
const standardKind = "nanohype/standards/resource-tagging"

// standardFile is the minimal shape cloudgov reads from a published nanohype
// resource-tagging standard — just enough to pull the required AWS tag keys.
// The standard pre-renders them (content.required_by_surface.aws holds the
// PascalCase keys), so there's no rendering logic here.
type standardFile struct {
	Kind    string `json:"kind"`
	Content struct {
		RequiredBySurface map[string][]string `json:"required_by_surface"`
	} `json:"content"`
}

// LoadRequired reads the required AWS tag keys from a nanohype resource-tagging
// standard JSON file (content.required_by_surface.aws) — the keys cloudgov then
// audits every AWS resource for. The same file the SDK/MCP serve and CI gates on.
func LoadRequired(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read standard file %s: %w", path, err)
	}
	var sf standardFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return nil, fmt.Errorf("parse standard file %s: %w", path, err)
	}
	if sf.Kind != standardKind {
		return nil, fmt.Errorf("standard file %s: unexpected kind %q (want %s)", path, sf.Kind, standardKind)
	}
	keys := sf.Content.RequiredBySurface["aws"]
	if len(keys) == 0 {
		return nil, fmt.Errorf("standard file %s: content.required_by_surface.aws is empty", path)
	}
	return keys, nil
}
