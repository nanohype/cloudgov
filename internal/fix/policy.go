package fix

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// WriteRawPolicies writes raw policy JSON/YAML files (one per principal) to dir.
func WriteRawPolicies(policies map[string]cloud.Policy, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	for principalID, pol := range policies {
		if len(pol.Raw) == 0 {
			continue
		}
		ext := ".json"
		filename := filepath.Join(dir, slug(principalID)+ext)
		if err := os.WriteFile(filename, pol.Raw, 0o644); err != nil {
			return fmt.Errorf("write policy %s: %w", principalID, err)
		}
	}
	return nil
}
