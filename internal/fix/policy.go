package fix

import (
	"fmt"
	"os"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// WriteRawPolicies writes raw policy JSON/YAML files (one per principal) to dir.
func WriteRawPolicies(policies map[string]cloud.Policy, dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	for principalID, pol := range policies {
		if len(pol.Raw) == 0 {
			continue
		}
		ext := ".json"
		s := slug(principalID)
		if err := NameComponent("principal", s); err != nil {
			return err
		}
		// Reachable on a valid principal: PathUnder also refuses a name that is
		// already a symlink, which has nothing to do with the check above.
		filename, err := PathUnder(dir, s+ext)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filename, pol.Raw, 0o600); err != nil {
			return fmt.Errorf("write policy %s: %w", principalID, err)
		}
	}
	return nil
}
