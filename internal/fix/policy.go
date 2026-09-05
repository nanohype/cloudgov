package fix

import (
	"fmt"
	"os"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// WriteRawPolicies writes raw policy JSON/YAML files (one per principal) to dir.
func WriteRawPolicies(policies map[string]cloud.Policy, opts Options) error {
	dir := opts.OutputDir
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// The caveat cannot go inside the policy documents: a raw IAM policy has no
	// comment syntax and anything added to it stops being a policy. So it goes
	// in a file beside them, named to sort ahead of the policies and to be
	// unmissable in a directory listing or a pull request.
	if banner := provenanceBanner(opts); banner != "" {
		notePath, err := PathUnder(dir, partialScanNote)
		if err != nil {
			return err
		}
		if err := os.WriteFile(notePath, []byte(banner), 0o600); err != nil {
			return fmt.Errorf("write partial-scan note: %w", err)
		}
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
