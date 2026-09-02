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
		// slug repairs an arbitrary principal id into a filename; the two checks
		// below assert the result rather than trusting the repair. Nothing here
		// supplies a prefix, so the principal id is the whole of the name before
		// the extension and PathUnder is what refuses one that reads as a flag.
		s := slug(principalID)
		if err := NameComponent("principal", s); err != nil {
			return err
		}
		// NameComponent above refuses the separators and the bare directory
		// references, so nothing reaches the refusal below. slug is not what
		// makes that true — it replaces only / @ . - and space, so a backslash
		// passes through it and a backslash is a separator by this package's own
		// definition. The check two lines up is what catches it.
		//
		// Kept because containment must not rest on the order of two statements:
		// this is the layer that holds if the check above is moved or dropped.
		filename, err := PathUnder(dir, s+ext)
		if err != nil {
			return err //coverage:ignore unreachable while slug produces one plain element
		}
		if err := os.WriteFile(filename, pol.Raw, 0o600); err != nil {
			return fmt.Errorf("write policy %s: %w", principalID, err)
		}
	}
	return nil
}
