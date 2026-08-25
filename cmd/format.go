package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// outputFormats is the set of --output values one command can render, in the
// order its help text lists them.
//
// The set and the help text are the same value rather than two that have to
// agree. A command that names sarif in its usage string and has no sarif arm is
// then a compile-time impossibility instead of a flag that accepts a format it
// silently does not produce.
type outputFormats []string

// The two shapes every command in the tree uses. SARIF is a security-findings
// format, so a command whose output is an inventory, a cost delta or a quota
// table has nothing to express in it.
var (
	tableJSON      = outputFormats{"table", "json"}
	tableJSONSARIF = outputFormats{"table", "json", "sarif"}
)

// usage renders the flag's help text from the set itself.
func (f outputFormats) usage() string {
	return "output format: " + strings.Join(f, ", ")
}

// resolve lowercases and validates a caller-supplied format.
//
// An unrecognised value is an error rather than a fall-through to the table
// renderer. A fall-through writes an ANSI table into results.sarif and exits 0,
// and a CI step that redirects output to a file and checks the exit code cannot
// tell that apart from a scan that worked.
func (f outputFormats) resolve(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, accepted := range f {
		if normalized == accepted {
			return normalized, nil
		}
	}
	return "", fmt.Errorf("unknown output format %q; want one of: %s", value, strings.Join(f, ", "))
}

// outputFormatFor returns the format set a command declared, resolved from the
// usage text on its own --output flag. Tests use it to enumerate the tree.
func outputFormatFor(cmd *cobra.Command) (outputFormats, bool) {
	// A group command declares the flag on its PersistentFlags, so the
	// subcommand that consumes it inherits rather than owns it. Looking only at
	// the local set would classify `k8s rbac` and `platform audit` as having no
	// --output flag at all.
	flag := cmd.Flags().Lookup("output")
	if flag == nil {
		flag = cmd.InheritedFlags().Lookup("output")
	}
	if flag == nil {
		return nil, false
	}
	const prefix = "output format: "
	if !strings.HasPrefix(flag.Usage, prefix) {
		return nil, false
	}
	var out outputFormats
	for _, name := range strings.Split(strings.TrimPrefix(flag.Usage, prefix), ",") {
		out = append(out, strings.TrimSpace(name))
	}
	return out, true
}
