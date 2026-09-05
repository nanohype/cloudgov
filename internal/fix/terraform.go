package fix

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// Options controls fix file generation.
type Options struct {
	OutputDir string
	Severity  cloud.Severity
	// Incomplete is what the scan behind these fixes could not observe, empty
	// when it saw everything it was asked to.
	//
	// Carried into the generated files rather than printed once at the terminal.
	// A fix file outlives the run that produced it: it is reviewed later, in a
	// pull request, by someone who never saw the command. A caveat that existed
	// only on stderr is gone by then, and what is left is a diff removing
	// permissions with nothing to say the evidence was partial.
	Incomplete []string
	// Window is the audit-log period the scan covered, so a reader of a
	// generated file can see the period the removals rest on.
	Window cloud.ScanWindow
}

// partialScanNote is the file written beside raw policies when the scan behind
// them was partial. JSON policies cannot carry a comment, so the caveat is a
// file of its own; the name sorts ahead of the policies and reads as a warning
// in a directory listing.
const partialScanNote = "AAA-PARTIAL-SCAN-README.txt"

// provenanceBanner renders the caveat a generated file carries, or "" when the
// scan behind it was complete.
//
// Every line is a comment in the language this generates, so the banner can head
// any file the generator writes without changing what the file means.
func provenanceBanner(opts Options) string {
	if len(opts.Incomplete) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("# GENERATED FROM A PARTIAL SCAN — REVIEW BEFORE APPLYING\n")
	b.WriteString("#\n")
	b.WriteString("# The scan behind this file did not observe everything it was asked to, and a\n")
	b.WriteString("# permission it could not observe being used is indistinguishable here from one\n")
	b.WriteString("# that is genuinely unused. Applying this removes both.\n")
	if opts.Window.ObservedDays > 0 {
		fmt.Fprintf(&b, "#\n# Audit-log window covered: %d day(s)", opts.Window.ObservedDays)
		if opts.Window.Short() {
			fmt.Fprintf(&b, " of the %d requested", opts.Window.RequestedDays)
			if opts.Window.LimitedBy != "" {
				fmt.Fprintf(&b, " (%s retains no more)", opts.Window.LimitedBy)
			}
		}
		b.WriteString(".\n")
	}
	b.WriteString("#\n# What the scan could not observe:\n")
	for _, o := range opts.Incomplete {
		fmt.Fprintf(&b, "#   - %s\n", CommentText(o))
	}
	b.WriteString("\n")
	return b.String()
}

// GenerateTerraform writes one .tf file per principal with minimal policy resources.
func GenerateTerraform(findings []cloud.Finding, policies map[string]cloud.Policy, opts Options) error {
	if err := os.MkdirAll(opts.OutputDir, 0o750); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	type entry struct {
		principal cloud.Principal
		policy    cloud.Policy
	}
	seen := make(map[string]entry)
	for _, f := range findings {
		if f.Principal == nil {
			continue
		}
		if cloud.SeverityRank(f.Severity) < cloud.SeverityRank(opts.Severity) {
			continue
		}
		pid := f.Principal.ID
		if _, ok := seen[pid]; !ok {
			seen[pid] = entry{principal: *f.Principal, policy: policies[pid]}
		}
	}

	banner := provenanceBanner(opts)
	for _, e := range seen {
		if err := writePrincipalTF(e.principal, e.policy, opts.OutputDir, banner); err != nil {
			return err
		}
	}
	return nil
}

func writePrincipalTF(principal cloud.Principal, policy cloud.Policy, dir, banner string) error {
	s := slug(principal.Name)
	if err := NameComponent("principal", s); err != nil {
		return err
	}
	// Reachable on a valid principal: PathUnder also refuses a name that is
	// already a symlink, which has nothing to do with the check above.
	filename, err := PathUnder(dir, "minimal_"+s+".tf")
	if err != nil {
		return err
	}

	var content string
	switch principal.Provider {
	case "aws":
		content = formatAWSTF(s, principal.Name, policy)
	default:
		content = fmt.Sprintf("# no Terraform template available for provider %q\n", principal.Provider)
	}

	content = banner + content

	// The error names the principal: `iam fix` writes one file per principal,
	// and the operator's next move is to re-run for the one that failed, which
	// a bare path error does not identify.
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write fix for %s: %w", principal.Name, err)
	}
	return nil
}

func formatAWSTF(s, name string, policy cloud.Policy) string {
	// Emit the policy as a literal JSON string via a heredoc. The previous
	// jsonencode(<raw policy JSON>) form broke two ways: Terraform interpolated IAM
	// policy variables like ${aws:username} (treating them as template expressions
	// -> "Extra characters after interpolation expression"), and it rejected JSON
	// escapes HCL doesn't accept (e.g. \/, \b). A heredoc keeps backslashes literal;
	// escaping ${ and %{ stops the remaining interpolation so policy variables
	// survive verbatim. Pretty-printed so the generated file is reviewable.
	body := "{}"
	if len(policy.Raw) > 0 {
		var buf bytes.Buffer
		if err := json.Indent(&buf, policy.Raw, "", "  "); err == nil {
			body = buf.String()
		} else {
			body = string(policy.Raw)
		}
	}
	body = strings.ReplaceAll(body, "${", "$${")
	body = strings.ReplaceAll(body, "%{", "%%{")
	return fmt.Sprintf(`resource "aws_iam_policy" "minimal_%s" {
  name        = "minimal-%s"
  description = "Minimal policy generated by cloudgov"
  policy      = <<POLICY
%s
POLICY
}
`, s, strings.ReplaceAll(name, "_", "-"), body)
}

// slug renders an arbitrary principal name as one filename element.
//
// The named substitutions are kept so existing filenames do not move, and a
// sweep against what NameComponent accepts is added behind them. A replacer
// alone names the characters someone thought of, and this one had already let a
// backslash and a colon through — a backslash being a separator by this
// package's own definition, and a colon appearing in every principal ARN.
func slug(name string) string {
	// The named substitutions first, so the filenames this produces do not change:
	// "@" carries meaning spelled out, and "." "-" and "/" have always collapsed
	// to an underscore here.
	lowered := strings.NewReplacer(
		"/", "_", "@", "_at_", ".", "_", "-", "_", " ", "_",
	).Replace(strings.ToLower(name))

	// Then everything else outside the accepted set, which is the half a list of
	// substitutions kept missing.
	var b strings.Builder
	b.Grow(len(lowered))
	for _, r := range lowered {
		if allowedInAName(r) {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('_')
	}
	return b.String()
}
