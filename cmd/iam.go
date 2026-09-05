package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/cloud"
	"github.com/nanohype/cloudgov/internal/fix"
	"github.com/nanohype/cloudgov/internal/iam"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/nanohype/cloudgov/internal/providers"
	"github.com/spf13/cobra"
)

var iamCmd = &cobra.Command{
	Use:   "iam",
	Short: "IAM least-privilege analysis",
}

var iamScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan principals for unused and overprivileged permissions",
	RunE:  runIAMScan,
}

var iamFixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Generate minimal policy fix files from a prior scan report",
	RunE:  runIAMFix,
}

var (
	iamDays        int
	iamPrincipal   string
	iamSeverity    string
	iamOutputFmt   string
	iamOutputFile  string
	iamConcurrency int
	iamProfile     string
	iamFromFile    string
	iamFixFormat   string
	iamFixOut      string
	iamFixSeverity string
	iamFixProfile  string
	// iamFixAcceptIncomplete is the operator saying, in this run, that they want
	// a fix built from a scan that did not see everything.
	//
	// Its own flag rather than --fail-on. --fail-on asks what severity should
	// make a run exit non-zero, which is a question about reporting; this answers
	// whether a change may be generated from an unsound premise. Overloading one
	// on the other would make an operator raising a reporting threshold silently
	// authorise a remediation.
	iamFixAcceptIncomplete bool
)

func init() {
	iamScanCmd.Flags().IntVar(&iamDays, "days", 90, "audit log lookback period in days")
	iamScanCmd.Flags().StringVar(&iamPrincipal, "principal", "", "scan a specific principal by name or ID")
	iamScanCmd.Flags().StringVar(&iamSeverity, "severity", "LOW", severityUsage("minimum severity to report"))
	iamScanCmd.Flags().StringVar(&iamOutputFmt, "output", tableJSONSARIF[0], tableJSONSARIF.usage())
	iamScanCmd.Flags().StringVar(&iamOutputFile, "output-file", "", "write output to file instead of stdout")
	iamScanCmd.Flags().IntVar(&iamConcurrency, "concurrency", 10, "max parallel goroutines for scanning principals")
	iamScanCmd.Flags().StringVar(&iamProfile, "profile", "", "AWS named profile to use for credentials")

	iamFixCmd.Flags().StringVar(&iamFromFile, "from", "", "path to JSON report from 'cloudgov iam scan --output json'")
	iamFixCmd.Flags().StringVar(&iamFixFormat, "format", "terraform", "fix format: terraform, json")
	iamFixCmd.Flags().StringVar(&iamFixOut, "out", "./cloudgov-fixes", "output directory")
	iamFixCmd.Flags().StringVar(&iamFixSeverity, "severity", "HIGH", severityUsage("minimum severity to generate fixes for"))
	iamFixCmd.Flags().StringVar(&iamFixProfile, "profile", "", "AWS named profile to use for credentials (match the profile used for the scan)")
	iamFixCmd.Flags().BoolVar(&iamFixAcceptIncomplete, "accept-incomplete-scan", false,
		"generate fixes from a scan that did not see everything it was asked to; the generated files record that they were")
	_ = iamFixCmd.MarkFlagRequired("from")

	iamCmd.AddCommand(iamScanCmd, iamFixCmd)
}

func runIAMScan(cmd *cobra.Command, _ []string) error {
	// Refused rather than coerced: an unrecognised level ranks below every
	// real one, so a typo widens a reporting floor instead of failing.
	minSeverity, err := resolveSeverity(iamSeverity, cloud.SeverityLow)
	if err != nil {
		return err
	}
	// Validated before any provider is resolved, so an unrenderable format
	// fails on the flag rather than after a full account sweep.
	iamFormat, err := tableJSONSARIF.resolve(iamOutputFmt)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	providers, err := resolveIAMProviders(ctx, iamProfile)
	if err != nil {
		return err
	}

	opts := iam.ScanOptions{
		Days:            iamDays,
		PrincipalFilter: iamPrincipal,
		MinSeverity:     minSeverity,
		Concurrency:     iamConcurrency,
	}

	var allFindings []cloud.Finding
	var incomplete []string
	allUsedPerms := make(map[string][]cloud.Permission)
	totalPrincipals := 0
	totalScanned := 0
	// One envelope, several providers: the report can claim only the window every
	// contributing provider covered.
	var windows []cloud.ScanWindow
	for _, p := range providers {
		providerName := p.Name()
		if !quiet {
			opts.Progress = func(done, total int) {
				fmt.Fprintf(os.Stderr, "\rscanning %s: %d/%d principals...", providerName, done, total)
				if done == total {
					fmt.Fprintln(os.Stderr)
				}
			}
		}
		result, err := iam.Scan(ctx, p, opts)
		if err != nil {
			// A provider that failed outright contributes nothing, so the run
			// saw less than it was asked to — record it rather than moving on.
			incomplete = append(incomplete, fmt.Sprintf("provider %s: scan failed: %v", p.Name(), err))
			continue
		}
		allFindings = append(allFindings, result.Findings...)
		incomplete = append(incomplete, result.Incomplete...)
		windows = append(windows, result.Window)
		totalPrincipals += result.Principals
		totalScanned += result.Scanned
		for pid, used := range result.UsedPermissions {
			allUsedPerms[pid] = used
		}
	}

	w := os.Stdout
	if iamOutputFile != "" {
		f, err := os.Create(iamOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	scanWindow := cloud.NarrowestWindow(windows)

	incomplete = append(incomplete, cloud.Incomplete(providers)...)

	gate(allFindings, func(f cloud.Finding) cloud.Severity { return f.Severity })
	gateIncomplete(incomplete)

	switch iamFormat {
	case "json":
		return output.WriteIAM(w, allFindings, totalPrincipals, totalScanned, allUsedPerms, incomplete, scanWindow)
	case "sarif":
		return output.WriteSARIF(w, allFindings, Version, incomplete)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\nFound %d findings across %d principals\n\n", len(allFindings), totalPrincipals)
		}
		output.IAMFindings(w, allFindings, totalPrincipals)
		output.IncompleteNote(w, incomplete)
	}
	return nil
}

// iamFixReport is the saved scan this command acts on.
//
// Incomplete and Window are read because this command acts on the report rather
// than displaying it. A scan that could not see part of the account produces a
// used-permission set that is short, and a fix generated from it removes access
// on the strength of activity nobody observed. Before these two fields were read
// the report's own record of what it could not see was discarded at the
// unmarshal, and the fix inherited the premise without ever seeing it.
type iamFixReport struct {
	Findings        []cloud.Finding               `json:"findings"`
	UsedPermissions map[string][]cloud.Permission `json:"used_permissions"`
	Incomplete      []string                      `json:"incomplete"`
	Window          cloud.ScanWindow              `json:"window"`
}

func runIAMFix(cmd *cobra.Command, _ []string) error {
	fixSeverity, err := resolveSeverity(iamFixSeverity, cloud.SeverityLow)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(iamFromFile)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}

	var r iamFixReport
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("parse report: %w", err)
	}

	// Resolved before the decision so the decision can be made in one place, and
	// after the report is parsed so an unreadable file fails on its own terms.
	//
	// Splitting resolution from the work is what lets the refusal be observed by
	// looking at the filesystem: generateIAMFixes is reached with providers in
	// hand, so a test can hand it working ones and watch nothing appear. A
	// command that resolved and generated in one body could only ever be proven
	// by its exit code, which is the fix's own account of itself.
	ctx := cmd.Context()
	providers, err := resolveIAMProviders(ctx, iamFixProfile)
	if err != nil {
		return err
	}

	return generateIAMFixes(ctx, r, providers, fix.Options{
		OutputDir: iamFixOut,
		Severity:  fixSeverity,
	}, iamFixAcceptIncomplete)
}

// generateIAMFixes turns a saved report into fix files, or refuses to.
//
// A report and a fix do not get the same default. Reporting an incomplete scan
// costs an operator a re-read, and gateIncomplete leaves that to --fail-on so
// they can decide what a partial view is worth. Generating a change from one
// costs them access that is in use: the removals are computed from the
// permissions the scan OBSERVED, so every permission it could not observe reads
// as unused. The asymmetry is the point, and it is why this refuses by default
// where `iam scan` does not.
//
// The refusal is the first thing it does, before a directory is made or a
// provider is called, so a run that has decided not to act leaves no trace of
// having considered it.
func generateIAMFixes(ctx context.Context, r iamFixReport, providers []cloud.IAMProvider, opts fix.Options, acceptIncomplete bool) error {
	if len(r.Incomplete) > 0 && !acceptIncomplete {
		return fmt.Errorf("%s", refuseIncompleteScan(iamFromFile, r.Incomplete, r.Window))
	}

	// Accepted, so the caveat travels with the artifact. A fix file outlives the
	// run that produced it and is reviewed by someone who never saw the command,
	// so a warning printed once at the terminal is gone by the time it matters.
	opts.Incomplete = r.Incomplete
	opts.Window = r.Window

	providerMap := make(map[string]cloud.IAMProvider)
	for _, p := range providers {
		providerMap[p.Name()] = p
	}

	// A principal this pass could not generate a policy for is a principal the
	// fix set does not cover. Without this record the caller gets a smaller fix
	// set than the report it was built from, exit 0, and nothing saying which
	// principals were left out.
	var unfixed []string

	policies := make(map[string]cloud.Policy)
	for _, f := range r.Findings {
		if f.Principal == nil {
			continue
		}
		if _, ok := policies[f.Principal.ID]; ok {
			continue
		}
		p, ok := providerMap[f.Provider]
		if !ok {
			unfixed = append(unfixed, fmt.Sprintf("%s: no %s provider is available, so no policy was generated",
				f.Principal.Name, f.Provider))
			continue
		}
		usedPerms := r.UsedPermissions[f.Principal.ID]
		pol, err := p.MinimalPolicy(ctx, *f.Principal, usedPerms)
		if err != nil {
			unfixed = append(unfixed, fmt.Sprintf("%s: minimal policy could not be generated: %v",
				f.Principal.Name, err))
			continue
		}
		policies[f.Principal.ID] = pol
		if !quiet {
			writePolicyFallbackWarnings(os.Stderr, f.Principal.Name, pol.Fallbacks)
		}
	}

	// The same contract as every command that reads an account: a fix set built
	// from a partial pass must not report as a complete one. The provider's own
	// unread observations count too — a scan that could not read a principal's
	// policies produces a fix for it that is not a fix.
	gateIncomplete(append(cloud.Incomplete(providers), unfixed...))

	switch strings.ToLower(iamFixFormat) {
	case "json":
		return fix.WriteRawPolicies(policies, opts)
	default:
		if err := fix.GenerateTerraform(r.Findings, policies, opts); err != nil {
			return err
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "fix files written to %s\n", opts.OutputDir)
		}
	}
	return nil
}

// refuseIncompleteScan renders why no fix was generated, and what would let one
// be.
//
// It names three things, because a refusal naming none of them leaves the
// operator with a command that merely stopped: what the scan could not see, what
// the removals would have rested on, and the two ways forward. The window is
// quoted from the report rather than recomputed — a fix is a claim about the same
// period the scan claimed, and stating a different one here would be a third
// number to disagree with.
func refuseIncompleteScan(reportPath string, incomplete []string, window cloud.ScanWindow) string {
	var b strings.Builder
	fmt.Fprintf(&b, "no fix generated: %s is a partial scan, and a fix removes permissions "+
		"the scan did not observe being used\n", reportPath)
	fmt.Fprintf(&b, "\n%d observation(s) the scan could not make:\n", len(incomplete))
	for _, o := range incomplete {
		fmt.Fprintf(&b, "  - %s\n", o)
	}
	if window.ObservedDays > 0 {
		fmt.Fprintf(&b, "\nthe scan covered %d day(s)", window.ObservedDays)
		if window.Short() {
			fmt.Fprintf(&b, " of the %d requested", window.RequestedDays)
			if window.LimitedBy != "" {
				fmt.Fprintf(&b, "; %s retains no more", window.LimitedBy)
			}
		}
		b.WriteString(". A permission last used before that is indistinguishable from one never used.\n")
	}
	b.WriteString("\nEither re-run the scan so it sees what it could not — the entries above name " +
		"what to grant or widen — or pass --accept-incomplete-scan to generate the fix anyway. " +
		"The generated files record that they were built from a partial scan.\n")
	return b.String()
}

// writePolicyFallbackWarnings surfaces actions the minimal-policy generator
// could not scope: they land in the generated policy under Resource "*"
// (statement Sid "UnscopedFallback"), which a least-privilege fix must never
// do silently.
func writePolicyFallbackWarnings(w io.Writer, principal string, fallbacks []cloud.PolicyFallback) {
	if len(fallbacks) == 0 {
		return
	}
	fmt.Fprintf(w, "warn: %s: %d action(s) could not be scoped and were granted Resource \"*\" (statement Sid %q):\n", principal, len(fallbacks), "UnscopedFallback")
	for _, fb := range fallbacks {
		if fb.Resource != "" {
			fmt.Fprintf(w, "  - %s: %s (recorded resource %q)\n", fb.Action, fb.Reason, fb.Resource)
		} else {
			fmt.Fprintf(w, "  - %s: %s\n", fb.Action, fb.Reason)
		}
	}
}

func resolveIAMProviders(ctx context.Context, profile string) ([]cloud.IAMProvider, error) {
	return providers.Resolve[cloud.IAMProvider](ctx, providerOptions(providers.WithProfile(profile))...)
}
