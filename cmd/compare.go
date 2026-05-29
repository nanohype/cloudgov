package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/nanohype/cloudgov/internal/baseline"
	"github.com/nanohype/cloudgov/internal/compare"
	"github.com/nanohype/cloudgov/internal/output"
	"github.com/spf13/cobra"
)

var compareCmd = &cobra.Command{
	Use:   "compare",
	Short: "Compare two scan reports or a baseline against a current report",
	RunE:  runCompare,
}

var (
	compareBaseline   string
	compareCurrent    string
	compareFrom       string
	compareTo         string
	compareOutputFmt  string
	compareOutputFile string
)

func init() {
	compareCmd.Flags().StringVar(&compareBaseline, "baseline", "", "name of saved baseline to compare against")
	compareCmd.Flags().StringVar(&compareCurrent, "current", "", "path to current report JSON file")
	compareCmd.Flags().StringVar(&compareFrom, "from", "", "path to older report JSON file")
	compareCmd.Flags().StringVar(&compareTo, "to", "", "path to newer report JSON file")
	compareCmd.Flags().StringVar(&compareOutputFmt, "output", "table", "output format: table, json")
	compareCmd.Flags().StringVar(&compareOutputFile, "output-file", "", "write output to file")
}

func runCompare(_ *cobra.Command, _ []string) error {
	var baselineData, currentData []byte
	var err error

	if compareBaseline != "" && compareCurrent != "" {
		// baseline name + current file
		store, err := baseline.DefaultStore()
		if err != nil {
			return err
		}
		b, err := store.Load(compareBaseline)
		if err != nil {
			return err
		}
		baselineData = b.Report
		currentData, err = os.ReadFile(compareCurrent)
		if err != nil {
			return fmt.Errorf("read current report: %w", err)
		}
	} else if compareFrom != "" && compareTo != "" {
		// two files
		baselineData, err = os.ReadFile(compareFrom)
		if err != nil {
			return fmt.Errorf("read from file: %w", err)
		}
		currentData, err = os.ReadFile(compareTo)
		if err != nil {
			return fmt.Errorf("read to file: %w", err)
		}
	} else {
		return fmt.Errorf("specify either --baseline + --current, or --from + --to")
	}

	baselineFindings, err := compare.NormalizeReport(baselineData)
	if err != nil {
		return fmt.Errorf("normalize baseline: %w", err)
	}
	currentFindings, err := compare.NormalizeReport(currentData)
	if err != nil {
		return fmt.Errorf("normalize current: %w", err)
	}

	result := compare.Diff(baselineFindings, currentFindings)

	w := os.Stdout
	if compareOutputFile != "" {
		f, err := os.Create(compareOutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	switch strings.ToLower(compareOutputFmt) {
	case "json":
		return writeCompareJSON(w, result)
	default:
		if !quiet {
			fmt.Fprintf(os.Stderr, "\ncomparing %d baseline findings against %d current findings\n\n",
				len(baselineFindings), len(currentFindings))
		}
		writeCompareTable(w, result)
	}
	return nil
}

func writeCompareJSON(w *os.File, result compare.DiffResult) error {
	newF := toJSONFindings(result.New)
	resolved := toJSONFindings(result.Resolved)
	unchanged := toJSONFindings(result.Unchanged)
	return output.WriteCompare(w, newF, resolved, unchanged)
}

func writeCompareTable(w *os.File, result compare.DiffResult) {
	cr := output.NewCompareResult(
		toTableFindings(result.New),
		toTableFindings(result.Resolved),
		toTableFindings(result.Unchanged),
	)
	output.CompareTable(w, cr)
}

func toJSONFindings(findings []compare.NormalizedFinding) []output.CompareFindingJSONType {
	result := make([]output.CompareFindingJSONType, len(findings))
	for i, f := range findings {
		result[i] = output.CompareFindingJSON(f.Domain, f.Provider, f.Type, f.ResourceID, f.Detail, f.Severity)
	}
	return result
}

func toTableFindings(findings []compare.NormalizedFinding) []output.CompareFindingType {
	result := make([]output.CompareFindingType, len(findings))
	for i, f := range findings {
		result[i] = output.NewCompareFinding(f.Domain, f.Provider, f.Type, f.ResourceID, f.Detail, f.Severity)
	}
	return result
}
