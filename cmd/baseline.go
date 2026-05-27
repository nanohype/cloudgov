package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/nanohype/cloudgov/internal/baseline"
)

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Save and manage scan baselines for comparison",
}

var baselineSaveCmd = &cobra.Command{
	Use:   "save",
	Short: "Save a scan report as a named baseline",
	RunE:  runBaselineSave,
}

var baselineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List saved baselines",
	RunE:  runBaselineList,
}

var baselineDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a saved baseline",
	RunE:  runBaselineDelete,
}

var (
	baselineFrom string
	baselineName string
)

func init() {
	baselineSaveCmd.Flags().StringVar(&baselineFrom, "from", "", "path to scan report JSON file (required)")
	baselineSaveCmd.Flags().StringVar(&baselineName, "name", "", "name for the baseline (required)")
	baselineSaveCmd.MarkFlagRequired("from")
	baselineSaveCmd.MarkFlagRequired("name")

	baselineDeleteCmd.Flags().StringVar(&baselineName, "name", "", "name of the baseline to delete (required)")
	baselineDeleteCmd.MarkFlagRequired("name")

	baselineCmd.AddCommand(baselineSaveCmd)
	baselineCmd.AddCommand(baselineListCmd)
	baselineCmd.AddCommand(baselineDeleteCmd)
}

func runBaselineSave(_ *cobra.Command, _ []string) error {
	data, err := os.ReadFile(baselineFrom)
	if err != nil {
		return fmt.Errorf("read report file: %w", err)
	}

	// Validate JSON
	if !json.Valid(data) {
		return fmt.Errorf("file %s is not valid JSON", baselineFrom)
	}

	store, err := baseline.DefaultStore()
	if err != nil {
		return err
	}

	if err := store.Save(baselineName, json.RawMessage(data), baselineFrom); err != nil {
		return err
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "baseline %q saved from %s\n", baselineName, baselineFrom)
	}
	return nil
}

func runBaselineList(_ *cobra.Command, _ []string) error {
	store, err := baseline.DefaultStore()
	if err != nil {
		return err
	}

	metas, err := store.List()
	if err != nil {
		return err
	}

	if len(metas) == 0 {
		fmt.Println("no baselines saved")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "NAME\tCREATED\tSOURCE\n")
	for _, m := range metas {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", m.Name, m.CreatedAt.Format("2006-01-02 15:04:05"), m.Source)
	}
	tw.Flush()
	return nil
}

func runBaselineDelete(_ *cobra.Command, _ []string) error {
	store, err := baseline.DefaultStore()
	if err != nil {
		return err
	}

	if err := store.Delete(baselineName); err != nil {
		return err
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "baseline %q deleted\n", baselineName)
	}
	return nil
}
