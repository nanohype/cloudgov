package output

import (
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	"github.com/nanohype/cloudgov/internal/cloud"
)

// InventoryResources renders an inventory table with resource details.
func InventoryResources(w io.Writer, resources []cloud.InventoryResource) {
	if len(resources) == 0 {
		fmt.Fprintln(w, dimStyle.Render("no resources found"))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
		headerStyle.Render("TYPE"),
		headerStyle.Render("PROVIDER"),
		headerStyle.Render("NAME"),
		headerStyle.Render("REGION"),
		headerStyle.Render("STATUS"),
		headerStyle.Render("TAGS"),
	)
	for _, r := range resources {
		tagStr := formatTags(r.Tags, 50)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Type, r.Provider, truncate(r.Name, 30), r.Region, r.Status, tagStr,
		)
	}
	tw.Flush()

	// Summary by type
	typeCounts := make(map[string]int)
	for _, r := range resources {
		typeCounts[r.Type]++
	}
	types := make([]string, 0, len(typeCounts))
	for t := range typeCounts {
		types = append(types, t)
	}
	sort.Strings(types)
	fmt.Fprintf(w, "\n%s: %d resources", headerStyle.Render("Total"), len(resources))
	for _, t := range types {
		fmt.Fprintf(w, ", %s: %d", t, typeCounts[t])
	}
	fmt.Fprintln(w)
}

type inventoryReport struct {
	Resources []cloud.InventoryResource `json:"resources"`
	Total     int                       `json:"total"`
}

// WriteInventory marshals inventory resources as JSON to w.
func WriteInventory(w io.Writer, resources []cloud.InventoryResource) error {
	return writeJSON(w, inventoryReport{
		Resources: resources,
		Total:     len(resources),
	})
}
