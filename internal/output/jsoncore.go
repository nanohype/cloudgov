package output

import (
	"encoding/json"
	"io"
)

// observed normalizes the incomplete record for a JSON envelope.
//
// The key is always emitted, and a run that saw everything emits it as `[]`
// rather than omitting it. Over MCP there is no exit code, so this array is the
// only carrier of "the scan could not see everything it was asked to" — and an
// absent key cannot be told apart from a tool that does not report coverage at
// all. A nil slice would marshal as `null`, which is the same ambiguity wearing
// a different value, so it is normalized here rather than at each call site.
func observed(incomplete []string) []string {
	if incomplete == nil {
		return []string{}
	}
	return incomplete
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
