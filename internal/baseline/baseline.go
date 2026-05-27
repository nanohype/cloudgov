package baseline

import (
	"encoding/json"
	"time"
)

// Metadata stores information about when and how a baseline was created.
type Metadata struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Source    string    `json:"source"` // path to the original report file
}

// Baseline wraps report data with metadata for comparison.
type Baseline struct {
	Metadata Metadata          `json:"metadata"`
	Report   json.RawMessage   `json:"report"`
}
