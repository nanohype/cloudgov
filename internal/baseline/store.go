package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nanohype/cloudgov/internal/fix"
)

var validName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Store manages baseline files on disk.
type Store struct {
	dir string
}

// NewStore creates a store at the given directory.
func NewStore(dir string) *Store {
	return &Store{dir: dir}
}

// DefaultStore creates a store at ~/.cloudgov/baselines.
func DefaultStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("home directory: %w", err)
	}
	dir := filepath.Join(home, ".cloudgov", "baselines")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create baselines dir: %w", err)
	}
	return NewStore(dir), nil
}

// Save writes a baseline to disk. Overwrites any existing baseline with the same name.
func (s *Store) Save(name string, report json.RawMessage, source string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("invalid baseline name %q: must match [a-zA-Z0-9_-]+", name)
	}

	b := Baseline{
		Metadata: Metadata{
			Name:      name,
			CreatedAt: time.Now().UTC(),
			Source:    source,
		},
		Report: report,
	}

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}

	// Atomic write via temp file + rename. The temp name goes through the same
	// definition as the final one rather than being derived from it: a write is
	// a write, and the file this places is the one that becomes the baseline a
	// moment later.
	path, err := s.path(name)
	if err != nil {
		return err
	}
	tmp, err := s.tmpPath(name)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// Load reads a baseline from disk.
func (s *Store) Load(name string) (*Baseline, error) {
	if !validName.MatchString(name) {
		return nil, fmt.Errorf("invalid baseline name %q: must match [a-zA-Z0-9_-]+", name)
	}

	path, err := s.path(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline %q: %w", name, err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %q: %w", name, err)
	}
	return &b, nil
}

// List returns all saved baseline names sorted by creation date (newest first).
func (s *Store) List() ([]Metadata, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read baselines dir: %w", err)
	}

	var metas []Metadata
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		_ = strings.TrimSuffix(e.Name(), ".json")
		data, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		var b Baseline
		if err := json.Unmarshal(data, &b); err != nil {
			continue
		}
		metas = append(metas, b.Metadata)
	}

	sort.Slice(metas, func(i, j int) bool {
		return metas[i].CreatedAt.After(metas[j].CreatedAt)
	})
	return metas, nil
}

// Delete removes a baseline from disk.
func (s *Store) Delete(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("invalid baseline name %q: must match [a-zA-Z0-9_-]+", name)
	}
	path, err := s.path(name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("baseline %q not found", name)
	}
	return os.Remove(path)
}

// path composes the file a baseline name refers to.
//
// validName has already refused a separator and a bare directory reference by
// the time this runs, so the second check here is not a second opinion on the
// same question — it is the layer that holds if validName is ever relaxed, and
// it is what refuses a name the pattern does allow: one starting with a dash,
// which every tool that later takes the file as an argument reads as a flag.
// Read and write share it, so a name this store will not write is also a name
// it will not read back.
func (s *Store) path(name string) (string, error) {
	return fix.PathUnder(s.dir, name+".json")
}

// tmpPath is the file Save writes before renaming it into place. Composed the
// same way as path rather than from path, so both writes are contained by the
// same definition and neither inherits the other's.
func (s *Store) tmpPath(name string) (string, error) {
	return fix.PathUnder(s.dir, name+".json.tmp")
}
