package drift

import (
	"testing"
)

func TestCompareAttributes(t *testing.T) {
	tests := []struct {
		name     string
		expected map[string]interface{}
		actual   map[string]interface{}
		fields   []string
		wantN    int
	}{
		{
			name:     "no diff when same",
			expected: map[string]interface{}{"name": "web-sg", "description": "test"},
			actual:   map[string]interface{}{"name": "web-sg", "description": "test"},
			fields:   []string{"name", "description"},
			wantN:    0,
		},
		{
			name:     "detects changed field",
			expected: map[string]interface{}{"name": "web-sg", "description": "old desc"},
			actual:   map[string]interface{}{"name": "web-sg", "description": "new desc"},
			fields:   []string{"name", "description"},
			wantN:    1,
		},
		{
			name:     "detects missing field in actual",
			expected: map[string]interface{}{"name": "web-sg"},
			actual:   map[string]interface{}{},
			fields:   []string{"name"},
			wantN:    1,
		},
		{
			name:     "detects missing field in expected",
			expected: map[string]interface{}{},
			actual:   map[string]interface{}{"name": "web-sg"},
			fields:   []string{"name"},
			wantN:    1,
		},
		{
			name:     "nil values compared",
			expected: map[string]interface{}{"name": nil},
			actual:   map[string]interface{}{"name": nil},
			fields:   []string{"name"},
			wantN:    0,
		},
		{
			name:     "nil vs non-nil",
			expected: map[string]interface{}{"name": nil},
			actual:   map[string]interface{}{"name": "something"},
			fields:   []string{"name"},
			wantN:    1,
		},
		{
			name:     "empty fields list",
			expected: map[string]interface{}{"name": "web"},
			actual:   map[string]interface{}{"name": "changed"},
			fields:   []string{},
			wantN:    0,
		},
		{
			name:     "multiple diffs",
			expected: map[string]interface{}{"a": "1", "b": "2", "c": "3"},
			actual:   map[string]interface{}{"a": "x", "b": "y", "c": "3"},
			fields:   []string{"a", "b", "c"},
			wantN:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diffs := CompareAttributes(tt.expected, tt.actual, tt.fields)
			if len(diffs) != tt.wantN {
				t.Errorf("got %d diffs, want %d: %v", len(diffs), tt.wantN, diffs)
			}
		})
	}
}

func TestCompareAttributesDiffContent(t *testing.T) {
	expected := map[string]interface{}{"description": "old"}
	actual := map[string]interface{}{"description": "new"}
	diffs := CompareAttributes(expected, actual, []string{"description"})
	if len(diffs) != 1 {
		t.Fatalf("got %d diffs, want 1", len(diffs))
	}
	if diffs[0].Field != "description" {
		t.Errorf("got field %q, want description", diffs[0].Field)
	}
	if diffs[0].Expected != "old" {
		t.Errorf("got expected %q, want old", diffs[0].Expected)
	}
	if diffs[0].Actual != "new" {
		t.Errorf("got actual %q, want new", diffs[0].Actual)
	}
}

func TestStringMapKeys(t *testing.T) {
	m := map[string]interface{}{"c": 1, "a": 2, "b": 3}
	keys := StringMapKeys(m)
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(keys))
	}
	if keys[0] != "a" || keys[1] != "b" || keys[2] != "c" {
		t.Errorf("keys not sorted: %v", keys)
	}
}
