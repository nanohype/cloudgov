package fix

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Containment for the files cloudgov writes.
//
// Every generated remediation file is named after a value the tool read rather
// than one it chose: the provider on a saved finding, the principal on a
// scanned policy, the name on a baseline. `cloudgov remediate` reads that value
// out of a JSON file an operator received — from CI, from a colleague, from a
// bucket — so without a refusal, whoever wrote the report picks both the name
// of the file this tool creates and the directory it lands in. The scripts are
// written executable, and one generator emits DELETE commands.
//
// The refusal is two layers, and they are not the same kind. NameComponent
// rejects the value, and holds because the value is checked before anything is
// composed from it — an arrangement of two statements. PathUnder rejects the
// joined path, and holds whatever the caller did first — a guarantee. A
// generator written without the first still cannot write outside the directory
// it was handed.
//
// Both refuse rather than repair. A repaired name is a file the operator did
// not ask for, under a name they cannot predict, reported as the file they did;
// and a report carrying a path separator where a provider belongs is either
// corrupt or hostile, with no third reading in which writing the file anyway is
// the right answer.
//
// The two split on what they can see. NameComponent sees one untrusted value
// and asks whether it can be a path element. PathUnder sees the finished
// filename and asks where it lands and how it will be read. A rule that needs
// the whole name — a leading dash — belongs to the second, or a component that
// a prefix already makes safe gets refused for a problem the caller solved.

// pathSeparators are refused wherever one filename element is expected.
//
// A backslash separates nothing on the platforms this binary targets. It is
// refused because a report is a file that travels: validating removes the
// premise rather than leaving a claim about which host resolves what.
const pathSeparators = `/\`

// NameComponent returns an error when value cannot be one element of a
// filename. field names the report field the value came from, so a refusal
// points at what to fix rather than at a path nobody typed.
func NameComponent(field, value string) error {
	switch {
	case value == "":
		return fmt.Errorf("%s is empty; a generated filename cannot be built from it", field)
	case strings.ContainsAny(value, pathSeparators):
		return fmt.Errorf("%s %q contains a path separator; it names one file, not a location", field, value)
	case value == "." || value == "..":
		return fmt.Errorf("%s %q is a directory reference, not a name", field, value)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s %q contains a control character", field, value)
		}
	}
	return nil
}

// PathUnder joins name onto dir and returns the result only when it names a
// file directly inside dir.
//
// The test is not whether the cleaned path still begins with dir. A name
// carrying a ".." segment is refused even when the segments cancel and the
// result lands back inside: "x/../y.sh" and "y.sh" are the same file and
// different claims, and a caller that accepts the first has stopped deciding
// where its own output goes. Whether a particular arrangement of separators
// happens to cancel is not a property to rest containment on.
//
// Directly inside, not merely underneath: a name reaching a subdirectory is
// refused too. Every caller composes one filename in one directory, so a name
// resolving anywhere else has already lost the argument.
func PathUnder(dir, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty filename under %s", dir)
	}
	for _, segment := range strings.FieldsFunc(name, isPathSeparator) {
		if segment == ".." {
			return "", fmt.Errorf("filename %q contains a %q segment; it must name a file directly inside %s", name, "..", dir)
		}
	}
	joined := filepath.Join(dir, name)
	if filepath.Dir(joined) != filepath.Clean(dir) {
		return "", fmt.Errorf("filename %q does not land directly inside %s; it resolves to %s", name, dir, joined)
	}
	// Checked on the finished name rather than on the component, because a
	// prefix the caller supplies is what decides it. The same reasoning
	// internal/repo/gh.go states for GitHub names: a leading dash is read as a
	// flag by whatever runs the file, which turns a filename into an argument.
	if strings.HasPrefix(filepath.Base(joined), "-") {
		return "", fmt.Errorf("filename %q starts with a dash; a file named this way is read as a flag by whatever runs it", filepath.Base(joined))
	}

	// Everything above decides on the string. A symlink already sitting at that
	// name carries the write wherever it points, so the lexical answer is right
	// and the file still lands outside dir — and the callers open with
	// os.WriteFile, which follows one. Lstat rather than Stat: the question is
	// what the name IS, not what it resolves to.
	//
	// A name with nothing at it is the ordinary case and passes; an unreadable
	// one is refused rather than assumed, because a caller that cannot tell what
	// is there is exactly the caller that must not write through it.
	info, err := os.Lstat(joined)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return "", fmt.Errorf("cannot tell what %s already is, so this write is refused: %w", joined, err)
	case info.Mode()&fs.ModeSymlink != 0:
		return "", fmt.Errorf("%s is a symlink; writing through it would place the file wherever it points rather than inside %s", joined, dir)
	}
	return joined, nil
}

func isPathSeparator(r rune) bool {
	return strings.ContainsRune(pathSeparators, r)
}

// CommentText renders an untrusted value so that it cannot leave the comment
// line it is written on.
//
// Containing the path was half of the defect. The same report supplies the
// values these generators interpolate into the `#` banner above each command,
// and a newline in one of them ends the comment and starts a line of its own —
// in a file written 0700, above a command the tool composed. The path half sends
// the file somewhere the operator did not choose; this half decides what is in
// it once it lands, and closing only the first moves the choice inside --out
// rather than removing it.
//
// Rendered rather than refused, because unlike a filename these values are meant
// to be reproduced: an AWS Detail legitimately carries text, and a report that
// wraps one over two lines is not hostile. What must not survive is the value's
// ability to end the line. A reader still sees what the report said, spelled so
// that the shell never does.
func CommentText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			// The rest of C0 and DEL: no shell meaning on a comment line, but a
			// terminal reading the generated script can act on them, and an
			// operator reviewing it would not see what they are agreeing to.
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
