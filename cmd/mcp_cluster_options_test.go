package cmd

import (
	"os"
	"path/filepath"
	"testing"

	cloudk8s "github.com/nanohype/cloudgov/internal/cloud/k8s"
)

// mcpClusterOptions is the whole decision on whether a kubeconfig NAMED BY THE
// MODEL may run an exec credential plugin.
//
// An exec plugin is an arbitrary command run by this process, and this process
// holds live AWS credentials. When the model supplies the path, the guard must
// be on; when the path is empty the connection falls back to the operator's own
// environment, which is the operator's choice to make and not the model's.
//
// It is four lines with one branch, and both sides of that branch decide whether
// a command runs. That is why it carries a 100 file floor.
func TestMCPClusterOptionsDeniesExecOnAModelSuppliedPath(t *testing.T) {
	if got := mcpClusterOptions(""); got != nil {
		t.Errorf("an empty path is the operator's own kubeconfig, resolved from their environment; "+
			"got %d option(s), want none", len(got))
	}

	opts := mcpClusterOptions("/tmp/some-model-supplied-kubeconfig")
	if len(opts) == 0 {
		t.Fatal("a model-supplied kubeconfig was given no options, so nothing stops it naming a " +
			"file whose exec plugin runs an arbitrary command beside live AWS credentials")
	}

	// The option must be the one that denies exec credentials — asserted by
	// APPLYING it, not by counting. A different option of the same shape would
	// satisfy a length check and deny nothing.
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(path, []byte(execKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := cloudk8s.New(t.Context(), path, opts...); err == nil {
		t.Error("a kubeconfig that authenticates by running a credential plugin was accepted " +
			"under the options given to a model-supplied path")
	}

	// The other direction, on the same file: without those options the same
	// kubeconfig is not refused for this reason, which is what makes the check
	// above about the option rather than about the file.
	if _, err := cloudk8s.New(t.Context(), path); err != nil {
		if containsExecRefusal(err.Error()) {
			t.Errorf("the exec plugin was refused without the option that refuses it, so the "+
				"test above proves nothing about the option: %v", err)
		}
	}
}

func containsExecRefusal(msg string) bool {
	return len(msg) > 0 && (indexOf(msg, "credential plugin") >= 0 || indexOf(msg, "may not name a kubeconfig") >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

const execKubeconfig = `apiVersion: v1
kind: Config
clusters:
  - name: probe
    cluster:
      server: https://127.0.0.1:1
contexts:
  - name: probe
    context:
      cluster: probe
      user: probe
current-context: probe
users:
  - name: probe
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: /bin/echo
        interactiveMode: Never
`
