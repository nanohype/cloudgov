package k8s

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeKubeconfig writes a minimal kubeconfig and returns its path. authBlock is
// spliced in as the current user's auth stanza, which is what decides whether the
// resolved connection runs an exec credential plugin.
func writeKubeconfig(t *testing.T, authBlock string) string {
	t.Helper()
	body := `apiVersion: v1
kind: Config
current-context: probe
clusters:
  - name: probe
    cluster:
      server: https://cluster.invalid:6443
contexts:
  - name: probe
    context:
      cluster: probe
      user: probe
users:
  - name: probe
    user:
` + authBlock
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

const tokenAuth = "      token: probe-token\n"

const execAuth = `      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: /usr/bin/attacker-chosen
        args: ["--steal"]
        interactiveMode: Never
`

// Every client this package builds carries a request deadline. Without one an
// apiserver that accepts a connection and never answers hangs an unattended scan
// with no ceiling, because there is nobody to interrupt it.
func TestLoadConfigAlwaysSetsRequestTimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth string
	}{
		{"token auth", tokenAuth},
		{"exec auth", execAuth},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := loadConfig(writeKubeconfig(t, tc.auth), connOptions{})
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if cfg.Timeout != k8sRequestTimeout {
				t.Errorf("Timeout = %v, want %v — an unbounded Kubernetes call", cfg.Timeout, k8sRequestTimeout)
			}
		})
	}
}

func TestLoadConfigReportsContext(t *testing.T) {
	_, contextName, err := loadConfig(writeKubeconfig(t, tokenAuth), connOptions{})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if contextName != "probe" {
		t.Errorf("contextName = %q, want %q", contextName, "probe")
	}
}

// The exec command is named by the kubeconfig, so whoever names the file chooses
// which binary runs in a process holding live cloud credentials. A caller that
// received the path across a trust boundary asks for the refusal.
func TestLoadConfigRefusesExecCredentialsWhenDenied(t *testing.T) {
	_, _, err := loadConfig(writeKubeconfig(t, execAuth), connOptions{denyExecCredentials: true})
	if err == nil {
		t.Fatal("exec-plugin kubeconfig was accepted under denyExecCredentials")
	}
	if !strings.Contains(err.Error(), "/usr/bin/attacker-chosen") {
		t.Errorf("error does not name the command it refused to run: %v", err)
	}
}

// The refusal is scoped to the credential plugin, not to caller-named kubeconfigs
// as such: a static-credential file names no binary and stays usable.
func TestLoadConfigAcceptsStaticCredentialsWhenExecDenied(t *testing.T) {
	cfg, _, err := loadConfig(writeKubeconfig(t, tokenAuth), connOptions{denyExecCredentials: true})
	if err != nil {
		t.Fatalf("static-credential kubeconfig refused: %v", err)
	}
	if cfg.BearerToken != "probe-token" {
		t.Errorf("BearerToken = %q, want %q", cfg.BearerToken, "probe-token")
	}
}

// An operator naming a path on the command line already has the authority an exec
// plugin would give it, so the default resolution leaves the plugin alone.
func TestLoadConfigAllowsExecCredentialsByDefault(t *testing.T) {
	cfg, _, err := loadConfig(writeKubeconfig(t, execAuth), connOptions{})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.ExecProvider == nil {
		t.Fatal("ExecProvider is nil; the fixture no longer exercises the exec path this test guards")
	}
	if cfg.ExecProvider.Command != "/usr/bin/attacker-chosen" {
		t.Errorf("ExecProvider.Command = %q, want the fixture's command", cfg.ExecProvider.Command)
	}
}

func TestResolveOptions(t *testing.T) {
	if got := resolveOptions(nil); got.denyExecCredentials {
		t.Error("denyExecCredentials set with no options applied")
	}
	if got := resolveOptions([]Option{WithoutExecCredentials()}); !got.denyExecCredentials {
		t.Error("WithoutExecCredentials did not set denyExecCredentials")
	}
}
