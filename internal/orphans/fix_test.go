package orphans

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanohype/cloudgov/internal/cloud"
)

func TestDeleteCommand(t *testing.T) {
	cases := []struct {
		name    string
		orphan  cloud.OrphanResource
		want    []string // substrings the command must contain
		notWant []string // substrings it must NOT contain
		empty   bool     // no delete path expected
	}{
		{
			name:   "disk",
			orphan: cloud.OrphanResource{Kind: cloud.OrphanDisk, ID: "vol-123", Region: "us-west-2"},
			want:   []string{"aws ec2 delete-volume --volume-id 'vol-123'", "--region 'us-west-2'"},
		},
		{
			name:   "ip",
			orphan: cloud.OrphanResource{Kind: cloud.OrphanIP, ID: "eipalloc-9", Region: "us-east-1"},
			want:   []string{"aws ec2 release-address --allocation-id 'eipalloc-9'", "--region 'us-east-1'"},
		},
		{
			name:   "load balancer",
			orphan: cloud.OrphanResource{Kind: cloud.OrphanLoadBalancer, ID: "arn:aws:elb:lb/abc", Region: "us-west-2"},
			want:   []string{"aws elbv2 delete-load-balancer --load-balancer-arn 'arn:aws:elb:lb/abc'"},
		},
		{
			name:   "eks log group",
			orphan: cloud.OrphanResource{Kind: cloud.OrphanEKSLogGroup, ID: "/aws/eks/dead/cluster", Region: "us-west-2"},
			want:   []string{"aws logs delete-log-group --log-group-name '/aws/eks/dead/cluster'"},
		},
		{
			name:   "karpenter queue",
			orphan: cloud.OrphanResource{Kind: cloud.OrphanKarpenterQueue, ID: "https://sqs.us-west-2.amazonaws.com/1/Karpenter-dead", Region: "us-west-2"},
			want:   []string{"aws sqs delete-queue --queue-url 'https://sqs.us-west-2.amazonaws.com/1/Karpenter-dead'"},
		},
		{
			name:   "karpenter rule removes targets then deletes by name",
			orphan: cloud.OrphanResource{Kind: cloud.OrphanKarpenterRule, ID: "arn:aws:events:us-west-2:1:rule/KarpenterSpot", Name: "KarpenterSpot", Region: "us-west-2"},
			want: []string{
				"aws events list-targets-by-rule --rule 'KarpenterSpot'",
				"aws events remove-targets --rule 'KarpenterSpot'",
				"aws events delete-rule --name 'KarpenterSpot'",
				"if [ -n \"$_ids\" ]; then",
			},
			notWant: []string{"arn:aws:events"}, // rule ops are name-keyed, never the ARN
		},
		{
			name:    "no region omits the flag",
			orphan:  cloud.OrphanResource{Kind: cloud.OrphanDisk, ID: "vol-x"},
			want:    []string{"aws ec2 delete-volume --volume-id 'vol-x'"},
			notWant: []string{"--region"},
		},
		{
			name:   "snapshot",
			orphan: cloud.OrphanResource{Kind: cloud.OrphanSnapshot, ID: "snap-1", Region: "us-west-2"},
			want:   []string{"aws ec2 delete-snapshot --snapshot-id 'snap-1'", "--region 'us-west-2'"},
		},
		{
			name:   "image deregisters the AMI",
			orphan: cloud.OrphanResource{Kind: cloud.OrphanImage, ID: "ami-1", Region: "us-west-2"},
			want:   []string{"aws ec2 deregister-image --image-id 'ami-1'"},
		},
		{
			// The instance and cluster forms take different flags on different
			// subcommands; emitting one for the other silently fails at run time.
			name:    "db snapshot deletes via the instance subcommand",
			orphan:  cloud.OrphanResource{Kind: cloud.OrphanDBSnapshot, ID: "old-db-final", Region: "us-west-2"},
			want:    []string{"aws rds delete-db-snapshot --db-snapshot-identifier 'old-db-final'", "--region 'us-west-2'"},
			notWant: []string{"delete-db-cluster-snapshot"},
		},
		{
			name:    "db cluster snapshot deletes via the cluster subcommand",
			orphan:  cloud.OrphanResource{Kind: cloud.OrphanDBClusterSnapshot, ID: "stg-snap", Region: "us-west-2"},
			want:    []string{"aws rds delete-db-cluster-snapshot --db-cluster-snapshot-identifier 'stg-snap'"},
			notWant: []string{"delete-db-snapshot --db-snapshot-identifier"},
		},
		{
			name:   "empty id has no delete path",
			orphan: cloud.OrphanResource{Kind: cloud.OrphanDisk, ID: ""},
			empty:  true,
		},
		{
			name:   "rule without a name has no delete path",
			orphan: cloud.OrphanResource{Kind: cloud.OrphanKarpenterRule, ID: "arn:aws:events:...:rule/x"},
			empty:  true,
		},
		{
			name:   "unknown kind has no delete path",
			orphan: cloud.OrphanResource{Kind: cloud.OrphanKind("mystery"), ID: "x-1"},
			empty:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deleteCommand(tc.orphan)
			if tc.empty {
				if got != "" {
					t.Fatalf("want no delete command, got %q", got)
				}
				return
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("command %q missing %q", got, w)
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(got, nw) {
					t.Errorf("command %q should not contain %q", got, nw)
				}
			}
		})
	}
}

func TestShellQuoteEscapesSingleQuotes(t *testing.T) {
	// AWS IDs don't contain quotes, but the script must stay correct if one does.
	if got, want := shellQuote("a'b"), `'a'\''b'`; got != want {
		t.Errorf("shellQuote(\"a'b\") = %q, want %q", got, want)
	}
}

func TestWriteFixScripts(t *testing.T) {
	dir := t.TempDir()
	orphans := []cloud.OrphanResource{
		{Kind: cloud.OrphanDisk, ID: "vol-1", Name: "vol-1", Region: "us-west-2", Provider: "aws", Detail: "available"},
		{Kind: cloud.OrphanEKSLogGroup, ID: "/aws/eks/dead/cluster", Name: "/aws/eks/dead/cluster", Region: "us-west-2", Provider: "aws"},
		{Kind: cloud.OrphanKind("mystery"), ID: "x-1", Provider: "aws"}, // not deletable → skipped
	}

	files, err := WriteFixScripts(orphans, dir)
	if err != nil {
		t.Fatalf("WriteFixScripts: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("want 1 script (one provider), got %d: %v", len(files), files)
	}

	want := filepath.Join(dir, "delete-orphans-aws.sh")
	if files[0] != want {
		t.Errorf("script path: got %q, want %q", files[0], want)
	}

	body, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}
	script := string(body)
	for _, must := range []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"DESTRUCTIVE",
		"aws ec2 delete-volume --volume-id 'vol-1'",
		"aws logs delete-log-group --log-group-name '/aws/eks/dead/cluster'",
	} {
		if !strings.Contains(script, must) {
			t.Errorf("script missing %q\n---\n%s", must, script)
		}
	}
	if strings.Contains(script, "x-1") {
		t.Errorf("non-deletable kind leaked into script:\n%s", script)
	}

	// Executable bit set.
	info, err := os.Stat(want)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("script not executable: mode %v", info.Mode())
	}
}

func TestWriteFixScriptsDiffBeforeWrite(t *testing.T) {
	dir := t.TempDir()
	orphans := []cloud.OrphanResource{
		{Kind: cloud.OrphanDisk, ID: "vol-1", Name: "vol-1", Region: "us-west-2", Provider: "aws"},
	}
	path := filepath.Join(dir, "delete-orphans-aws.sh")

	if _, err := WriteFixScripts(orphans, dir); err != nil {
		t.Fatalf("first write: %v", err)
	}
	first, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// Re-running with identical input must not rewrite the file (idempotent).
	if _, err := WriteFixScripts(orphans, dir); err != nil {
		t.Fatalf("second write: %v", err)
	}
	second, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !first.ModTime().Equal(second.ModTime()) {
		t.Errorf("unchanged script was rewritten: mtime %v -> %v", first.ModTime(), second.ModTime())
	}
}

func TestWriteFixScriptsNoDeletable(t *testing.T) {
	dir := t.TempDir()
	// Only non-deletable kinds → no scripts, no error.
	files, err := WriteFixScripts([]cloud.OrphanResource{
		{Kind: cloud.OrphanKind("mystery"), ID: "x-1", Provider: "aws"},
	}, dir)
	if err != nil {
		t.Fatalf("WriteFixScripts: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("want no scripts, got %v", files)
	}
}

// The provider on a saved report decides a filename, and `cloudgov remediate`
// reads it out of a file an operator received rather than one cloudgov wrote.
// This generator's scripts are written 0700 and their body is a list of DELETE
// commands, so an escaping name is the worst version of the defect in the tree.
func TestWriteFixScriptsRefusesAProviderThatNamesAPath(t *testing.T) {
	for _, provider := range []string{
		"../ESCAPED",
		"../../ESCAPED",
		"../../../ESCAPED",
		"sub/ESCAPED",
		// Segments that cancel back inside are refused too: the result is a file
		// this code did not name, whether or not it lands where it meant to.
		"x/../aws",
		"/etc/cron.d/ESCAPED",
		"..",
		"",
	} {
		t.Run(provider, func(t *testing.T) {
			root := t.TempDir()
			out := filepath.Join(root, "out")

			_, err := WriteFixScripts([]cloud.OrphanResource{{
				Kind: cloud.OrphanDisk, ID: "vol-1", Region: "us-east-1",
				Provider: provider,
			}}, out)
			if err == nil {
				t.Fatalf("provider %q was accepted; it names a path, not a file", provider)
			}

			// The refusal is only worth having if nothing was written. Checked over
			// the whole temporary tree rather than over `out`, because the failure
			// this guards against is a file appearing somewhere else.
			for _, path := range treeFiles(t, root) {
				if filepath.Dir(path) != out {
					t.Errorf("provider %q produced %s, outside %s", provider, path, out)
				}
			}
		})
	}
}

// treeFiles returns every regular file under root.
func treeFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}
