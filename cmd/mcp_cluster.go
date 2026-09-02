package cmd

import (
	cloudk8s "github.com/nanohype/cloudgov/internal/cloud/k8s"
)

// This decision lives in its own file so it can carry a per-file coverage floor.
//
// A package floor cannot reach it: this function is four lines inside a large
// package, so it measured 0% while the package average stayed above its floor
// and nothing reported the gap. The per-file floor in .coverage-floors is what
// makes the branch visible at all — a package average cannot see one function,
// whatever the distance between the floor and the average happens to be. It is the entire control on whether a
// kubeconfig NAMED BY THE MODEL may run an exec credential plugin — an arbitrary
// command, in a process holding live AWS credentials — and both sides of its one
// branch decide whether that command runs.

// mcpClusterOptions decides what a caller-named kubeconfig is allowed to do.
//
// A kubeconfig can authenticate by running an exec credential plugin, and the
// command it runs is named by the file. Over the CLI the operator typed the
// path, so the file and the process are already under the same authority. Over
// MCP the path is a tool argument — model output — reaching a process that
// holds live AWS credentials, so a named file must not be able to choose which
// binary runs. An empty argument names no file: the server falls back to its
// own kubeconfig chain, which is the operator's, and an exec plugin there is
// the operator's own choice.
func mcpClusterOptions(kubeconfig string) []cloudk8s.Option {
	if kubeconfig == "" {
		return nil
	}
	return []cloudk8s.Option{cloudk8s.WithoutExecCredentials()}
}
