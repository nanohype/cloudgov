// Package integration holds tests that exercise the provider → scanner → output
// layers together. A fixture provider is registered through the real provider
// registry (providers.NewRegistry / Capable), resolved by capability, run through
// the domain scanner, and rendered by the output package.
//
// This is the substance of what a command does, but not the command shell itself:
// a command's RunE resolves providers via providers.Resolve (→ Default()), which is
// AWS-backed and intentionally has no test-injection seam, so the cobra layer
// (flag→ScanOptions threading, the output-format switch, gate/exit-code) is covered
// by the unit tests in package cmd, not here. These tests catch composition breaks
// the per-layer unit tests miss: a scanner that resolves or filters wrong, or a
// renderer that drops a field.
package integration
