// Package integration holds tests that exercise the provider → scanner → output
// layers together. A fixture provider is registered through the real provider
// registry (providers.NewRegistry / Capable), resolved by capability, run through
// the domain scanner, and rendered by the output package.
//
// This is the substance of what a command does, but not the command shell
// itself, and the shell splits in two.
//
// A handler that reads saved reports resolves nothing, so it can be driven
// directly; package cmd drives runCompliance and runCompare that way, exercising their
// flags, their exit codes and the artifacts they write rather than reading them.
// The remaining report-reading handlers can be driven the same way and are not
// yet.
//
// A handler that reaches an account resolves providers through providers.Resolve
// (→ Default()), which is AWS-backed and has no test-injection seam, so nothing
// runs those: package cmd tests the pure helpers they call and checks their
// SOURCE for invariants an AST can see, which proves a call site exists rather
// than that the value reaches it.
//
// The split is where it is because of the seam, not because of what was
// convenient, and .coverage-floors floors package cmd against the half that is
// only read.
//
// What these tests catch is the composition break the per-layer unit tests miss:
// a scanner that resolves or filters wrong, or a renderer that drops a field.
package integration
