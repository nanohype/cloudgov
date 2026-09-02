// Package integration holds tests that exercise the provider → scanner → output
// layers together. A fixture provider is registered through the real provider
// registry (providers.NewRegistry / Capable), resolved by capability, run through
// the domain scanner, and rendered by the output package.
//
// This is the substance of what a command does, but not the command shell
// itself: a command's RunE resolves providers via providers.Resolve (→
// Default()), which is AWS-backed and has no test-injection seam, so no test in
// this repository executes a RunE.
//
// That gap is stated rather than covered. Package cmd tests the pure helpers a
// handler calls — severity resolution, output-format resolution, the exit-code
// gate — and checks the handlers' SOURCE for invariants an AST can see, such as
// whether each one gates on what its providers could not read. Neither runs a
// handler, so flag→ScanOptions threading, the output-format switch and the
// exit-code path are read but never exercised. `go tool cover -func` reports
// every runXxx at 0%, and .coverage-floors floors the package accordingly.
//
// What these tests do catch is the composition break the per-layer unit tests
// miss: a scanner that resolves or filters wrong, or a renderer that drops a
// field.
package integration
