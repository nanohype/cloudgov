---
name: verify
description: Run full build, test, and lint checks to verify code changes are correct
---

Run the full verification pipeline for the cloudgov project. Execute these commands in order and report results:

1. `task build` — compile the binary with ldflags
2. `task test` — run all tests (`go test ./...`)
3. `task lint` — run golangci-lint

If any step fails, stop and report the failure with the full error output. Do not proceed to the next step.

After all steps pass, report a brief summary: build status, test count/pass rate, and any lint warnings.
