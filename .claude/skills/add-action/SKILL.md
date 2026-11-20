---
name: add-action
description: Add a new typed agent action (e.g. docker.list, swap.create) end to end — proto, risk and validation, agent or privd execution, operator API and smctl command, tests and docs. Use when implementing a plan task that adds something the agent does on a server.
---

# Add an agent action

Follow the steps in order; each has a check. Keep the security invariants in `CLAUDE.md`.

1. **Proto.** In `api/proto/sm/agent/v1/actions.proto` add `<Name>Request` and
   `<Name>Result` messages and a new field to the `ActionRequest` and `ActionResult`
   `oneof`s (next free field numbers; never reuse numbers). Bound every repeated or
   string field in comments and in `Validate`. Run `make generate` and `make lint`.

2. **Risk and validation** in `internal/command/actions.go`:
   - `Describe`: action name (`area.verb`, e.g. `docker.list`), risk level
     (read / low / medium / high / critical) and whether it is privileged.
   - `Validate`: reject anything outside a narrow allowlist (unit names, paths under fixed
     roots, PIDs > 1, limits). Add table tests in `command_test.go` for good and bad input.

3. **Execution.**
   - Read-only, no root: implement in `internal/agent/modules/<area>.go` and add a case
     to `runLocal` in `internal/agent/exec.go`. Linux-only code goes in `_linux.go`
     files with an `_other.go` stub so Windows/macOS builds keep working.
   - Needs root: add the case to `internal/privd/privd.go` (it re-verifies the signed
     envelope) and route it from the agent. Never call a shell; pass an argv slice
     with a fixed binary path, or use D-Bus/netlink/syscalls.
   - Cap output size and time; return structured results, not raw text.

4. **Operator surface.** The generic `ActionService` already signs and dispatches any
   validated `ActionRequest`. Add a `smctl` subcommand in `cmd/smctl/main.go` and a
   printer in `internal/ctl/print.go`. Medium and higher risk must require `--yes`;
   high/critical already trigger step-up MFA on the server.

5. **Tests.** Unit tests for the module; an end-to-end case through the gateway where
   similar actions have one (`internal/server/...` tests using `storetest`). Run
   `make test` (with `SM_TEST_DATABASE_URL`) and
   `GOOS=windows go build ./cmd/smctl ./cmd/sm-server`.

6. **Docs.** Update the task status in `docs/DEVELOPMENT_PLAN.md`, the feature table in
   `docs/REQUIREMENTS.md`, and the command list in `README.md`.
