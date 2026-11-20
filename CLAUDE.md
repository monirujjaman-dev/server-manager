# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Server Manager

Self-hosted fleet manager for Linux servers. Operators run `smctl` on Windows, macOS or
Linux; a control plane (`sm-server` + PostgreSQL + VictoriaMetrics) runs on an always-on
cloud VM; `sm-agent` runs on every managed server and dials out over mTLS.
Read `docs/REQUIREMENTS.md`, `docs/ARCHITECTURE.md` and `docs/DEVELOPMENT_PLAN.md` before
larger changes; decisions live in `docs/adr/`.

## Layout

- `cmd/sm-server`, `cmd/sm-agent`, `cmd/smctl`: binaries (cobra).
- `api/proto/sm/{agent,operator}/v1`: protobuf (ConnectRPC). Generated code in `gen/`.
- `internal/server/...`: control plane (gateway, enroll, jobs, auth, audit, api, store).
  SQL migrations and queries in `internal/server/store`; sqlc output in `store/db`.
- `internal/agent`, `internal/agent/modules`: agent and its read-only actions.
- `internal/privd`: root helper for privileged actions (UNIX socket, no network).
- `internal/command`: signed command envelope, `Describe` (risk) and `Validate`.
- `internal/pki`, `internal/ctl` (smctl client code), `internal/pkg/*`.
- `deploy/`: systemd units, nFPM packaging, install script, dev compose.
- `test/system`: package install tests in systemd containers.

## Commands

```bash
make build            # bin/sm-server, bin/sm-agent, bin/smctl
make test             # go test -race ./...  (DB tests need SM_TEST_DATABASE_URL)
make lint             # golangci-lint (with gosec) + buf lint; CI also runs buf breaking
make generate         # buf + sqlc; run after touching api/proto, store/migrations or
                      # store/queries; never edit gen/ or store/db by hand
make check-generated  # CI fails if generated code is stale
make vuln             # govulncheck
make packages         # .deb/.rpm + smctl binaries into dist/
make system-test      # needs Docker; Ubuntu 24.04 and Rocky 9 containers
make dev-up dev-migrate dev-pki dev-server   # local control plane (Postgres on :5434)
make dev-enroll dev-agent                    # second terminal: enroll and run a local agent
```

First operator account for dev: `bin/sm-server users create you@example.com --role owner
--config deploy/dev/sm-server.yaml`, then `smctl login --server https://127.0.0.1:8444
--ca-file .dev/pki/root.crt`. `sm-server` also keeps host-side break-glass admin commands
(users, groups, enroll, servers, audit verify) that talk to the database directly.

Run a single package: `go test -race -count=1 ./internal/server/auth/...`.
DB-backed tests use `SM_TEST_DATABASE_URL` pointing at an **admin** connection
(e.g. `postgres://sm:sm-dev-only@127.0.0.1:5434/postgres?sslmode=disable`); each test
creates and drops its own database. Without it those tests skip.

The Go toolchain is pinned in `go.mod`; tools (buf, sqlc, govulncheck, nfpm) are run via
`go tool -modfile=tools/go.mod <tool>`, not global installs. The one exception is
golangci-lint, which must be installed separately at the version CI pins (v2.15.0).
On Windows, `make` needs Git Bash/MSYS2; `sm-agent run`/`privd` refuse to start off Linux,
so run the agent in WSL2 (see `docs/DEVELOPMENT.md`).

Config is YAML (`--config`), overridable by env vars `SM_<KEY>` (sm-server) and
`SM_AGENT_<KEY>` (sm-agent). Unknown config keys are rejected.

## How a command flows (spans several packages)

1. Operator API (`internal/server/api`) checks RBAC/MFA and runs `command.Validate`;
   `jobs.Submit` inserts a `pending` job, audits "requested" and `NOTIFY sm_jobs`.
2. `jobs.Dispatcher` (LISTEN + 5 s sweep + agent-connect kick) claims jobs for connected
   servers (`FOR UPDATE SKIP LOCKED`), **signs at dispatch time** (60 s validity) and sends
   over the agent's stream via `gateway.Registry`.
3. The agent verifies signature, target, validity, replay and parameters, then runs
   read-only actions itself (`internal/agent/modules`) or forwards the signed command
   unchanged to privd over a UNIX socket (peer UID checked with `SO_PEERCRED`), which
   verifies everything again before acting as root.
4. The result comes back on the stream; `Dispatcher.Complete` accepts it only from the
   server it was sent to, once, and audits the outcome. Jobs are never re-sent: no result
   after 2 min is `failed` ("outcome unknown"); undispatched jobs expire after 10 min.

Agent identity: enrollment runs on the API listener (server TLS + public-key pin, since
the agent has no cert yet); the agent listener is mTLS-only and rejects any certificate
whose serial isn't recorded in `agent_certificates` or is revoked — checked per handshake
and per stream.

## Security invariants (do not weaken)

- Agents execute only **typed actions** defined in `actions.proto`. No remote shell, no
  `sh -c`, no string-built commands: external programs get an argv slice.
- Every action has a risk level in `command.Describe` and input checks in
  `command.Validate`. Validate runs on the server before signing and again on the agent.
- Commands are signed by the control plane (Ed25519), short-lived and replay-checked;
  `privd` re-verifies the signature before doing anything as root.
- Privileged work goes through `privd` only; the unprivileged agent never gains root.
- Every operator action and login is written to the hash-chained audit log.
- RBAC: servers outside a user's groups are reported as NotFound. High/critical actions
  need step-up MFA. Keep enrollment tokens and session tokens hashed at rest.
- Never log secrets, tokens, private keys or TOTP secrets.

## Adding an action

Use the `add-action` skill (`.claude/skills/add-action`). In short: proto message →
`make generate` → `command.Describe`/`Validate` + tests → agent `runLocal` (read-only) or
`privd` (privileged) → operator API/smctl subcommand with `--yes` for medium+ → tests →
docs (plan status, README).

## Conventions

- Cross-platform: `smctl` and `sm-server` must build for Windows and macOS (CI checks).
  Put Linux-only syscalls in `*_linux.go` with a `*_other.go` fallback. The agent and
  privd only run on Linux.
- Keep shell scripts POSIX `sh` unless they already use bash; lint with `shellcheck`.
  Line endings are LF everywhere (`.gitattributes`).
- Errors: wrap with context (`fmt.Errorf("…: %w", err)`); ConnectRPC errors use proper codes.
- Tests next to the code; prefer real PostgreSQL over mocks for store code.
- A PostToolUse hook gofmt's Go files after every Write/Edit (`internal/devtools/gofmthook`).
- Security-relevant code (pki, gateway, privd, auth, RBAC) needs tests for rejection
  paths, not only the happy path. Every new dependency needs a reason in the PR.
- Commits: Conventional Commits (`feat(agent): add docker.list action`, `fix(pki): …`),
  body explains why. Work on a branch; the maintainer squash-merges PRs.
- Before a PR touching server/agent/privd/command/pki/deploy/protos, run the
  `security-reviewer` subagent.
