# Development Guide

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Go | 1.26+ (toolchain pinned to 1.27.4 in `go.mod`) | Older Go versions download the pinned toolchain automatically. |
| Docker + Compose | recent | Only for `make dev-up` (PostgreSQL, VictoriaMetrics). |
| golangci-lint | v2.15.0 | `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0` |
| make, git | any | |

`buf`, `protoc-gen-go`, `protoc-gen-connect-go`, `sqlc` and `govulncheck` are pinned in the
separate `tools/` module and run with `go tool -modfile=tools/go.mod <name>`; nothing else
needs to be installed. They are kept out of the main `go.mod` so their dependencies never
end up in the shipped binaries.

## Common tasks

```bash
make help             # list all targets
make build            # bin/sm-server, bin/sm-agent, bin/smctl
make test             # go test -race ./...
make lint             # golangci-lint (with gosec) + buf lint
make vuln             # govulncheck
make generate         # regenerate gen/ (protobuf) and internal/server/store/db (sqlc)
```

Generated code is committed. CI fails if `make generate` produces a diff, so run it after
changing anything under `api/proto/`, `internal/server/store/migrations/` or
`internal/server/store/queries/`.

## Local control plane and agent

```bash
make dev-up           # PostgreSQL on 127.0.0.1:5432, VictoriaMetrics on 127.0.0.1:8428
make dev-migrate      # apply database migrations
make dev-pki          # CA and server certificate in ./.dev/pki
make dev-server       # terminal 1
make dev-enroll       # terminal 2: token + `sm-agent enroll` into ./.dev/agent
make dev-agent        # terminal 2
bin/sm-server servers list --config deploy/dev/sm-server.yaml
bin/smctl health --server https://127.0.0.1:8444 --ca-file .dev/pki/root.crt
```

`make dev-enroll` runs the real enrollment flow: `sm-server enroll create-token` prints a
one-time token and the control plane's public-key pin, and `sm-agent enroll` generates
the agent key locally, enrolls, and writes `agent.yaml` next to the key and certificates.
Run it with `NAME=dev-2` to enroll a second agent into another directory by setting
`DEV_DIR` as well.

Admin commands on the control-plane host (they use the database directly until the
operator API gets user authentication):

```bash
sm-server groups create production
sm-server enroll create-token --name web-1 --group production
sm-server servers list
sm-server servers revoke web-1 --reason "decommissioned"
sm-server audit list
sm-server audit verify

sm-server system info web-1
sm-server services list web-1 --filter nginx
sm-server services restart web-1 nginx
sm-server processes list web-1 --sort mem --limit 20
sm-server processes kill web-1 1234 --start 567890 --yes   # medium risk: needs --yes

sm-server dashboard --watch 5s
sm-server logs web-1 --unit nginx --priority err --since 2h
sm-server logs web-1 --unit nginx --follow
sm-server logins web-1 --failed
```

Set `victoriametrics_url: http://127.0.0.1:8428` (the dev compose service) to keep
metric history; query it with PromQL, e.g. `sm_cpu_percent{server_id="…"}`.

Privileged actions (service control, signals) need the helper. On a real server it runs
from `deploy/systemd/sm-agent-privd.service`; locally, run it as root next to the agent
and point both at the same socket:

```bash
sudo bin/sm-agent privd --privd-config privd.yaml   # socket, agent_user, cert_file, command_key_file
```

`agent_user` must not be root; the helper refuses connections from any other UID.

Configuration is read from YAML (`--config`) and can be overridden by environment
variables: `SM_` + key for `sm-server` (e.g. `SM_API_LISTEN`), `SM_AGENT_` + key for
`sm-agent`. Unknown keys in a config file are rejected.

## Database tests

Database-backed tests create their own throw-away database for each test (and drop it
afterwards), so packages run in parallel safely. They need an admin URL for a server
where that user may create databases:

```bash
SM_TEST_DATABASE_URL='postgres://sm:sm-dev-only@127.0.0.1:5432/sm?sslmode=disable' make test
```

Without `SM_TEST_DATABASE_URL` those tests are skipped. CI always runs them.

## Test virtual machines

Modules that change the system (firewall, swap, fstab, services) are tested **only in
VMs**, never on a developer machine. Phase 1 adds automated VM tests under `test/e2e/`;
until then, create VMs manually:

```bash
multipass launch 24.04 --name sm-ubuntu --cpus 1 --memory 1G
multipass launch debian-12 --name sm-debian --cpus 1 --memory 1G   # or: incus launch images:debian/12 sm-debian --vm
incus launch images:rockylinux/9 sm-rocky --vm
```

Copy `bin/sm-agent` (built with `GOOS=linux GOARCH=<arch> make build`) into the VM, run
`sm-agent keygen`, sign the CSR on the host with `sm-server pki sign-agent`, and point the
agent at the host's agent listener (bind `agent_listen` to an address the VM can reach and
include that address in the server certificate with `sm-server pki issue-server --ip`).

## Conventions

- Trunk-based development: short branches, pull requests, squash merge.
- Conventional Commits: `feat(agent): …`, `fix(pki): …`, `docs: …`.
- Every new dependency needs a reason in the pull request description.
- Security-relevant code (`internal/pki`, `internal/server/gateway`, future `privd`, `auth`,
  `rbac`) needs tests for the rejection paths, not only the happy path.
