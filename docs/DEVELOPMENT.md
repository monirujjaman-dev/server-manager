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

## Windows and macOS

`sm-server` and `smctl` build and run on Windows, macOS and Linux. `sm-agent` manages
**Linux** servers only (it reads `/proc`, talks to systemd and uses `SO_PEERCRED`): it
compiles everywhere, but `sm-agent run` and `sm-agent privd` refuse to start off Linux.

- `make` needs a POSIX shell with `git` and `date`, e.g. Git Bash or MSYS2 on Windows.
- Easiest on Windows: clone and run the whole dev setup inside **WSL2** (Ubuntu). Docker
  Desktop's WSL integration provides `docker compose` there.
- Alternatively run the control plane on Windows and only the agent in WSL2. Enable
  mirrored networking (`networkingMode=mirrored` in `%UserProfile%\.wslconfig`) so the
  agent reaches the control plane on `127.0.0.1`, then run `make dev-enroll dev-agent`
  inside WSL.
- On Windows, private-key file permissions are not checked (Windows uses ACLs, not Unix
  mode bits); keep `.dev/` and production PKI directories readable only by your user.

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
make dev-up           # PostgreSQL on 127.0.0.1:5434, VictoriaMetrics on 127.0.0.1:8428
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

Create the first account on the control-plane host (it prompts for a password and
shows a TOTP secret to add to an authenticator app, then asks for one code to confirm):

```bash
bin/sm-server users create you@example.com --role owner --config deploy/dev/sm-server.yaml
```

Operators then use `smctl`, which logs in once and stores the session:

```bash
smctl login --server https://127.0.0.1:8444 --ca-file .dev/pki/root.crt
smctl whoami
smctl dashboard --watch 5s
smctl system info web-1
smctl services restart web-1 nginx
smctl processes list web-1 --sort mem --limit 20
smctl processes kill web-1 1234 --start 567890 --yes     # medium risk: needs --yes
smctl logs web-1 --unit nginx --priority err --since 2h
smctl logs web-1 --unit nginx --follow
smctl logins web-1 --failed
smctl enroll create-token --name web-2 --group production  # admin; asks for a fresh MFA code if needed
smctl servers revoke web-2 --reason "decommissioned" --yes # admin; high risk
smctl audit list                                           # global admin
smctl logout
```

Host-side admin commands (database access, no login) stay in `sm-server` for
bootstrapping and break-glass use:

```bash
sm-server users create|list|grant|ungrant|disable|enable|reset
sm-server groups create production
sm-server enroll create-token --name web-1 --group production
sm-server servers list|revoke
sm-server audit list|verify
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
SM_TEST_DATABASE_URL='postgres://sm:sm-dev-only@127.0.0.1:5434/sm?sslmode=disable' make test
```

Without `SM_TEST_DATABASE_URL` those tests are skipped. CI always runs them.

## Packages and system tests

```bash
make packages      # dist/: .deb/.rpm for sm-agent, sm-server, smctl (amd64, arm64),
                   # smctl for macOS/Windows, install-agent.sh, checksums.txt
make system-test   # needs Docker; DISTROS="ubuntu-24.04" to test one distribution
```

`make system-test` (`test/system/run.sh`) starts PostgreSQL, a control plane installed
from the `sm-server` package under systemd, and one agent container per distribution
installed with `install-agent.sh`. It then uses `smctl` to restart and stop a real unit,
kill a process, query the journal, find sudo records, check unit hardening
(`systemd-analyze security`), revoke the server and remove the package. Set `KEEP=1` to
leave the containers running for inspection. CI runs it for Ubuntu 24.04 and Rocky 9.

Releases: push a tag `vX.Y.Z`; `.github/workflows/release.yml` builds `dist/`, signs
`checksums.txt` with cosign (keyless, the workflow's identity) and publishes a GitHub
release. See [INSTALL.md](INSTALL.md) for installing from a release.

## Conventions

- Trunk-based development: short branches, pull requests, squash merge.
- Conventional Commits: `feat(agent): …`, `fix(pki): …`, `docs: …`.
- Every new dependency needs a reason in the pull request description.
- Security-relevant code (`internal/pki`, `internal/server/gateway`, future `privd`, `auth`,
  `rbac`) needs tests for the rejection paths, not only the happy path.
