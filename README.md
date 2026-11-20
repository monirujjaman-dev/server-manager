# Server Manager

A self-hosted, console-first platform for managing Linux cloud servers from one place:
dashboard, Docker, databases, services, processes, firewall, banned IPs, audit logs,
traffic, disk cleanup, swap, timezone, security checks, domains and TLS.

**Design principles**

- **Secure by default:** agents connect *out* over mutual TLS. Managed servers expose no management port. MFA, RBAC and a tamper-evident audit log for every action.
- **Efficient:** a single static Go binary per server (about 13 MB RAM when idle), one long-lived gRPC stream per server.
- **Safe operations:** typed actions only, dry-run, confirmations by risk level, automatic rollback for firewall and SSH changes.

## Components

| Binary | Role |
|--------|------|
| `sm-server` | Control plane: API, auth, RBAC, audit, jobs, alerts, internal CA |
| `sm-agent` | Runs on each server; collects metrics/logs and executes actions (`sm-agent privd` is the local privileged helper) |
| `smctl` | Operator CLI and full-screen TUI |

## Quick start (development)

```bash
make dev-up dev-migrate dev-pki   # PostgreSQL + VictoriaMetrics, schema, local CA
make dev-server                   # terminal 1
make dev-enroll dev-agent         # terminal 2: enroll an agent with a one-time token, run it
bin/sm-server users create you@example.com --role owner --config deploy/dev/sm-server.yaml
bin/smctl login --server https://127.0.0.1:8444 --ca-file .dev/pki/root.crt
bin/smctl dashboard
```

See the [development guide](docs/DEVELOPMENT.md) for the database, tests and VMs.

## Documentation

- [Requirements](docs/REQUIREMENTS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Development plan](docs/DEVELOPMENT_PLAN.md)
- [Architecture decision records](docs/adr/README.md)
- [Installation](docs/INSTALL.md)
- [Development guide](docs/DEVELOPMENT.md)

## Status

- **Phase 0 (foundations):** done.
- **Phase 1 (MVP):** done — token enrollment, certificate renewal, database-backed
  revocation, hash-chained audit log, signed command dispatch, the privileged helper,
  system/services/processes actions, metrics and a fleet dashboard, journal/SSH/sudo
  logs, MFA login, RBAC per server group, `smctl`, and `.deb`/`.rpm` packages with an
  install script, tested in systemd containers on Ubuntu 24.04 and Rocky 9.
- **Phase 2 (operations):** in progress — bulk actions
  (`smctl services restart --group staging nginx`, `--all`, `web-1,web-2`), typed
  confirmation for medium- and higher-risk actions, Docker (`smctl docker ps`,
  `start/stop/restart/rm`, `logs`, `stats`, `images/volumes/networks`, `prune`), time
  zone and NTP (`smctl time`) and swap (`smctl swap`) are done; disk cleanup, updates,
  TUI and control-plane deployment are next. See the
  [development plan](docs/DEVELOPMENT_PLAN.md).
