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
make build
make dev-pki      # local CA, server certificate and one enrolled agent in ./.dev
make dev-server   # terminal 1
make dev-agent    # terminal 2
bin/smctl health --server https://127.0.0.1:8444 --ca-file .dev/pki/root.crt
```

See the [development guide](docs/DEVELOPMENT.md) for the database, tests and VMs.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Development plan](docs/DEVELOPMENT_PLAN.md)
- [Architecture decision records](docs/adr/README.md)
- [Development guide](docs/DEVELOPMENT.md)

## Status

Phase 0 (foundations) is complete: protobuf API, internal CA, mTLS agent stream with
heartbeats, database schema and migrations, CI. Phase 1 (enrollment, dashboard, services,
processes, logs, auth, RBAC, audit) is next — see the [development plan](docs/DEVELOPMENT_PLAN.md).
