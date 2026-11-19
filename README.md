# Server Manager

A self-hosted, console-first platform for managing Linux cloud servers from one place:
dashboard, Docker, databases, services, processes, firewall, banned IPs, audit logs,
traffic, disk cleanup, swap, timezone, security checks, domains and TLS.

**Design principles**

- **Secure by default:** agents connect *out* over mutual TLS. Managed servers expose no management port. MFA, RBAC and a tamper-evident audit log for every action.
- **Efficient:** a single static Go binary per server (≤ 30 MB RAM), one long-lived gRPC stream per server.
- **Safe operations:** typed actions only, dry-run, confirmations by risk level, automatic rollback for firewall and SSH changes.

## Components

| Binary | Role |
|--------|------|
| `sm-server` | Control plane: API, auth, RBAC, audit, jobs, alerts, internal CA |
| `sm-agent` | Runs on each server; collects metrics/logs and executes actions (`sm-agent privd` is the local privileged helper) |
| `smctl` | Operator CLI and full-screen TUI |

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Development plan](docs/DEVELOPMENT_PLAN.md)

## Status

Planning — see the [development plan](docs/DEVELOPMENT_PLAN.md) for the roadmap.
