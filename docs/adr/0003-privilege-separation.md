# ADR 0003: Split the agent into an unprivileged agent and a local privileged helper

Status: Accepted · Date: 2026-11-19

## Context

Many operations (firewall, swap, services, packages, Docker) need root. A network-facing process running as root turns any parsing or protocol bug into full host compromise.

## Decision

The agent runs as two processes from the same binary:

- `sm-agent` — unprivileged user `smagent`, systemd-sandboxed, owns the network connection.
- `sm-agent privd` — root, **no network access**, listens only on a local UNIX socket, accepts connections only from the `smagent` UID (`SO_PEERCRED`), and executes a fixed set of typed privileged actions.

Access to the Docker socket is root-equivalent and therefore goes through the helper as well.

## Consequences

- A remote bug in the network-facing code does not directly yield root.
- Privileged code is small and reviewable.
- Two systemd units and a local IPC protocol to maintain.
- Implemented in Phase 1 (task 1.4).
