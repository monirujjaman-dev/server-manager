# ADR 0008: CrowdSec preferred over fail2ban for banned IPs

Status: Accepted · Date: 2026-11-19

## Context

Brute-force protection must cover the whole fleet: an IP attacking one server should be blocked everywhere.

## Decision

Integrate **CrowdSec** (local API decisions) as the preferred backend, with a **fail2ban** adapter for servers that already run it. The control plane can push fleet-wide ban decisions.

## Consequences

- Shared decisions across servers and optional community blocklists.
- One more daemon on each server when CrowdSec is chosen.
- fail2ban support keeps existing setups working.
