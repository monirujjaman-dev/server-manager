# ADR 0007: nftables as the primary firewall backend

Status: Accepted · Date: 2026-11-19

## Context

Firewall changes are the most likely way to lock an operator out of a server. Rollback must be reliable. Distributions use nftables directly, or ufw/firewalld on top of it.

## Decision

Manage rules with **nftables** through netlink (`google/nftables`). Ruleset changes are applied atomically; the previous ruleset is saved and restored automatically unless the control plane confirms reachability over a new connection within 90 seconds. ufw and firewalld are supported through adapters for servers that already use them.

## Consequences

- Atomic replace makes rollback dependable.
- Modern kernel default on all supported distributions.
- Adapters are needed so that existing ufw/firewalld setups are not silently overwritten.
