# ADR 0001: Agent-based architecture with outbound-only connections

Status: Accepted · Date: 2026-11-19

## Context

Managed servers must be controllable from one place, report live data, and expose as little attack surface as possible. Two families of solutions exist: agentless (SSH from a central host, as Ansible does) and agent-based.

Agentless management requires SSH (or another port) to be reachable from the control host on every server and turns the central SSH key into a master key for the fleet. Live metrics and log streams require polling over SSH, which is slow and expensive.

## Decision

Every managed server runs `sm-agent`, which **dials out** to the control plane and keeps one long-lived, mutually authenticated gRPC stream open. Managed servers listen on no management port. The control plane itself is reachable only over a private network (WireGuard / Headscale).

## Consequences

- No inbound port on managed servers; works behind NAT and restrictive security groups.
- Real-time streaming of metrics, logs and command results over one connection.
- Each server has its own credential (certificate), so compromise of one does not expose others.
- We must build, ship, and update an agent and support it on several distributions.
- The control plane becomes critical; agents must buffer while it is unavailable.
