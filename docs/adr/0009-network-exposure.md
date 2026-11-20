# ADR 0009: Network exposure of the control plane

Status: Accepted · Date: 2026-11-20

## Context

ADR 0001 places the control plane on a private network. In practice the managed servers
live in several clouds and regions, often without a private network between them, and the
operator works from a laptop. Requiring a VPN on every server is extra moving parts, and a
VPN outage would cut off the whole fleet.

The control plane has two listeners: the **agent gateway** (:8443) and the **operator API**
(:8444, which also serves enrollment).

## Decision

- The **agent gateway may be exposed to the internet**. It accepts only TLS 1.3 connections
  with a client certificate issued by the internal CA *and* recorded in the database; the
  serial is re-checked per handshake and per stream, so a stolen CA-signed certificate or a
  revoked server is refused. It speaks only the agent protocol.
- The **operator API should stay private**: reachable over WireGuard/Tailscale/Headscale or
  restricted to known IP addresses with the cloud firewall. Login is protected by MFA,
  lockout and rate limits, but keeping it off the internet removes it from scanning and
  credential-stuffing entirely.
- Because new servers must reach **enrollment**, enrollment will get its own exposure that
  is independent of the operator API (plan task 2.10). Until then, allow the enrollment
  path from new servers, for example by opening :8444 to the fleet's addresses only.

## Consequences

- Works across clouds without a VPN on every server; the VPN, if used, is only between the
  operator's laptop and the control plane.
- The agent port is internet-facing, so its TLS stack and the agent protocol handler are
  attack surface: they stay small, size-limited and covered by fuzzing (task 5.4).
- Operators need a VPN client or a static IP for the operator API; documented in
  INSTALL.md.
