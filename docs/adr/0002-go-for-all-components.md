# ADR 0002: Go for agent, control plane and CLI

Status: Accepted · Date: 2026-11-19

## Context

The agent runs on every server and must be small, dependency-free and efficient. The control plane and CLI share message types and logic with it. Candidates: Go, Rust, Python, Node.js.

## Decision

All components are written in **Go**.

## Consequences

- Single static binaries with no runtime on managed servers (`sm-agent` ≈ 12 MB).
- Mature libraries for systemd D-Bus, Docker, nftables/netlink, gRPC and TLS.
- One language and shared protobuf types across all components.
- Rust would give stronger memory-safety guarantees and smaller binaries, at the cost of slower development; Go's memory safety (no manual memory management) is sufficient for this workload.
- Python/Node.js would need a runtime on every server and use several times more memory.
