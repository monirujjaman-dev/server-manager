# ADR 0005: ConnectRPC over plain gRPC with grpc-gateway

Status: Accepted · Date: 2026-11-19

## Context

Agents need efficient bidirectional streaming (gRPC). The CLI and the future web UI need a browser-friendly API. Plain gRPC needs grpc-gateway or Envoy to serve browsers.

## Decision

Use **ConnectRPC** (`connectrpc.com/connect`) with protobuf schemas managed by **buf**. Agents use the gRPC protocol; browsers and scripts can use Connect/JSON from the same handlers on standard `net/http`.

## Consequences

- One set of handlers for agents, CLI and web UI.
- Runs on the standard library HTTP server, so TLS, timeouts and HTTP/2 settings are configured in one place.
- `buf lint` and `buf breaking` run in CI to protect wire compatibility.
- Smaller ecosystem than grpc-go (interceptors, middleware), acceptable for our needs.
