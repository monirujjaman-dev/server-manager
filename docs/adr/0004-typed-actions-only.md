# ADR 0004: Typed actions only; interactive shell is break-glass

Status: Accepted · Date: 2026-11-19

## Context

A generic "run this command" endpoint is the fastest way to build features, but it means anyone who controls the console, or forges a command, can do anything on every server.

## Decision

Every operation is a **typed protobuf action** with validated parameters, a risk level, dry-run support where possible, and an optional automatic rollback. The agent rejects anything that is not a registered action. An interactive shell exists only as a `critical` action: disabled by default per server group, time-limited, recorded, and requiring step-up MFA.

## Consequences

- A compromised console session is limited to the actions its role allows.
- Each new feature needs a proto message, a handler and validation: more work up front.
- Commands are executed with argument arrays, never through a shell, which removes command injection.
