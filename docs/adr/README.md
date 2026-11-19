# Architecture Decision Records

Each ADR records one significant decision: its context, the decision and its consequences. ADRs are immutable once accepted; a later ADR supersedes an earlier one.

| ADR | Decision |
|-----|----------|
| [0001](0001-agent-based-outbound-connection.md) | Agent-based architecture with outbound-only connections |
| [0002](0002-go-for-all-components.md) | Go for agent, control plane and CLI |
| [0003](0003-privilege-separation.md) | Split the agent into an unprivileged agent and a local privileged helper |
| [0004](0004-typed-actions-only.md) | Typed actions only; interactive shell is break-glass |
| [0005](0005-connectrpc.md) | ConnectRPC over plain gRPC with grpc-gateway |
| [0006](0006-postgresql-and-victoriametrics.md) | PostgreSQL for state and VictoriaMetrics for time series |
| [0007](0007-nftables-firewall-backend.md) | nftables as the primary firewall backend |
| [0008](0008-crowdsec-for-banned-ips.md) | CrowdSec preferred over fail2ban for banned IPs |
