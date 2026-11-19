-- name: UpsertServerMetrics :exec
-- Older batches (sent after a reconnect) never overwrite newer ones.
INSERT INTO server_metrics (
    server_id, collected_at, cpu_percent, cpu_count, load1, load5, load15,
    memory_total_bytes, memory_available_bytes, swap_total_bytes, swap_free_bytes,
    uptime_seconds, disk_max_used_percent, disk_max_mount, net_rx_bytes_per_second, net_tx_bytes_per_second
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
ON CONFLICT (server_id) DO UPDATE SET
    collected_at = EXCLUDED.collected_at, cpu_percent = EXCLUDED.cpu_percent, cpu_count = EXCLUDED.cpu_count,
    load1 = EXCLUDED.load1, load5 = EXCLUDED.load5, load15 = EXCLUDED.load15,
    memory_total_bytes = EXCLUDED.memory_total_bytes, memory_available_bytes = EXCLUDED.memory_available_bytes,
    swap_total_bytes = EXCLUDED.swap_total_bytes, swap_free_bytes = EXCLUDED.swap_free_bytes,
    uptime_seconds = EXCLUDED.uptime_seconds, disk_max_used_percent = EXCLUDED.disk_max_used_percent,
    disk_max_mount = EXCLUDED.disk_max_mount, net_rx_bytes_per_second = EXCLUDED.net_rx_bytes_per_second,
    net_tx_bytes_per_second = EXCLUDED.net_tx_bytes_per_second
WHERE server_metrics.collected_at < EXCLUDED.collected_at;

-- name: Dashboard :many
SELECT s.id, s.name, s.status, s.last_seen_at, s.agent_version,
       m.collected_at, m.cpu_percent, m.cpu_count, m.load1, m.memory_total_bytes, m.memory_available_bytes,
       m.disk_max_used_percent, m.disk_max_mount, m.net_rx_bytes_per_second, m.net_tx_bytes_per_second, m.uptime_seconds
FROM servers s LEFT JOIN server_metrics m ON m.server_id = s.id
ORDER BY s.name;

-- name: ListServersWithMetrics :many
SELECT s.id, s.name, s.group_id, g.name AS group_name, s.status, s.hostname, s.distro, s.distro_version,
       s.agent_version, s.last_seen_at,
       m.collected_at, m.cpu_percent, m.cpu_count, m.load1, m.memory_total_bytes, m.memory_available_bytes,
       m.disk_max_used_percent, m.disk_max_mount, m.net_rx_bytes_per_second, m.net_tx_bytes_per_second, m.uptime_seconds
FROM servers s
LEFT JOIN server_groups g ON g.id = s.group_id
LEFT JOIN server_metrics m ON m.server_id = s.id
ORDER BY s.name;
