-- +goose Up

-- Latest metrics per server, for the dashboard. History goes to VictoriaMetrics.
CREATE TABLE server_metrics (
    server_id              uuid             PRIMARY KEY REFERENCES servers (id) ON DELETE CASCADE,
    collected_at           timestamptz      NOT NULL,
    cpu_percent            double precision NOT NULL,
    cpu_count              integer          NOT NULL,
    load1                  double precision NOT NULL,
    load5                  double precision NOT NULL,
    load15                 double precision NOT NULL,
    memory_total_bytes     bigint           NOT NULL,
    memory_available_bytes bigint           NOT NULL,
    swap_total_bytes       bigint           NOT NULL,
    swap_free_bytes        bigint           NOT NULL,
    uptime_seconds         bigint           NOT NULL,
    -- Fullest filesystem.
    disk_max_used_percent  double precision NOT NULL,
    disk_max_mount         text             NOT NULL,
    net_rx_bytes_per_second double precision NOT NULL,
    net_tx_bytes_per_second double precision NOT NULL
);

-- +goose Down

DROP TABLE server_metrics;
