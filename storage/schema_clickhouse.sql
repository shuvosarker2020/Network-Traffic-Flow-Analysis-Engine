-- AegisFlow Enterprise ClickHouse Schema
-- Designed for 1,000+ devices, 1,000,000+ interfaces, and 1-3+ months of high-speed retention

CREATE DATABASE IF NOT EXISTS aegisflow;

USE aegisflow;

-- 1. Raw Flow Records Table (Ultra-compressed Columnar, 90-Day Retention TTL)
CREATE TABLE IF NOT EXISTS raw_flows (
    timestamp DateTime CODEC(DoubleDelta, LZ4),
    device_id LowCardinality(String),
    device_name LowCardinality(String),
    vendor LowCardinality(String),
    site LowCardinality(String),
    
    in_ifindex UInt32 CODEC(T64, LZ4),
    in_if_name LowCardinality(String),
    out_ifindex UInt32 CODEC(T64, LZ4),
    out_if_name LowCardinality(String),
    
    src_ip IPv4,
    dst_ip IPv4,
    next_hop IPv4,
    
    src_port UInt16 CODEC(T64, LZ4),
    dst_port UInt16 CODEC(T64, LZ4),
    protocol UInt8 CODEC(T64, LZ4),
    tcp_flags UInt8 CODEC(T64, LZ4),
    tos UInt8 CODEC(T64, LZ4),
    dscp UInt8 CODEC(T64, LZ4),
    dscp_name LowCardinality(String),
    qos_class LowCardinality(String),
    
    src_as UInt32 CODEC(T64, LZ4),
    src_as_name LowCardinality(String),
    dst_as UInt32 CODEC(T64, LZ4),
    dst_as_name LowCardinality(String),
    dst_as_category LowCardinality(String),
    
    src_country LowCardinality(String),
    src_city LowCardinality(String),
    src_cloud LowCardinality(String),
    src_lat Float32,
    src_lon Float32,
    
    dst_country LowCardinality(String),
    dst_city LowCardinality(String),
    dst_cloud LowCardinality(String),
    dst_lat Float32,
    dst_lon Float32,
    
    application LowCardinality(String),
    app_category LowCardinality(String),
    flow_direction LowCardinality(String),
    
    packets UInt64 CODEC(T64, ZSTD(1)),
    bytes UInt64 CODEC(T64, ZSTD(1)),
    duration_ms UInt32 CODEC(T64, LZ4),
    sampling_rate UInt32 CODEC(T64, LZ4)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, device_id, in_ifindex, out_ifindex, protocol, dst_port, src_ip, dst_ip)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- 2. 5-Minute Rollup Table for Long-Term Capacity Planning & Burstable 95th Percentile Billing
CREATE TABLE IF NOT EXISTS flows_5m_rollup (
    bucket_5m DateTime CODEC(DoubleDelta, LZ4),
    device_id LowCardinality(String),
    in_ifindex UInt32 CODEC(T64, LZ4),
    out_ifindex UInt32 CODEC(T64, LZ4),
    src_as UInt32 CODEC(T64, LZ4),
    dst_as UInt32 CODEC(T64, LZ4),
    application LowCardinality(String),
    dscp LowCardinality(String),
    flow_direction LowCardinality(String),
    total_bytes UInt64,
    total_packets UInt64,
    flow_count UInt64
) ENGINE = SummingMergeTree((total_bytes, total_packets, flow_count))
PARTITION BY toYYYYMM(bucket_5m)
ORDER BY (bucket_5m, device_id, in_ifindex, out_ifindex, src_as, dst_as, application, dscp, flow_direction)
TTL bucket_5m + INTERVAL 180 DAY;

-- 3. Materialized View continuous feeder
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_flows_5m TO flows_5m_rollup AS
SELECT
    toStartOfFiveMinutes(timestamp) AS bucket_5m,
    device_id,
    in_ifindex,
    out_ifindex,
    src_as,
    dst_as,
    application,
    dscp_name AS dscp,
    flow_direction,
    sum(bytes) AS total_bytes,
    sum(packets) AS total_packets,
    count() AS flow_count
FROM raw_flows
GROUP BY bucket_5m, device_id, in_ifindex, out_ifindex, src_as, dst_as, application, dscp, flow_direction;
