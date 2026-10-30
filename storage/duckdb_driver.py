"""
DuckDB Columnar OLAP Driver for AegisFlow
High-throughput vectorized analytical engine capable of processing millions of flows with zero server setup.
"""

import duckdb
import os
import threading
import logging
from typing import List, Dict, Any, Optional
from storage.engine import BaseStorageEngine

logger = logging.getLogger("AegisFlow.Storage.DuckDB")

class DuckDBStorageEngine(BaseStorageEngine):
    def __init__(self, db_path: str = "data/aegisflow.duckdb", threads: int = 4, read_only: bool = False):
        self.db_path = db_path
        self.read_only = read_only
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.lock = threading.Lock()
        
        # Connect to DuckDB database
        self.con = duckdb.connect(database=self.db_path, read_only=read_only)
        self.con.execute(f"PRAGMA threads={threads};")
        self.con.execute("PRAGMA memory_limit='4GB';")
        if not read_only:
            self._init_schema()

    def _init_schema(self):
        with self.lock:
            # 1. Raw Flows Columnar Table
            self.con.execute("""
            CREATE TABLE IF NOT EXISTS raw_flows (
                timestamp TIMESTAMP,
                device_id VARCHAR,
                device_name VARCHAR,
                vendor VARCHAR,
                site VARCHAR,
                in_ifindex INTEGER,
                in_if_name VARCHAR,
                out_ifindex INTEGER,
                out_if_name VARCHAR,
                src_ip VARCHAR,
                dst_ip VARCHAR,
                next_hop VARCHAR,
                src_port INTEGER,
                dst_port INTEGER,
                protocol INTEGER,
                tcp_flags INTEGER,
                tos INTEGER,
                dscp INTEGER,
                dscp_name VARCHAR,
                qos_class VARCHAR,
                src_as BIGINT,
                src_as_name VARCHAR,
                dst_as BIGINT,
                dst_as_name VARCHAR,
                dst_as_category VARCHAR,
                src_country VARCHAR,
                src_city VARCHAR,
                src_cloud VARCHAR,
                src_lat DOUBLE,
                src_lon DOUBLE,
                dst_country VARCHAR,
                dst_city VARCHAR,
                dst_cloud VARCHAR,
                dst_lat DOUBLE,
                dst_lon DOUBLE,
                application VARCHAR,
                app_category VARCHAR,
                flow_direction VARCHAR,
                upstream_provider VARCHAR,
                service_name VARCHAR,
                packets BIGINT,
                bytes BIGINT,
                duration_ms INTEGER,
                sampling_rate INTEGER
            );
            """)

            # 2. 5-Minute Rollup Table (for Capacity Planning & 95th Percentile)
            self.con.execute("""
            CREATE TABLE IF NOT EXISTS flows_5m_rollup (
                bucket_5m TIMESTAMP,
                device_id VARCHAR,
                in_ifindex INTEGER,
                out_ifindex INTEGER,
                src_as BIGINT,
                dst_as BIGINT,
                application VARCHAR,
                dscp_name VARCHAR,
                flow_direction VARCHAR,
                total_bytes BIGINT,
                total_packets BIGINT,
                flow_count BIGINT
            );
            """)

            # 3. Security & Anomaly Alerts Table
            self.con.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP,
                category VARCHAR,
                severity VARCHAR,
                title VARCHAR,
                description VARCHAR,
                target_ip VARCHAR,
                source_ip VARCHAR,
                metric_value DOUBLE,
                threshold DOUBLE,
                status VARCHAR,
                mitigation_status VARCHAR
            );
            """)

            # Create analytical indexes on high-cardinality search fields
            self.con.execute("CREATE INDEX IF NOT EXISTS idx_flows_ts ON raw_flows(timestamp);")
            self.con.execute("CREATE INDEX IF NOT EXISTS idx_flows_dev ON raw_flows(device_id);")
            self.con.execute("CREATE INDEX IF NOT EXISTS idx_flows_src_dst ON raw_flows(src_ip, dst_ip);")
            self.con.execute("CREATE INDEX IF NOT EXISTS idx_flows_as ON raw_flows(src_as, dst_as);")

            # Schema migration for Upstream Provider & Service
            try:
                self.con.execute("ALTER TABLE raw_flows ADD COLUMN IF NOT EXISTS upstream_provider VARCHAR;")
                self.con.execute("ALTER TABLE raw_flows ADD COLUMN IF NOT EXISTS service_name VARCHAR;")
            except Exception:
                pass

    def insert_flows(self, records: List[Dict[str, Any]]) -> int:
        if not records:
            return 0

        # Build columnar arrays for ultra-fast vectorized bulk ingestion
        cols = [
            "timestamp", "device_id", "device_name", "vendor", "site",
            "in_ifindex", "in_if_name", "out_ifindex", "out_if_name",
            "src_ip", "dst_ip", "next_hop",
            "src_port", "dst_port", "protocol", "tcp_flags", "tos", "dscp", "dscp_name", "qos_class",
            "src_as", "src_as_name", "dst_as", "dst_as_name", "dst_as_category",
            "src_country", "src_city", "src_cloud", "src_lat", "src_lon",
            "dst_country", "dst_city", "dst_cloud", "dst_lat", "dst_lon",
            "application", "app_category", "flow_direction",
            "upstream_provider", "service_name",
            "packets", "bytes", "duration_ms", "sampling_rate"
        ]

        import datetime
        rows = []
        for r in records:
            ts = r.get("timestamp")
            if isinstance(ts, (int, float)):
                ts = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
            elif ts is None:
                ts = datetime.datetime.now(datetime.timezone.utc)

            rows.append((
                ts,
                r.get("device_id", "unknown"),
                r.get("device_name", ""),
                r.get("vendor", "Generic"),
                r.get("site", "Default"),
                r.get("in_ifindex", 0),
                r.get("in_if_name", ""),
                r.get("out_ifindex", 0),
                r.get("out_if_name", ""),
                r.get("src_ip", "0.0.0.0"),
                r.get("dst_ip", "0.0.0.0"),
                r.get("next_hop", "0.0.0.0"),
                r.get("src_port", 0),
                r.get("dst_port", 0),
                r.get("protocol", 0),
                r.get("tcp_flags", 0),
                r.get("tos", 0),
                r.get("dscp", 0),
                r.get("dscp_name", "CS0"),
                r.get("qos_class", "Normal"),
                r.get("src_as", 0),
                r.get("src_as_name", ""),
                r.get("dst_as", 0),
                r.get("dst_as_name", ""),
                r.get("dst_as_category", ""),
                r.get("src_country", "UN"),
                r.get("src_city", "Unknown"),
                r.get("src_cloud", "Internet"),
                float(r.get("src_lat", 0.0)),
                float(r.get("src_lon", 0.0)),
                r.get("dst_country", "UN"),
                r.get("dst_city", "Unknown"),
                r.get("dst_cloud", "Internet"),
                float(r.get("dst_lat", 0.0)),
                float(r.get("dst_lon", 0.0)),
                r.get("application", "Unknown"),
                r.get("app_category", "General"),
                r.get("flow_direction", "External"),
                r.get("upstream_provider", "Default Transit"),
                r.get("service_name", "IPT"),
                int(r.get("packets", 0)),
                int(r.get("bytes", 0)),
                int(r.get("duration_ms", 0)),
                int(r.get("sampling_rate", 1))
            ))

        with self.lock:
            try:
                placeholders = ", ".join(["?"] * len(cols))
                col_names = ", ".join(cols)
                self.con.executemany(f"INSERT INTO raw_flows ({col_names}) VALUES ({placeholders})", rows)
                return len(rows)
            except Exception as e:
                logger.error(f"Error bulk inserting into DuckDB: {e}")
                return 0

    def query(self, sql: str, params: Optional[dict] = None) -> List[Dict[str, Any]]:
        with self.lock:
            try:
                if params:
                    cursor = self.con.execute(sql, params)
                else:
                    cursor = self.con.execute(sql)
                cols = [desc[0] for desc in cursor.description]
                rows = cursor.fetchall()
                return [dict(zip(cols, row)) for row in rows]
            except Exception as e:
                logger.error(f"Query execution error: {e} | SQL: {sql[:200]}")
                return []

    def insert_alert(self, alert: Dict[str, Any]):
        with self.lock:
            try:
                import datetime
                ts = alert.get("timestamp")
                if isinstance(ts, (int, float)):
                    ts = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
                self.con.execute("""
                INSERT OR REPLACE INTO alerts 
                (alert_id, timestamp, category, severity, title, description, target_ip, source_ip, metric_value, threshold, status, mitigation_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert["alert_id"], ts, alert["category"], alert["severity"],
                    alert["title"], alert["description"], alert.get("target_ip", ""),
                    alert.get("source_ip", ""), alert.get("metric_value", 0.0),
                    alert.get("threshold", 0.0), alert.get("status", "ACTIVE"),
                    alert.get("mitigation_status", "PENDING")
                ))
            except Exception as e:
                logger.error(f"Failed to insert alert: {e}")

    def close(self):
        with self.lock:
            try:
                self.con.close()
            except Exception:
                pass
