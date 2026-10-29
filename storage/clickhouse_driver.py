"""
ClickHouse Enterprise Columnar Driver for AegisFlow
Connects to distributed ClickHouse clusters for petabyte-scale multi-month network telemetry storage.
"""

import logging
from typing import List, Dict, Any, Optional
from storage.engine import BaseStorageEngine

logger = logging.getLogger("AegisFlow.Storage.ClickHouse")

class ClickHouseStorageEngine(BaseStorageEngine):
    def __init__(self, host: str = "localhost", port: int = 8123, user: str = "default", password: str = "", database: str = "aegisflow"):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.client = None
        self._connect()

    def _connect(self):
        try:
            import clickhouse_connect
            self.client = clickhouse_connect.get_client(
                host=self.host,
                port=self.port,
                username=self.user,
                password=self.password,
                database=self.database
            )
            logger.info(f"Connected to ClickHouse at {self.host}:{self.port}/{self.database}")
        except Exception as e:
            logger.warning(f"Could not connect to ClickHouse ({e}). Storage will operate in standby mode.")
            self.client = None

    def insert_flows(self, records: List[Dict[str, Any]]) -> int:
        if not self.client or not records:
            return 0
        try:
            data = []
            for r in records:
                data.append([
                    r.get("timestamp"), r.get("device_id"), r.get("device_name"), r.get("vendor"), r.get("site"),
                    r.get("in_ifindex"), r.get("in_if_name"), r.get("out_ifindex"), r.get("out_if_name"),
                    r.get("src_ip"), r.get("dst_ip"), r.get("next_hop"),
                    r.get("src_port"), r.get("dst_port"), r.get("protocol"), r.get("tcp_flags"),
                    r.get("tos"), r.get("dscp"), r.get("dscp_name"), r.get("qos_class"),
                    r.get("src_as"), r.get("src_as_name"), r.get("dst_as"), r.get("dst_as_name"), r.get("dst_as_category"),
                    r.get("src_country"), r.get("src_city"), r.get("src_cloud"), r.get("src_lat", 0.0), r.get("src_lon", 0.0),
                    r.get("dst_country"), r.get("dst_city"), r.get("dst_cloud"), r.get("dst_lat", 0.0), r.get("dst_lon", 0.0),
                    r.get("application"), r.get("app_category"), r.get("flow_direction"),
                    r.get("packets"), r.get("bytes"), r.get("duration_ms"), r.get("sampling_rate")
                ])
            self.client.insert("raw_flows", data)
            return len(records)
        except Exception as e:
            logger.error(f"ClickHouse batch insert failed: {e}")
            return 0

    def query(self, sql: str, params: Optional[dict] = None) -> List[Dict[str, Any]]:
        if not self.client:
            return []
        try:
            res = self.client.query(sql, parameters=params)
            cols = res.column_names
            return [dict(zip(cols, row)) for row in res.result_rows]
        except Exception as e:
            logger.error(f"ClickHouse query error: {e}")
            return []

    def close(self):
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
