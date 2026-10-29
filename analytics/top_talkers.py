"""
Top Talkers, Conversations & Application Analytics for AegisFlow
"""

from typing import List, Dict, Any, Optional
from storage.engine import BaseStorageEngine

class TopTalkersAnalyzer:
    def __init__(self, storage: BaseStorageEngine):
        self.storage = storage

    def get_overview_kpis(self, minutes: int = 60) -> Dict[str, Any]:
        """Calculates total bandwidth, packets, active flows, and device counts."""
        sql = f"""
        SELECT 
            COALESCE(SUM(bytes), 0) AS total_bytes,
            COALESCE(SUM(packets), 0) AS total_packets,
            COUNT(*) AS total_flows,
            COUNT(DISTINCT device_id) AS active_devices,
            COUNT(DISTINCT src_ip) AS unique_sources,
            COUNT(DISTINCT dst_ip) AS unique_destinations
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE';
        """
        rows = self.storage.query(sql)
        res = rows[0] if rows else {}
        total_bytes = res.get("total_bytes", 0)
        duration_sec = max(1, minutes * 60)
        avg_bps = (total_bytes * 8) / duration_sec
        avg_pps = res.get("total_packets", 0) / duration_sec

        return {
            "time_window_minutes": minutes,
            "total_bytes": total_bytes,
            "total_packets": res.get("total_packets", 0),
            "total_flows": res.get("total_flows", 0),
            "avg_mbps": round(avg_bps / 1_000_000, 2),
            "avg_gbps": round(avg_bps / 1_000_000_000, 3),
            "avg_pps": int(avg_pps),
            "active_devices": res.get("active_devices", 0),
            "unique_sources": res.get("unique_sources", 0),
            "unique_destinations": res.get("unique_destinations", 0)
        }

    def get_top_source_ips(self, limit: int = 10, minutes: int = 60) -> List[Dict[str, Any]]:
        sql = f"""
        SELECT 
            src_ip, 
            src_country, 
            src_as_name, 
            src_cloud,
            SUM(bytes) AS bytes, 
            SUM(packets) AS packets,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
        GROUP BY src_ip, src_country, src_as_name, src_cloud
        ORDER BY bytes DESC
        LIMIT {limit};
        """
        return self.storage.query(sql)

    def get_top_destination_ips(self, limit: int = 10, minutes: int = 60) -> List[Dict[str, Any]]:
        sql = f"""
        SELECT 
            dst_ip, 
            dst_country, 
            dst_as_name, 
            dst_cloud,
            SUM(bytes) AS bytes, 
            SUM(packets) AS packets,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
        GROUP BY dst_ip, dst_country, dst_as_name, dst_cloud
        ORDER BY bytes DESC
        LIMIT {limit};
        """
        return self.storage.query(sql)

    def get_top_conversations(self, limit: int = 15, minutes: int = 60) -> List[Dict[str, Any]]:
        """Source to Destination conversation matrix."""
        sql = f"""
        SELECT 
            src_ip,
            src_country,
            dst_ip,
            dst_country,
            application,
            protocol,
            dst_port,
            flow_direction,
            SUM(bytes) AS bytes,
            SUM(packets) AS packets,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
        GROUP BY src_ip, src_country, dst_ip, dst_country, application, protocol, dst_port, flow_direction
        ORDER BY bytes DESC
        LIMIT {limit};
        """
        return self.storage.query(sql)

    def get_top_applications(self, limit: int = 10, minutes: int = 60) -> List[Dict[str, Any]]:
        sql = f"""
        SELECT 
            application,
            app_category,
            SUM(bytes) AS bytes,
            SUM(packets) AS packets,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
        GROUP BY application, app_category
        ORDER BY bytes DESC
        LIMIT {limit};
        """
        return self.storage.query(sql)

    def get_throughput_timeseries(self, minutes: int = 60, interval_sec: int = 60) -> List[Dict[str, Any]]:
        """Time-series throughput for dashboard graphs."""
        sql = f"""
        SELECT 
            time_bucket(INTERVAL '{interval_sec} SECOND', timestamp) AS time_point,
            SUM(bytes) * 8.0 / ({interval_sec} * 1000000.0) AS mbps,
            SUM(packets) * 1.0 / {interval_sec} AS pps,
            COUNT(*) AS flow_rate
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
        GROUP BY time_point
        ORDER BY time_point ASC;
        """
        rows = self.storage.query(sql)
        # Convert timestamp to ISO format string
        for r in rows:
            if "time_point" in r and hasattr(r["time_point"], "isoformat"):
                r["time_point"] = r["time_point"].isoformat()
        return rows
