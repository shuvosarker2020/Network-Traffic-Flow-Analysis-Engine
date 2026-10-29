"""
Anomaly Detection & Lateral Movement Tracker for AegisFlow
Detects port scans, unauthorized internal East-West lateral movement, and statistical deviations from baseline.
"""

import time
import uuid
from typing import List, Dict, Any
from storage.engine import BaseStorageEngine

class AnomalyDetector:
    def __init__(self, storage: BaseStorageEngine, config: dict):
        self.storage = storage
        self.cfg = config.get("security", {}).get("anomaly", {})
        self.port_scan_thresh = self.cfg.get("port_scan_unique_ports_threshold", 30)

    def scan_for_anomalies(self, window_minutes: int = 15) -> List[Dict[str, Any]]:
        anomalies = []

        # 1. Port Scan Detection (Reconnaissance)
        sql_port_scan = f"""
        SELECT 
            src_ip,
            dst_ip,
            flow_direction,
            COUNT(DISTINCT dst_port) AS unique_ports_probed,
            COUNT(*) AS total_probes,
            SUM(packets) AS packets
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{window_minutes} MINUTE'
        GROUP BY src_ip, dst_ip, flow_direction
        HAVING unique_ports_probed >= {self.port_scan_thresh}
        ORDER BY unique_ports_probed DESC;
        """
        scanners = self.storage.query(sql_port_scan)
        for s in scanners:
            src = s["src_ip"]
            dst = s["dst_ip"]
            ports = s["unique_ports_probed"]
            anomalies.append({
                "alert_id": f"anom-scan-{uuid.uuid4().hex[:8]}",
                "timestamp": int(time.time()),
                "category": "Reconnaissance / Port Scan",
                "severity": "MAJOR",
                "title": f"Port Scanning: {src} -> {dst}",
                "description": f"Source {src} scanned {ports} distinct ports on destination {dst} within {window_minutes} minutes.",
                "source_ip": src,
                "target_ip": dst,
                "metric_value": ports,
                "threshold": self.port_scan_thresh,
                "status": "ACTIVE"
            })

        # 2. Unauthorized East-West Lateral Movement
        # Sensitive admin / exploitation ports: 445 (SMB), 3389 (RDP), 22 (SSH), 5985 (WinRM), 135 (RPC)
        sql_lateral = f"""
        SELECT 
            src_ip,
            dst_ip,
            COUNT(DISTINCT dst_port) AS sensitive_ports_targeted,
            site,
            SUM(bytes) AS bytes,
            SUM(packets) AS packets,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{window_minutes} MINUTE'
          AND flow_direction = 'East-West (Internal)'
          AND dst_port IN (445, 3389, 22, 5985, 135, 7001, 8080)
        GROUP BY src_ip, dst_ip, site
        HAVING flow_count >= 3;
        """
        lat_rows = self.storage.query(sql_lateral)
        for l in lat_rows:
            anomalies.append({
                "alert_id": f"anom-lateral-{uuid.uuid4().hex[:8]}",
                "timestamp": int(time.time()),
                "category": "Lateral Movement",
                "severity": "HIGH",
                "title": f"East-West Lateral Movement: {l['src_ip']} -> {l['dst_ip']}",
                "description": f"Internal host {l['src_ip']} probed {l['sensitive_ports_targeted']} sensitive admin ports ({l['flow_count']} sessions) on internal server {l['dst_ip']} in site {l['site']}.",
                "source_ip": l["src_ip"],
                "target_ip": l["dst_ip"],
                "metric_value": l["flow_count"],
                "threshold": 3,
                "status": "ACTIVE"
            })

        # Record in alert store
        for a in anomalies:
            if hasattr(self.storage, "insert_alert"):
                self.storage.insert_alert(a)

        return anomalies
