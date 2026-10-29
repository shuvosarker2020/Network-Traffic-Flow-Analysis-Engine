"""
Real-Time DDoS Detection & BGP Flowspec Mitigation Engine for AegisFlow
Detects Volumetric attacks, SYN floods, UDP amplification, and ICMP floods.
"""

import time
import uuid
from typing import List, Dict, Any
from storage.engine import BaseStorageEngine

class DDoSDetector:
    def __init__(self, storage: BaseStorageEngine, config: dict):
        self.storage = storage
        self.cfg = config.get("security", {}).get("ddos", {})
        self.volumetric_thresh_mbps = self.cfg.get("volumetric_threshold_mbps", 500)
        self.syn_ratio_thresh = self.cfg.get("syn_flood_ratio_threshold", 0.80)
        self.udp_flood_pps_thresh = self.cfg.get("udp_flood_pps_threshold", 50000)
        self.dns_amp_thresh_pps = self.cfg.get("dns_amplification_threshold_pps", 20000)
        self.icmp_flood_thresh_pps = self.cfg.get("icmp_flood_pps_threshold", 15000)

    def scan_for_attacks(self, window_minutes: int = 5) -> List[Dict[str, Any]]:
        attacks = []
        duration_sec = max(1, window_minutes * 60)

        # 1. Volumetric Target IP Spike
        sql_volumetric = f"""
        SELECT 
            dst_ip,
            dst_country,
            dst_as_name,
            SUM(bytes) AS bytes,
            SUM(packets) AS packets,
            ROUND(SUM(bytes) * 8.0 / ({duration_sec} * 1000000), 2) AS mbps,
            ROUND(SUM(packets) * 1.0 / {duration_sec}, 0) AS pps
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{window_minutes} MINUTE'
        GROUP BY dst_ip, dst_country, dst_as_name
        HAVING mbps > {self.volumetric_thresh_mbps}
        ORDER BY mbps DESC;
        """
        vol_targets = self.storage.query(sql_volumetric)
        for t in vol_targets:
            target_ip = t["dst_ip"]
            mbps = t["mbps"]
            pps = t["pps"]
            attacks.append(self._create_attack_record(
                attack_type="Volumetric DDoS Flood",
                severity="CRITICAL",
                target_ip=target_ip,
                metric_value=mbps,
                threshold=self.volumetric_thresh_mbps,
                unit="Mbps",
                description=f"Inbound traffic toward {target_ip} exceeded threshold: {mbps} Mbps ({int(pps)} pps)."
            ))

        # 2. TCP SYN Flood Detection
        # TCP Flags: SYN=2, ACK=16. SYN-only packets have (tcp_flags & 2) != 0 and (tcp_flags & 16) == 0
        sql_syn = f"""
        SELECT 
            dst_ip,
            SUM(CASE WHEN (tcp_flags & 2) != 0 AND (tcp_flags & 16) == 0 THEN packets ELSE 0 END) AS syn_packets,
            SUM(packets) AS total_packets,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{window_minutes} MINUTE'
          AND protocol = 6
        GROUP BY dst_ip
        HAVING total_packets > 10000;
        """
        syn_rows = self.storage.query(sql_syn)
        for r in syn_rows:
            tot = r["total_packets"]
            syn = r["syn_packets"]
            ratio = (syn / tot) if tot > 0 else 0
            if ratio >= self.syn_ratio_thresh:
                attacks.append(self._create_attack_record(
                    attack_type="TCP SYN Flood Attack",
                    severity="CRITICAL",
                    target_ip=r["dst_ip"],
                    metric_value=round(ratio * 100, 1),
                    threshold=self.syn_ratio_thresh * 100,
                    unit="%",
                    description=f"SYN Flood against {r['dst_ip']}: {round(ratio * 100, 1)}% of TCP packets are naked SYN without ACK ({syn:,} SYN packets)."
                ))

        # 3. DNS / NTP / Memcached Amplification Floods
        sql_udp_amp = f"""
        SELECT 
            dst_ip,
            src_port,
            application,
            SUM(packets) AS packets,
            SUM(bytes) AS bytes,
            ROUND(SUM(packets) * 1.0 / {duration_sec}, 0) AS pps
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{window_minutes} MINUTE'
          AND protocol = 17
          AND src_port IN (53, 123, 11211, 1900)
        GROUP BY dst_ip, src_port, application
        HAVING pps > {self.dns_amp_thresh_pps};
        """
        amp_rows = self.storage.query(sql_udp_amp)
        for r in amp_rows:
            attacks.append(self._create_attack_record(
                attack_type=f"UDP Reflection/Amplification ({r['application']})",
                severity="CRITICAL",
                target_ip=r["dst_ip"],
                metric_value=r["pps"],
                threshold=self.dns_amp_thresh_pps,
                unit="PPS",
                description=f"UDP reflection from port {r['src_port']} ({r['application']}) blasting {r['dst_ip']} at {int(r['pps']):,} PPS."
            ))

        # 4. ICMP Ping Flood
        sql_icmp = f"""
        SELECT 
            dst_ip,
            SUM(packets) AS packets,
            ROUND(SUM(packets) * 1.0 / {duration_sec}, 0) AS pps
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{window_minutes} MINUTE'
          AND protocol = 1
        GROUP BY dst_ip
        HAVING pps > {self.icmp_flood_thresh_pps};
        """
        icmp_rows = self.storage.query(sql_icmp)
        for r in icmp_rows:
            attacks.append(self._create_attack_record(
                attack_type="ICMP Ping Flood Attack",
                severity="MAJOR",
                target_ip=r["dst_ip"],
                metric_value=r["pps"],
                threshold=self.icmp_flood_thresh_pps,
                unit="PPS",
                description=f"ICMP flood targeting {r['dst_ip']} at {int(r['pps']):,} PPS."
            ))

        # Record attacks in the database
        for att in attacks:
            if hasattr(self.storage, "insert_alert"):
                self.storage.insert_alert(att)

        return attacks

    def _create_attack_record(self, attack_type: str, severity: str, target_ip: str, metric_value: float, threshold: float, unit: str, description: str) -> Dict[str, Any]:
        alert_id = f"ddos-{uuid.uuid4().hex[:8]}"
        bgp_flowspec = self.generate_bgp_flowspec(target_ip, attack_type)
        return {
            "alert_id": alert_id,
            "timestamp": int(time.time()),
            "category": "DDoS",
            "attack_type": attack_type,
            "severity": severity,
            "title": f"{severity}: {attack_type} -> {target_ip}",
            "description": description,
            "target_ip": target_ip,
            "metric_value": metric_value,
            "threshold": threshold,
            "unit": unit,
            "status": "ACTIVE",
            "mitigation_status": "READY_FOR_DEPLOYMENT",
            "bgp_flowspec_rule": bgp_flowspec
        }

    def generate_bgp_flowspec(self, target_ip: str, attack_type: str) -> str:
        """
        Generates industry standard RFC 5575 / RFC 8955 BGP Flowspec mitigation rule syntax.
        """
        if "SYN" in attack_type:
            return f"flow-spec route {{\n  match {{\n    destination {target_ip}/32;\n    protocol tcp;\n    tcp-flags (syn & !ack);\n  }}\n  then rate-limit 0;\n}}"
        elif "DNS" in attack_type or "UDP" in attack_type:
            return f"flow-spec route {{\n  match {{\n    destination {target_ip}/32;\n    protocol udp;\n    port [53 123 11211];\n  }}\n  then rate-limit 0;\n}}"
        elif "ICMP" in attack_type:
            return f"flow-spec route {{\n  match {{\n    destination {target_ip}/32;\n    protocol icmp;\n  }}\n  then rate-limit 0;\n}}"
        else:
            return f"flow-spec route {{\n  match {{\n    destination {target_ip}/32;\n  }}\n  then community 'no-export'; rate-limit 1000000;\n}}"
