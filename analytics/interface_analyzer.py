"""
Interface-Level Utilization & Site-to-Site WAN Analytics for AegisFlow
"""

from typing import List, Dict, Any
from storage.engine import BaseStorageEngine
from enrichment.snmp_cache import snmp_cache

class InterfaceAnalyzer:
    def __init__(self, storage: BaseStorageEngine):
        self.storage = storage

    def get_interface_utilization(self, limit: int = 50, minutes: int = 15) -> List[Dict[str, Any]]:
        """
        Calculates interface-level (IN / OUT) utilization against provisioned bandwidth capacity.
        """
        duration_sec = max(1, minutes * 60)
        sql = f"""
        SELECT 
            device_id,
            device_name,
            site,
            vendor,
            in_ifindex,
            in_if_name,
            SUM(bytes) AS in_bytes,
            SUM(packets) AS in_packets
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
        GROUP BY device_id, device_name, site, vendor, in_ifindex, in_if_name
        ORDER BY in_bytes DESC
        LIMIT {limit};
        """
        rows = self.storage.query(sql)
        results = []

        for r in rows:
            dev_id = r["device_id"]
            if_idx = r["in_ifindex"]
            dev = snmp_cache.devices.get(dev_id, {})
            dev_ip = dev.get("ip", "0.0.0.0")
            if_meta = snmp_cache.get_interface(dev_ip, if_idx)
            
            speed_bps = if_meta.get("speed_bps", 100_000_000_000)
            in_bytes = r.get("in_bytes", 0)
            in_bps = (in_bytes * 8) / duration_sec
            in_mbps = in_bps / 1_000_000
            utilization_pct = min(100.0, (in_bps / speed_bps) * 100.0)

            results.append({
                "device_id": dev_id,
                "device_name": r["device_name"],
                "site": r["site"],
                "vendor": r["vendor"],
                "if_index": if_idx,
                "if_name": if_meta.get("name", r["in_if_name"]),
                "if_alias": if_meta.get("alias", ""),
                "if_type": if_meta.get("type", "General"),
                "speed_readable": if_meta.get("speed_readable", "100GE"),
                "speed_bps": speed_bps,
                "current_in_mbps": round(in_mbps, 2),
                "utilization_pct": round(utilization_pct, 2),
                "status": "SATURATED" if utilization_pct >= 80.0 else ("WARNING" if utilization_pct >= 65.0 else "HEALTHY")
            })

        return sorted(results, key=lambda x: x["utilization_pct"], reverse=True)

    def get_site_to_site_traffic(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Traffic matrix between physical data centers, branches, and cloud locations."""
        sql = f"""
        SELECT 
            site AS src_site,
            dst_cloud AS dst_site_or_cloud,
            SUM(bytes) AS bytes,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
        GROUP BY site, dst_cloud
        ORDER BY bytes DESC
        LIMIT 25;
        """
        return self.storage.query(sql)

    def get_geographic_flow_map(self, minutes: int = 30) -> List[Dict[str, Any]]:
        """Returns geographic flow links between Source Lat/Lon and Dest Lat/Lon for world map visualization."""
        sql = f"""
        SELECT 
            src_country,
            src_city,
            src_lat,
            src_lon,
            dst_country,
            dst_city,
            dst_lat,
            dst_lon,
            SUM(bytes) AS bytes,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
          AND src_lat != 0 AND dst_lat != 0
        GROUP BY src_country, src_city, src_lat, src_lon, dst_country, dst_city, dst_lat, dst_lon
        ORDER BY bytes DESC
        LIMIT 50;
        """
        return self.storage.query(sql)
