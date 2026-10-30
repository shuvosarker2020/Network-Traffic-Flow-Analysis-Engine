"""
Advanced Multi-Condition Traffic Pattern Engine for AegisFlow
Allows complex multi-attribute filtering across:
- ASN to ASN (src_as to dst_as)
- IP addresses & Subnet Prefixes (CIDR)
- Ingress/Egress Interfaces & Devices
- Countries, Applications, DSCP, and Flow Directions
"""

import ipaddress
import time
from typing import Dict, Any, List, Optional
from storage.engine import BaseStorageEngine

def cidr_to_int_range(cidr_str: str) -> Optional[tuple[int, int]]:
    """Converts a CIDR like '10.0.0.0/16' or single IP into (start_int, end_int)."""
    try:
        if "/" not in cidr_str:
            net = ipaddress.ip_network(f"{cidr_str.strip()}/32", strict=False)
        else:
            net = ipaddress.ip_network(cidr_str.strip(), strict=False)
        return int(net.network_address), int(net.broadcast_address)
    except Exception:
        return None

def ip_to_int_sql(col_name: str) -> str:
    """SQL expression in DuckDB converting an IPv4 string to a 32-bit integer."""
    return (
        f"(split_part({col_name}, '.', 1)::BIGINT * 16777216 + "
        f"split_part({col_name}, '.', 2)::BIGINT * 65536 + "
        f"split_part({col_name}, '.', 3)::BIGINT * 256 + "
        f"split_part({col_name}, '.', 4)::BIGINT)"
    )

class TrafficPatternEngine:
    def __init__(self, storage: BaseStorageEngine):
        self.storage = storage

    def build_where_clause(self, criteria: Dict[str, Any], minutes: int = 60) -> str:
        clauses = [f"timestamp >= NOW() - INTERVAL '{minutes} MINUTE'"]

        # 1. ASN Filters (Source, Destination, or ASN-to-ASN)
        if criteria.get("src_as"):
            clauses.append(f"src_as = {int(criteria['src_as'])}")
        if criteria.get("dst_as"):
            clauses.append(f"dst_as = {int(criteria['dst_as'])}")

        # 2. Specific IP Filters
        if criteria.get("src_ip"):
            sip = criteria["src_ip"].strip()
            if "/" in sip:
                rng = cidr_to_int_range(sip)
                if rng:
                    clauses.append(f"{ip_to_int_sql('src_ip')} BETWEEN {rng[0]} AND {rng[1]}")
            else:
                clauses.append(f"src_ip LIKE '{sip}%'")

        if criteria.get("dst_ip"):
            dip = criteria["dst_ip"].strip()
            if "/" in dip:
                rng = cidr_to_int_range(dip)
                if rng:
                    clauses.append(f"{ip_to_int_sql('dst_ip')} BETWEEN {rng[0]} AND {rng[1]}")
            else:
                clauses.append(f"dst_ip LIKE '{dip}%'")

        # 3. CIDR Prefix Filters (Source Prefix, Destination Prefix)
        if criteria.get("src_prefix"):
            rng = cidr_to_int_range(criteria["src_prefix"])
            if rng:
                clauses.append(f"{ip_to_int_sql('src_ip')} BETWEEN {rng[0]} AND {rng[1]}")

        if criteria.get("dst_prefix"):
            rng = cidr_to_int_range(criteria["dst_prefix"])
            if rng:
                clauses.append(f"{ip_to_int_sql('dst_ip')} BETWEEN {rng[0]} AND {rng[1]}")

        # 4. Device and Interface Filters
        if criteria.get("device_id"):
            clauses.append(f"device_id = '{criteria['device_id'].strip()}'")
        if criteria.get("device_name"):
            clauses.append(f"device_name LIKE '%{criteria['device_name'].strip()}%'")
        if criteria.get("in_if_name"):
            clauses.append(f"in_if_name = '{criteria['in_if_name'].strip()}'")
        if criteria.get("out_if_name"):
            clauses.append(f"out_if_name = '{criteria['out_if_name'].strip()}'")

        # 5. Country Filters
        if criteria.get("src_country"):
            clauses.append(f"src_country = '{criteria['src_country'].strip().upper()}'")
        if criteria.get("dst_country"):
            clauses.append(f"dst_country = '{criteria['dst_country'].strip().upper()}'")

        # 6. Application, Protocol, DSCP
        if criteria.get("application"):
            clauses.append(f"application = '{criteria['application'].strip()}'")
        if criteria.get("protocol") is not None and str(criteria["protocol"]).isdigit():
            clauses.append(f"protocol = {int(criteria['protocol'])}")
        if criteria.get("dscp") is not None and str(criteria["dscp"]).isdigit():
            clauses.append(f"dscp = {int(criteria['dscp'])}")
        if criteria.get("flow_direction"):
            clauses.append(f"flow_direction LIKE '%{criteria['flow_direction'].strip()}%'")

        # 7. Upstream Provider & Service Filters (IIG / Transit / Peering / CDN)
        if criteria.get("upstream_provider"):
            clauses.append(f"upstream_provider = '{criteria['upstream_provider'].strip()}'")
        if criteria.get("service_name"):
            clauses.append(f"service_name = '{criteria['service_name'].strip().upper()}'")

        return " AND ".join(clauses)

    def analyze_pattern(self, criteria: Dict[str, Any], minutes: int = 60) -> Dict[str, Any]:
        """
        Executes multi-condition query and returns:
        - Pattern summary (total bytes, packets, wire-rate mbps, pps)
        - Wire-rate time-series trend (for plotting traffic pattern)
        - Top talkers matching this pattern
        - Top ASN-to-ASN flows matching this pattern
        - Top interfaces matching this pattern
        - Top countries and applications
        """
        where_clause = self.build_where_clause(criteria, minutes=minutes)
        duration_sec = max(1, minutes * 60)

        # 1. Overall Summary Metrics
        sql_summary = f"""
        SELECT 
            COALESCE(SUM(bytes), 0) AS total_bytes,
            COALESCE(SUM(packets), 0) AS total_packets,
            COUNT(*) AS flow_count,
            COUNT(DISTINCT src_ip) AS unique_sources,
            COUNT(DISTINCT dst_ip) AS unique_destinations,
            COUNT(DISTINCT device_id) AS matched_devices,
            ROUND(COALESCE(SUM(bytes), 0) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS avg_mbps,
            ROUND(COALESCE(SUM(packets), 0) * 1.0 / ({minutes} * 60.0), 0) AS avg_pps
        FROM raw_flows
        WHERE {where_clause};
        """
        summary_rows = self.storage.query(sql_summary)
        summary = summary_rows[0] if summary_rows else {}

        # 2. Time-Series Traffic Pattern (Bucket resolution: 60s for <= 120m, 300s for > 120m)
        interval_sec = 60 if minutes <= 120 else 300
        sql_timeseries = f"""
        SELECT 
            time_bucket(INTERVAL '{interval_sec} SECOND', timestamp) AS time_point,
            ROUND(SUM(bytes) * 8.0 / ({interval_sec} * 1000000.0), 2) AS mbps,
            ROUND(SUM(packets) * 1.0 / {interval_sec}, 0) AS pps,
            COUNT(*) AS flows
        FROM raw_flows
        WHERE {where_clause}
        GROUP BY time_point
        ORDER BY time_point ASC;
        """
        timeseries = self.storage.query(sql_timeseries)
        for t in timeseries:
            if "time_point" in t and hasattr(t["time_point"], "isoformat"):
                t["time_point"] = t["time_point"].isoformat()

        # 3. Top ASN-to-ASN Conversations in this pattern
        sql_asns = f"""
        SELECT 
            src_as, src_as_name, dst_as, dst_as_name, dst_as_category,
            SUM(bytes) AS bytes,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE {where_clause}
        GROUP BY src_as, src_as_name, dst_as, dst_as_name, dst_as_category
        ORDER BY bytes DESC
        LIMIT 10;
        """
        top_asns = self.storage.query(sql_asns)

        # 4. Top IP Talker Conversations in this pattern
        sql_convs = f"""
        SELECT 
            src_ip, src_country, src_as_name,
            dst_ip, dst_country, dst_as_name,
            application, protocol, dst_port, flow_direction,
            SUM(bytes) AS bytes,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            SUM(packets) AS packets
        FROM raw_flows
        WHERE {where_clause}
        GROUP BY src_ip, src_country, src_as_name, dst_ip, dst_country, dst_as_name, application, protocol, dst_port, flow_direction
        ORDER BY bytes DESC
        LIMIT 12;
        """
        top_conversations = self.storage.query(sql_convs)

        # 5. Interface Utilization in this pattern
        sql_interfaces = f"""
        SELECT 
            device_id, device_name, in_if_name, out_if_name, site,
            SUM(bytes) AS bytes,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            SUM(packets) AS packets
        FROM raw_flows
        WHERE {where_clause}
        GROUP BY device_id, device_name, in_if_name, out_if_name, site
        ORDER BY bytes DESC
        LIMIT 10;
        """
        top_interfaces = self.storage.query(sql_interfaces)

        # 6. Country Breakdown
        sql_countries = f"""
        SELECT 
            src_country, dst_country,
            SUM(bytes) AS bytes,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE {where_clause}
        GROUP BY src_country, dst_country
        ORDER BY bytes DESC
        LIMIT 8;
        """
        top_countries = self.storage.query(sql_countries)

        # 7. Application Breakdown
        sql_apps = f"""
        SELECT 
            application, app_category,
            SUM(bytes) AS bytes,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE {where_clause}
        GROUP BY application, app_category
        ORDER BY bytes DESC
        LIMIT 6;
        """
        top_apps = self.storage.query(sql_apps)

        # 8. Upstream Provider & Service Breakdown
        sql_upstreams = f"""
        SELECT 
            COALESCE(upstream_provider, 'Default Transit') AS upstream_provider,
            COALESCE(service_name, 'IPT') AS service_name,
            SUM(bytes) AS bytes,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000000.0), 3) AS gbps,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE {where_clause}
        GROUP BY upstream_provider, service_name
        ORDER BY bytes DESC
        LIMIT 10;
        """
        top_upstreams = self.storage.query(sql_upstreams)

        return {
            "criteria": criteria,
            "time_window_minutes": minutes,
            "summary": summary,
            "timeseries": timeseries,
            "top_asns": top_asns,
            "top_conversations": top_conversations,
            "top_interfaces": top_interfaces,
            "top_countries": top_countries,
            "top_applications": top_apps,
            "top_upstreams": top_upstreams
        }

    def get_multiview_flow_data(self, criteria: Dict[str, Any], minutes: int = 60, preset: str = "CDN_ENTRY_EXIT") -> Dict[str, Any]:
        """
        Generates full multi-view dataset across:
        - Sankey Flow Diagram (exact 5-stage entry/exit view as in Kentik picture or dynamic stages)
        - Ranked Bar Charts (providers, prefixes, interconnects, devices)
        - Interactive Flow Data Table (with search, sort, metrics, CSV export)
        - Time-Series Wave (wire-rate mbps and pps over time)
        - Treemap Matrix (hierarchical rectangular volume packing)
        - Sunburst Flow (radial multi-level concentric rings)
        """
        # If user explicitly requested the CDN Saved Preset, or if criteria is empty and preset is CDN_ENTRY_EXIT:
        if preset == "CDN_ENTRY_EXIT" or (preset != "DYNAMIC" and not any(criteria.values())):
            return self._build_cdn_entry_exit_view(minutes=minutes)
        else:
            return self._build_dynamic_multiview(criteria=criteria, minutes=minutes)

    def _build_cdn_entry_exit_view(self, minutes: int = 60) -> Dict[str, Any]:
        """
        Faithfully produces the Kentik 5-stage 'CDN Traffic Network Entry and Exit' flow:
        Stage 1: CDN Provider (EdgeCast Verizon, Facebook, Apple, Google Youtube, Yahoo, Amazon + AWS, Akamai, Netflix)
        Stage 2: Interconnect (customer, free_pni, transit, paid_pni)
        Stage 3: Ingress PoP (SFO1, NYC1, ORD1)
        Stage 4: Egress PoP (ORD1, SFO1)
        Stage 5: Destination Prefix (12.0.0.0/9, 96.6.0.0/22, 66.100.0.0/15, 205.158.0.0/16, 15.143.96.0/23, 144.224.0.0/16, 141.193.36.0/22, 141.193.37.5/32, 17.0.0.0/21)
        """
        providers = [
            {"name": "Google Youtube", "color": "#ef4444", "mbps": 4680.0, "pps": 390000},
            {"name": "Netflix", "color": "#dc2626", "mbps": 3820.0, "pps": 318000},
            {"name": "Amazon + AWS", "color": "#f59e0b", "mbps": 3410.0, "pps": 284000},
            {"name": "Facebook", "color": "#3b82f6", "mbps": 2950.0, "pps": 245000},
            {"name": "Akamai", "color": "#06b6d4", "mbps": 2240.0, "pps": 186000},
            {"name": "Apple", "color": "#64748b", "mbps": 1680.0, "pps": 140000},
            {"name": "Yahoo", "color": "#a855f7", "mbps": 940.0, "pps": 78000},
            {"name": "EdgeCast Verizon", "color": "#8b5cf6", "mbps": 780.0, "pps": 65000},
        ]

        interconnects = [
            {"name": "free_pni", "color": "#14b8a6"},
            {"name": "paid_pni", "color": "#f97316"},
            {"name": "transit", "color": "#94a3b8"},
            {"name": "customer", "color": "#38bdf8"},
        ]

        ingress_pops = [
            {"name": "SFO1 (Entry)", "display": "SFO1", "color": "#10b981"},
            {"name": "NYC1 (Entry)", "display": "NYC1", "color": "#f59e0b"},
            {"name": "ORD1 (Entry)", "display": "ORD1", "color": "#06b6d4"},
        ]

        egress_pops = [
            {"name": "ORD1 (Exit)", "display": "ORD1", "color": "#0ea5e9"},
            {"name": "SFO1 (Exit)", "display": "SFO1", "color": "#10b981"},
        ]

        prefixes = [
            {"name": "12.0.0.0/9", "color": "#ec4899", "mbps": 4800.0},
            {"name": "96.6.0.0/22", "color": "#8b5cf6", "mbps": 3250.0},
            {"name": "66.100.0.0/15", "color": "#3b82f6", "mbps": 2800.0},
            {"name": "205.158.0.0/16", "color": "#06b6d4", "mbps": 2400.0},
            {"name": "15.143.96.0/23", "color": "#10b981", "mbps": 2150.0},
            {"name": "144.224.0.0/16", "color": "#eab308", "mbps": 1750.0},
            {"name": "141.193.36.0/22", "color": "#f97316", "mbps": 1450.0},
            {"name": "141.193.37.5/32", "color": "#ef4444", "mbps": 1050.0},
            {"name": "17.0.0.0/21", "color": "#6366f1", "mbps": 850.0},
        ]

        nodes = []
        for p in providers:
            nodes.append({"name": p["name"], "display": p["name"], "stage": "CDN Provider", "depth": 0, "itemStyle": {"color": p["color"]}})
        for i in interconnects:
            nodes.append({"name": i["name"], "display": i["name"], "stage": "Interconnect", "depth": 1, "itemStyle": {"color": i["color"]}})
        for ip in ingress_pops:
            nodes.append({"name": ip["name"], "display": ip["display"], "stage": "Ingress PoP", "depth": 2, "itemStyle": {"color": ip["color"]}})
        for ep in egress_pops:
            nodes.append({"name": ep["name"], "display": ep["display"], "stage": "Egress PoP", "depth": 3, "itemStyle": {"color": ep["color"]}})
        for pr in prefixes:
            nodes.append({"name": pr["name"], "display": pr["name"], "stage": "Destination Prefix", "depth": 4, "itemStyle": {"color": pr["color"]}})

        # Stage 1 -> 2
        l1 = [
            {"source": "Google Youtube", "target": "free_pni", "value": 3120.0},
            {"source": "Google Youtube", "target": "paid_pni", "value": 1100.0},
            {"source": "Google Youtube", "target": "transit", "value": 460.0},
            {"source": "Netflix", "target": "free_pni", "value": 2840.0},
            {"source": "Netflix", "target": "transit", "value": 980.0},
            {"source": "Amazon + AWS", "target": "free_pni", "value": 1850.0},
            {"source": "Amazon + AWS", "target": "paid_pni", "value": 1120.0},
            {"source": "Amazon + AWS", "target": "customer", "value": 440.0},
            {"source": "Facebook", "target": "free_pni", "value": 2100.0},
            {"source": "Facebook", "target": "paid_pni", "value": 850.0},
            {"source": "Akamai", "target": "free_pni", "value": 1420.0},
            {"source": "Akamai", "target": "customer", "value": 820.0},
            {"source": "Apple", "target": "paid_pni", "value": 1050.0},
            {"source": "Apple", "target": "transit", "value": 630.0},
            {"source": "Yahoo", "target": "free_pni", "value": 520.0},
            {"source": "Yahoo", "target": "transit", "value": 420.0},
            {"source": "EdgeCast Verizon", "target": "transit", "value": 480.0},
            {"source": "EdgeCast Verizon", "target": "customer", "value": 300.0},
        ]

        # Stage 2 -> 3
        l2 = [
            {"source": "free_pni", "target": "SFO1 (Entry)", "value": 5200.0},
            {"source": "free_pni", "target": "NYC1 (Entry)", "value": 3950.0},
            {"source": "free_pni", "target": "ORD1 (Entry)", "value": 2700.0},

            {"source": "paid_pni", "target": "SFO1 (Entry)", "value": 1800.0},
            {"source": "paid_pni", "target": "NYC1 (Entry)", "value": 1420.0},
            {"source": "paid_pni", "target": "ORD1 (Entry)", "value": 900.0},

            {"source": "transit", "target": "SFO1 (Entry)", "value": 1100.0},
            {"source": "transit", "target": "NYC1 (Entry)", "value": 1070.0},
            {"source": "transit", "target": "ORD1 (Entry)", "value": 800.0},

            {"source": "customer", "target": "SFO1 (Entry)", "value": 700.0},
            {"source": "customer", "target": "NYC1 (Entry)", "value": 460.0},
            {"source": "customer", "target": "ORD1 (Entry)", "value": 400.0},
        ]

        # Stage 3 -> 4
        l3 = [
            {"source": "SFO1 (Entry)", "target": "ORD1 (Exit)", "value": 4600.0},
            {"source": "SFO1 (Entry)", "target": "SFO1 (Exit)", "value": 4200.0},

            {"source": "NYC1 (Entry)", "target": "ORD1 (Exit)", "value": 4100.0},
            {"source": "NYC1 (Entry)", "target": "SFO1 (Exit)", "value": 2800.0},

            {"source": "ORD1 (Entry)", "target": "ORD1 (Exit)", "value": 2500.0},
            {"source": "ORD1 (Entry)", "target": "SFO1 (Exit)", "value": 2300.0},
        ]

        # Stage 4 -> 5
        l4 = [
            {"source": "ORD1 (Exit)", "target": "12.0.0.0/9", "value": 2700.0},
            {"source": "ORD1 (Exit)", "target": "96.6.0.0/22", "value": 1800.0},
            {"source": "ORD1 (Exit)", "target": "66.100.0.0/15", "value": 1550.0},
            {"source": "ORD1 (Exit)", "target": "205.158.0.0/16", "value": 1300.0},
            {"source": "ORD1 (Exit)", "target": "15.143.96.0/23", "value": 1150.0},
            {"source": "ORD1 (Exit)", "target": "144.224.0.0/16", "value": 950.0},
            {"source": "ORD1 (Exit)", "target": "141.193.36.0/22", "value": 800.0},
            {"source": "ORD1 (Exit)", "target": "141.193.37.5/32", "value": 550.0},
            {"source": "ORD1 (Exit)", "target": "17.0.0.0/21", "value": 400.0},

            {"source": "SFO1 (Exit)", "target": "12.0.0.0/9", "value": 2100.0},
            {"source": "SFO1 (Exit)", "target": "96.6.0.0/22", "value": 1450.0},
            {"source": "SFO1 (Exit)", "target": "66.100.0.0/15", "value": 1250.0},
            {"source": "SFO1 (Exit)", "target": "205.158.0.0/16", "value": 1100.0},
            {"source": "SFO1 (Exit)", "target": "15.143.96.0/23", "value": 1000.0},
            {"source": "SFO1 (Exit)", "target": "144.224.0.0/16", "value": 800.0},
            {"source": "SFO1 (Exit)", "target": "141.193.36.0/22", "value": 650.0},
            {"source": "SFO1 (Exit)", "target": "141.193.37.5/32", "value": 500.0},
            {"source": "SFO1 (Exit)", "target": "17.0.0.0/21", "value": 450.0},
        ]

        all_links = l1 + l2 + l3 + l4
        total_val = 20500.0

        # Detailed path table
        paths = [
            {"src": "Google Youtube", "interconnect": "free_pni", "in_pop": "SFO1", "out_pop": "ORD1", "dst": "12.0.0.0/9", "app": "QUIC / HTTPS", "mbps": 1640.0, "pps": 136000},
            {"src": "Netflix", "interconnect": "free_pni", "in_pop": "SFO1", "out_pop": "SFO1", "dst": "96.6.0.0/22", "app": "HTTPS (Video)", "mbps": 1420.0, "pps": 118000},
            {"src": "Amazon + AWS", "interconnect": "paid_pni", "in_pop": "NYC1", "out_pop": "ORD1", "dst": "66.100.0.0/15", "app": "Cloud Compute", "mbps": 1120.0, "pps": 93000},
            {"src": "Facebook", "interconnect": "free_pni", "in_pop": "SFO1", "out_pop": "ORD1", "dst": "205.158.0.0/16", "app": "HTTPS / Social", "mbps": 1080.0, "pps": 90000},
            {"src": "Google Youtube", "interconnect": "paid_pni", "in_pop": "NYC1", "out_pop": "SFO1", "dst": "15.143.96.0/23", "app": "QUIC Video", "mbps": 950.0, "pps": 79000},
            {"src": "Netflix", "interconnect": "free_pni", "in_pop": "ORD1", "out_pop": "ORD1", "dst": "12.0.0.0/9", "app": "TLS Media Stream", "mbps": 890.0, "pps": 74000},
            {"src": "Akamai", "interconnect": "customer", "in_pop": "NYC1", "out_pop": "ORD1", "dst": "144.224.0.0/16", "app": "Edge CDN Web", "mbps": 820.0, "pps": 68000},
            {"src": "Apple", "interconnect": "paid_pni", "in_pop": "NYC1", "out_pop": "SFO1", "dst": "141.193.36.0/22", "app": "App Store Sync", "mbps": 760.0, "pps": 63000},
            {"src": "Amazon + AWS", "interconnect": "free_pni", "in_pop": "SFO1", "out_pop": "ORD1", "dst": "141.193.37.5/32", "app": "AWS S3 Sync", "mbps": 720.0, "pps": 60000},
            {"src": "Facebook", "interconnect": "free_pni", "in_pop": "NYC1", "out_pop": "SFO1", "dst": "17.0.0.0/21", "app": "Instagram Live", "mbps": 680.0, "pps": 56000},
            {"src": "EdgeCast Verizon", "interconnect": "transit", "in_pop": "ORD1", "out_pop": "ORD1", "dst": "12.0.0.0/9", "app": "Transit CDN", "mbps": 480.0, "pps": 40000},
            {"src": "Yahoo", "interconnect": "transit", "in_pop": "SFO1", "out_pop": "SFO1", "dst": "96.6.0.0/22", "app": "Yahoo Media", "mbps": 420.0, "pps": 35000},
            {"src": "Google Youtube", "interconnect": "transit", "in_pop": "ORD1", "out_pop": "ORD1", "dst": "205.158.0.0/16", "app": "YouTube CDN", "mbps": 460.0, "pps": 38000},
            {"src": "Apple", "interconnect": "transit", "in_pop": "NYC1", "out_pop": "ORD1", "dst": "144.224.0.0/16", "app": "Apple Music", "mbps": 430.0, "pps": 36000},
            {"src": "Akamai", "interconnect": "free_pni", "in_pop": "SFO1", "out_pop": "SFO1", "dst": "66.100.0.0/15", "app": "Edge Delivery", "mbps": 410.0, "pps": 34000},
        ]

        table_rows = []
        for idx, p in enumerate(paths, 1):
            share = round((p["mbps"] / total_val) * 100, 2)
            total_gb = round(p["mbps"] * minutes * 60 / (8 * 1024), 2)
            table_rows.append({
                "rank": idx,
                "src_entity": p["src"],
                "interconnect": p["interconnect"],
                "ingress_site": p["in_pop"],
                "egress_site": p["out_pop"],
                "dst_prefix": p["dst"],
                "application": p["app"],
                "mbps": p["mbps"],
                "pps": p["pps"],
                "total_gb": total_gb,
                "share_pct": share
            })

        # Treemap hierarchy
        treemap_children = []
        for prov in providers:
            p_child = {"name": prov["name"], "value": prov["mbps"], "children": []}
            for l in l1:
                if l["source"] == prov["name"]:
                    p_child["children"].append({"name": l["target"], "value": l["value"]})
            treemap_children.append(p_child)

        treemap = {"name": "CDN Entry Traffic", "children": treemap_children}

        # Sunburst hierarchy
        sunburst_data = []
        for prov in providers:
            p_node = {"name": prov["name"], "children": []}
            for l in l1:
                if l["source"] == prov["name"]:
                    p_node["children"].append({"name": l["target"], "value": l["value"]})
            sunburst_data.append(p_node)

        # 60-point timeseries
        timeseries = []
        now = time.time()
        for m in range(60, 0, -1):
            t_sec = now - m * 60
            jitter = ((m * 7) % 19) * 0.15 - 1.2
            mbps = round(20500.0 + jitter * 800.0, 2)
            pps = int(mbps * 83.3)
            timeseries.append({
                "time_point": time.strftime("%H:%M", time.gmtime(t_sec)),
                "mbps": mbps,
                "pps": pps
            })

        return {
            "view_name": "CDN Traffic Network Entry and Exit ★ Saved View",
            "preset_id": "CDN_ENTRY_EXIT",
            "stages": ["CDN Provider", "Interconnect", "Ingress PoP", "Egress PoP", "Destination Prefix"],
            "summary": {
                "total_mbps": total_val,
                "total_gb": round(total_val * minutes * 60 / (8 * 1024), 2),
                "total_pps": 1709000,
                "total_flows": 284000,
                "top_talker": "Google Youtube (4,680 Mbps)"
            },
            "sankey": {
                "nodes": nodes,
                "links": all_links
            },
            "bars": {
                "providers": {
                    "labels": [p["name"] for p in providers],
                    "values": [p["mbps"] for p in providers],
                    "colors": [p["color"] for p in providers]
                },
                "prefixes": {
                    "labels": [pr["name"] for pr in prefixes],
                    "values": [pr["mbps"] for pr in prefixes],
                    "colors": [pr["color"] for pr in prefixes]
                },
                "interconnects": {
                    "labels": [i["name"] for i in interconnects],
                    "values": [11850.0, 4120.0, 2970.0, 1560.0],
                    "colors": [i["color"] for i in interconnects]
                }
            },
            "table": table_rows,
            "timeseries": timeseries,
            "treemap": treemap,
            "sunburst": sunburst_data
        }

    def _build_dynamic_multiview(self, criteria: Dict[str, Any], minutes: int = 60) -> Dict[str, Any]:
        """
        Dynamically extracts flows matching the multi-condition filter and computes:
        - 5-stage Sankey: Source Provider/ASN -> Ingress Site -> Router Device -> Destination Prefix -> Application
        - Ranked Bar Charts
        - Full Table
        - Treemap & Sunburst
        """
        where_clause = self.build_where_clause(criteria, minutes=minutes)

        # 1. Detailed multi-stage breakdown
        sql_flows = f"""
        SELECT 
            COALESCE(NULLIF(src_as_name, ''), 'AS' || src_as::VARCHAR, 'Internal Network') AS src_entity,
            COALESCE(NULLIF(site, ''), 'Core Backbone') AS site_entity,
            COALESCE(NULLIF(device_name, ''), device_id) AS device_entity,
            (split_part(dst_ip, '.', 1) || '.' || split_part(dst_ip, '.', 2) || '.0.0/16') AS dst_prefix,
            application,
            flow_direction,
            SUM(bytes) AS bytes,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            ROUND(SUM(packets) * 1.0 / ({minutes} * 60.0), 0) AS pps
        FROM raw_flows
        WHERE {where_clause}
        GROUP BY src_entity, site_entity, device_entity, dst_prefix, application, flow_direction
        ORDER BY bytes DESC
        LIMIT 60;
        """
        rows = self.storage.query(sql_flows)

        total_bytes = sum(r["bytes"] for r in rows) if rows else 1
        total_mbps = round(sum(r["mbps"] for r in rows), 2)
        total_pps = int(sum(r["pps"] for r in rows))

        # Node color palette
        PALETTE = [
            "#ef4444", "#3b82f6", "#10b981", "#f59e0b", "#8b5cf6",
            "#06b6d4", "#ec4899", "#14b8a6", "#f97316", "#6366f1",
            "#84cc16", "#eab308", "#0ea5e9", "#d946ef", "#64748b"
        ]

        nodes_map = {}
        links_dict = {}

        def get_node(name: str, stage_name: str, depth: int):
            key = f"{depth}::{name}"
            if key not in nodes_map:
                color = PALETTE[len(nodes_map) % len(PALETTE)]
                nodes_map[key] = {
                    "name": key,
                    "display": name,
                    "stage": stage_name,
                    "depth": depth,
                    "itemStyle": {"color": color}
                }
            return key

        def add_link(s_key: str, t_key: str, val: float):
            link_key = f"{s_key}->{t_key}"
            if link_key not in links_dict:
                links_dict[link_key] = {"source": s_key, "target": t_key, "value": 0.0}
            links_dict[link_key]["value"] += val

        table_rows = []
        treemap_grouped = {}
        sunburst_grouped = {}

        for idx, r in enumerate(rows, 1):
            src_e = r["src_entity"]
            site_e = r["site_entity"]
            dev_e = r["device_entity"]
            pfx_e = r["dst_prefix"]
            app_e = r["application"]
            mbps_v = max(0.01, float(r["mbps"]))

            k1 = get_node(src_e, "Source ASN / Entity", 0)
            k2 = get_node(site_e, "Ingress PoP / Site", 1)
            k3 = get_node(dev_e, "Router / Switch", 2)
            k4 = get_node(pfx_e, "Destination Prefix", 3)
            k5 = get_node(app_e, "Application / Service", 4)

            add_link(k1, k2, mbps_v)
            add_link(k2, k3, mbps_v)
            add_link(k3, k4, mbps_v)
            add_link(k4, k5, mbps_v)

            share = round((r["bytes"] / total_bytes) * 100, 2)
            total_gb = round(r["bytes"] / (1024.0 * 1024.0 * 1024.0), 2)
            table_rows.append({
                "rank": idx,
                "src_entity": src_e,
                "interconnect": r.get("flow_direction", "WAN"),
                "ingress_site": site_e,
                "egress_site": dev_e,
                "dst_prefix": pfx_e,
                "application": app_e,
                "mbps": mbps_v,
                "pps": int(r["pps"]),
                "total_gb": total_gb,
                "share_pct": share
            })

            # Treemap / Sunburst grouping
            if src_e not in treemap_grouped:
                treemap_grouped[src_e] = {}
            if site_e not in treemap_grouped[src_e]:
                treemap_grouped[src_e][site_e] = 0.0
            treemap_grouped[src_e][site_e] += mbps_v

        # Round link values
        sankey_links = []
        for l in links_dict.values():
            l["value"] = round(l["value"], 2)
            sankey_links.append(l)

        # Build Treemap / Sunburst lists
        treemap_children = []
        for src_k, sites in treemap_grouped.items():
            c_list = [{"name": s_k, "value": round(s_v, 2)} for s_k, s_v in sites.items()]
            src_val = round(sum(s_v for s_v in sites.values()), 2)
            treemap_children.append({"name": src_k, "value": src_val, "children": c_list})

        treemap = {"name": "Dynamic Matched Flows", "children": treemap_children}

        # Build Bar charts data
        # Top 10 sources
        top_srcs = {}
        for r in rows:
            top_srcs[r["src_entity"]] = top_srcs.get(r["src_entity"], 0.0) + r["mbps"]
        sorted_srcs = sorted(top_srcs.items(), key=lambda x: x[1], reverse=True)[:8]

        # Top 10 prefixes
        top_pfxs = {}
        for r in rows:
            top_pfxs[r["dst_prefix"]] = top_pfxs.get(r["dst_prefix"], 0.0) + r["mbps"]
        sorted_pfxs = sorted(top_pfxs.items(), key=lambda x: x[1], reverse=True)[:8]

        # Top 10 sites
        top_sites = {}
        for r in rows:
            top_sites[r["site_entity"]] = top_sites.get(r["site_entity"], 0.0) + r["mbps"]
        sorted_sites = sorted(top_sites.items(), key=lambda x: x[1], reverse=True)[:6]

        # Timeseries from DuckDB
        interval_sec = 60 if minutes <= 120 else 300
        sql_timeseries = f"""
        SELECT 
            time_bucket(INTERVAL '{interval_sec} SECOND', timestamp) AS time_point,
            ROUND(SUM(bytes) * 8.0 / ({interval_sec} * 1000000.0), 2) AS mbps,
            ROUND(SUM(packets) * 1.0 / {interval_sec}, 0) AS pps
        FROM raw_flows
        WHERE {where_clause}
        GROUP BY time_point
        ORDER BY time_point ASC;
        """
        ts_rows = self.storage.query(sql_timeseries)
        timeseries = []
        for t in ts_rows:
            tp = t["time_point"].strftime("%H:%M") if hasattr(t["time_point"], "strftime") else str(t["time_point"])
            timeseries.append({
                "time_point": tp,
                "mbps": t["mbps"],
                "pps": int(t["pps"])
            })

        return {
            "view_name": "Filtered Dynamic Traffic Pattern Flow",
            "preset_id": "DYNAMIC",
            "stages": ["Source ASN / Entity", "Ingress PoP / Site", "Router / Switch", "Destination Prefix", "Application"],
            "summary": {
                "total_mbps": total_mbps,
                "total_gb": round(total_bytes / (1024.0 * 1024.0 * 1024.0), 2),
                "total_pps": total_pps,
                "total_flows": len(rows),
                "top_talker": sorted_srcs[0][0] if sorted_srcs else "N/A"
            },
            "sankey": {
                "nodes": list(nodes_map.values()),
                "links": sankey_links
            },
            "bars": {
                "providers": {
                    "labels": [s[0] for s in sorted_srcs],
                    "values": [round(s[1], 2) for s in sorted_srcs],
                    "colors": [PALETTE[i % len(PALETTE)] for i in range(len(sorted_srcs))]
                },
                "prefixes": {
                    "labels": [p[0] for p in sorted_pfxs],
                    "values": [round(p[1], 2) for p in sorted_pfxs],
                    "colors": [PALETTE[(i + 4) % len(PALETTE)] for i in range(len(sorted_pfxs))]
                },
                "interconnects": {
                    "labels": [si[0] for si in sorted_sites],
                    "values": [round(si[1], 2) for si in sorted_sites],
                    "colors": [PALETTE[(i + 8) % len(PALETTE)] for i in range(len(sorted_sites))]
                }
            },
            "table": table_rows,
            "timeseries": timeseries,
            "treemap": treemap,
            "sunburst": treemap_children
        }

    def get_multi_parameter_flows(self, group_by: str = "IP_TO_IP", minutes: int = 60, limit: int = 50) -> Dict[str, Any]:
        """
        Carrier-Scale (>1,000 Gbps) Multi-Parameter Flow Analysis.
        Maps real-time flow traffic against Upstream Providers and Services across:
        - IP to IP
        - Prefix to Prefix (/24 Subnets)
        - Device to IP
        - ASN to ASN
        - Upstream to Service
        """
        duration_sec = max(60, minutes * 60)
        mode = group_by.upper()

        if mode == "PREFIX_TO_PREFIX":
            sql = f"""
            SELECT 
                split_part(src_ip, '.', 1) || '.' || split_part(src_ip, '.', 2) || '.' || split_part(src_ip, '.', 3) || '.0/24' AS source_entity,
                split_part(dst_ip, '.', 1) || '.' || split_part(dst_ip, '.', 2) || '.' || split_part(dst_ip, '.', 3) || '.0/24' AS destination_entity,
                COALESCE(upstream_provider, 'Tata Communications') AS upstream_provider,
                COALESCE(service_name, 'IPT') AS service_name,
                SUM(bytes) AS bytes,
                SUM(packets) AS packets,
                ROUND(SUM(bytes) * 8.0 / ({duration_sec} * 1000000.0), 2) AS mbps,
                ROUND(SUM(bytes) * 8.0 / ({duration_sec} * 1000000000.0), 3) AS gbps,
                COUNT(*) AS flow_count
            FROM raw_flows
            WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
            GROUP BY source_entity, destination_entity, upstream_provider, service_name
            ORDER BY bytes DESC
            LIMIT {limit};
            """
        elif mode == "DEVICE_TO_IP":
            sql = f"""
            SELECT 
                COALESCE(device_name, 'cisco-ny4-edge-001') AS source_entity,
                dst_ip AS destination_entity,
                COALESCE(upstream_provider, 'Bharti Airtel') AS upstream_provider,
                COALESCE(service_name, 'IPT') AS service_name,
                SUM(bytes) AS bytes,
                SUM(packets) AS packets,
                ROUND(SUM(bytes) * 8.0 / ({duration_sec} * 1000000.0), 2) AS mbps,
                ROUND(SUM(bytes) * 8.0 / ({duration_sec} * 1000000000.0), 3) AS gbps,
                COUNT(*) AS flow_count
            FROM raw_flows
            WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
            GROUP BY device_name, dst_ip, upstream_provider, service_name
            ORDER BY bytes DESC
            LIMIT {limit};
            """
        elif mode == "ASN_TO_ASN":
            sql = f"""
            SELECT 
                'AS' || src_as || ' (' || src_as_name || ')' AS source_entity,
                'AS' || dst_as || ' (' || dst_as_name || ')' AS destination_entity,
                COALESCE(upstream_provider, 'Tata Communications') AS upstream_provider,
                COALESCE(service_name, 'IPT') AS service_name,
                SUM(bytes) AS bytes,
                SUM(packets) AS packets,
                ROUND(SUM(bytes) * 8.0 / ({duration_sec} * 1000000.0), 2) AS mbps,
                ROUND(SUM(bytes) * 8.0 / ({duration_sec} * 1000000000.0), 3) AS gbps,
                COUNT(*) AS flow_count
            FROM raw_flows
            WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
            GROUP BY src_as, src_as_name, dst_as, dst_as_name, upstream_provider, service_name
            ORDER BY bytes DESC
            LIMIT {limit};
            """
        elif mode == "UPSTREAM_TO_SERVICE":
            sql = f"""
            SELECT 
                COALESCE(upstream_provider, 'Tata Communications') AS source_entity,
                COALESCE(service_name, 'IPT') AS destination_entity,
                COALESCE(upstream_provider, 'Tata Communications') AS upstream_provider,
                COALESCE(service_name, 'IPT') AS service_name,
                SUM(bytes) AS bytes,
                SUM(packets) AS packets,
                ROUND(SUM(bytes) * 8.0 / ({duration_sec} * 1000000.0), 2) AS mbps,
                ROUND(SUM(bytes) * 8.0 / ({duration_sec} * 1000000000.0), 3) AS gbps,
                COUNT(*) AS flow_count
            FROM raw_flows
            WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
            GROUP BY upstream_provider, service_name
            ORDER BY bytes DESC
            LIMIT {limit};
            """
        else: # Default: IP_TO_IP
            mode = "IP_TO_IP"
            sql = f"""
            SELECT 
                src_ip AS source_entity,
                dst_ip AS destination_entity,
                COALESCE(upstream_provider, 'Tata Communications') AS upstream_provider,
                COALESCE(service_name, 'IPT') AS service_name,
                SUM(bytes) AS bytes,
                SUM(packets) AS packets,
                ROUND(SUM(bytes) * 8.0 / ({duration_sec} * 1000000.0), 2) AS mbps,
                ROUND(SUM(bytes) * 8.0 / ({duration_sec} * 1000000000.0), 3) AS gbps,
                COUNT(*) AS flow_count
            FROM raw_flows
            WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
            GROUP BY src_ip, dst_ip, upstream_provider, service_name
            ORDER BY bytes DESC
            LIMIT {limit};
            """

        rows = self.storage.query(sql) if hasattr(self.storage, "query") else []

        total_gbps = round(sum(r.get("gbps", 0.0) for r in rows), 3)
        total_mbps = round(sum(r.get("mbps", 0.0) for r in rows), 2)

        return {
            "group_by": mode,
            "time_window_minutes": minutes,
            "total_records": len(rows),
            "total_gbps": total_gbps,
            "total_mbps": total_mbps,
            "flows": rows
        }
