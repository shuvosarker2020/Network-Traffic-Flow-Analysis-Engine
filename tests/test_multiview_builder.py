"""
Prototype implementation of get_multiview_flow_data
"""
import time

def build_cdn_entry_exit_view(minutes: int = 60):
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

    # Links 1->2 (Provider -> Interconnect)
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

    # Links 2->3 (Interconnect -> Ingress PoP)
    # free_pni (11850) -> SFO1 (5200), NYC1 (3950), ORD1 (2700)
    # paid_pni (4120)  -> SFO1 (1800), NYC1 (1420), ORD1 (900)
    # transit (2970)   -> SFO1 (1100), NYC1 (1070), ORD1 (800)
    # customer (1560)  -> SFO1 (700),  NYC1 (460),  ORD1 (400)
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

    # Links 3->4 (Ingress PoP -> Egress PoP)
    # SFO1 (Entry) total 8800 -> ORD1 (Exit) 4600, SFO1 (Exit) 4200
    # NYC1 (Entry) total 6900 -> ORD1 (Exit) 4100, SFO1 (Exit) 2800
    # ORD1 (Entry) total 4800 -> ORD1 (Exit) 2500, SFO1 (Exit) 2300
    l3 = [
        {"source": "SFO1 (Entry)", "target": "ORD1 (Exit)", "value": 4600.0},
        {"source": "SFO1 (Entry)", "target": "SFO1 (Exit)", "value": 4200.0},

        {"source": "NYC1 (Entry)", "target": "ORD1 (Exit)", "value": 4100.0},
        {"source": "NYC1 (Entry)", "target": "SFO1 (Exit)", "value": 2800.0},

        {"source": "ORD1 (Entry)", "target": "ORD1 (Exit)", "value": 2500.0},
        {"source": "ORD1 (Entry)", "target": "SFO1 (Exit)", "value": 2300.0},
    ]

    # Links 4->5 (Egress PoP -> Prefixes)
    # ORD1 (Exit) total 11200:
    # 12.0.0.0/9 (2700), 96.6.0.0/22 (1800), 66.100.0.0/15 (1550), 205.158.0.0/16 (1300),
    # 15.143.96.0/23 (1150), 144.224.0.0/16 (950), 141.193.36.0/22 (800), 141.193.37.5/32 (550), 17.0.0.0/21 (400)
    # SFO1 (Exit) total 9300:
    # 12.0.0.0/9 (2100), 96.6.0.0/22 (1450), 66.100.0.0/15 (1250), 205.158.0.0/16 (1100),
    # 15.143.96.0/23 (1000), 144.224.0.0/16 (800), 141.193.36.0/22 (650), 141.193.37.5/32 (500), 17.0.0.0/21 (450)
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

    # Build Table rows
    table_rows = []
    total_val = 20500.0
    rank = 1
    # Sample realistic detailed flow paths
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
    ]

    for p in paths:
        share = round((p["mbps"] / total_val) * 100, 2)
        total_gb = round(p["mbps"] * minutes * 60 / (8 * 1024), 2)
        table_rows.append({
            "rank": rank,
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
        rank += 1

    # Build Treemap data
    treemap_children = []
    for prov in providers:
        p_child = {"name": prov["name"], "value": prov["mbps"], "children": []}
        # break into interconnects
        for l in l1:
            if l["source"] == prov["name"]:
                p_child["children"].append({"name": l["target"], "value": l["value"]})
        treemap_children.append(p_child)

    treemap = {"name": "CDN Entry Traffic", "children": treemap_children}

    # Build Sunburst data
    sunburst_data = []
    for prov in providers:
        p_node = {"name": prov["name"], "children": []}
        for l in l1:
            if l["source"] == prov["name"]:
                p_node["children"].append({"name": l["target"], "value": l["value"]})
        sunburst_data.append(p_node)

    # Build Timeseries data (60 points)
    timeseries = []
    now = time.time()
    for m in range(60, 0, -1):
        t_sec = now - m * 60
        # fluctuate between 19.2 and 22.1 Gbps
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
            "providers": {"labels": [p["name"] for p in providers], "values": [p["mbps"] for p in providers], "colors": [p["color"] for p in providers]},
            "prefixes": {"labels": [pr["name"] for pr in prefixes], "values": [pr["mbps"] for pr in prefixes], "colors": [pr["color"] for pr in prefixes]},
            "interconnects": {"labels": [i["name"] for i in interconnects], "values": [11850.0, 4120.0, 2970.0, 1560.0], "colors": [i["color"] for i in interconnects]}
        },
        "table": table_rows,
        "timeseries": timeseries,
        "treemap": treemap,
        "sunburst": sunburst_data
    }

if __name__ == "__main__":
    res = build_cdn_entry_exit_view()
    print("Sankey Nodes:", len(res["sankey"]["nodes"]))
    print("Sankey Links:", len(res["sankey"]["links"]))
    print("Table Rows:", len(res["table"]))
    print("Bars Providers:", len(res["bars"]["providers"]["labels"]))
    print("Summary:", res["summary"])
