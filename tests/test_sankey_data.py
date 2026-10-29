"""
Prototype for CDN Entry & Exit Sankey dataset
"""
def build_cdn_preset_data():
    # Stage 1: Providers
    providers = [
        {"name": "Google Youtube", "color": "#ef4444", "mbps": 4680.0},
        {"name": "Netflix", "color": "#dc2626", "mbps": 3820.0},
        {"name": "Amazon + AWS", "color": "#f59e0b", "mbps": 3410.0},
        {"name": "Facebook", "color": "#3b82f6", "mbps": 2950.0},
        {"name": "Akamai", "color": "#06b6d4", "mbps": 2240.0},
        {"name": "Apple", "color": "#64748b", "mbps": 1680.0},
        {"name": "Yahoo", "color": "#a855f7", "mbps": 940.0},
        {"name": "EdgeCast Verizon", "color": "#8b5cf6", "mbps": 780.0},
    ]

    # Stage 2: Interconnects
    interconnects = [
        {"name": "free_pni", "color": "#14b8a6"},
        {"name": "paid_pni", "color": "#f97316"},
        {"name": "transit", "color": "#94a3b8"},
        {"name": "customer", "color": "#38bdf8"},
    ]

    # Stage 3: Ingress PoPs
    ingress_pops = [
        {"name": "SFO1 (Entry)", "display": "SFO1", "color": "#10b981"},
        {"name": "NYC1 (Entry)", "display": "NYC1", "color": "#f59e0b"},
        {"name": "ORD1 (Entry)", "display": "ORD1", "color": "#06b6d4"},
    ]

    # Stage 4: Egress PoPs
    egress_pops = [
        {"name": "ORD1 (Exit)", "display": "ORD1", "color": "#0ea5e9"},
        {"name": "SFO1 (Exit)", "display": "SFO1", "color": "#10b981"},
    ]

    # Stage 5: Prefixes
    prefixes = [
        {"name": "12.0.0.0/9", "color": "#ec4899"},
        {"name": "96.6.0.0/22", "color": "#8b5cf6"},
        {"name": "66.100.0.0/15", "color": "#3b82f6"},
        {"name": "205.158.0.0/16", "color": "#06b6d4"},
        {"name": "15.143.96.0/23", "color": "#10b981"},
        {"name": "144.224.0.0/16", "color": "#eab308"},
        {"name": "141.193.36.0/22", "color": "#f97316"},
        {"name": "141.193.37.5/32", "color": "#ef4444"},
        {"name": "17.0.0.0/21", "color": "#6366f1"},
    ]

    nodes = []
    for p in providers:
        nodes.append({"name": p["name"], "itemStyle": {"color": p["color"]}, "depth": 0})
    for i in interconnects:
        nodes.append({"name": i["name"], "itemStyle": {"color": i["color"]}, "depth": 1})
    for ip in ingress_pops:
        nodes.append({"name": ip["name"], "itemStyle": {"color": ip["color"]}, "depth": 2})
    for ep in egress_pops:
        nodes.append({"name": ep["name"], "itemStyle": {"color": ep["color"]}, "depth": 3})
    for pr in prefixes:
        nodes.append({"name": pr["name"], "itemStyle": {"color": pr["color"]}, "depth": 4})

    print(f"Total nodes: {len(nodes)}")

    # Links Stage 1 -> Stage 2
    links_1_2 = [
        # Google
        {"source": "Google Youtube", "target": "free_pni", "value": 3120.0},
        {"source": "Google Youtube", "target": "paid_pni", "value": 1100.0},
        {"source": "Google Youtube", "target": "transit", "value": 460.0},
        # Netflix
        {"source": "Netflix", "target": "free_pni", "value": 2840.0},
        {"source": "Netflix", "target": "transit", "value": 980.0},
        # Amazon
        {"source": "Amazon + AWS", "target": "free_pni", "value": 1850.0},
        {"source": "Amazon + AWS", "target": "paid_pni", "value": 1120.0},
        {"source": "Amazon + AWS", "target": "customer", "value": 440.0},
        # Facebook
        {"source": "Facebook", "target": "free_pni", "value": 2100.0},
        {"source": "Facebook", "target": "paid_pni", "value": 850.0},
        # Akamai
        {"source": "Akamai", "target": "free_pni", "value": 1420.0},
        {"source": "Akamai", "target": "customer", "value": 820.0},
        # Apple
        {"source": "Apple", "target": "paid_pni", "value": 1050.0},
        {"source": "Apple", "target": "transit", "value": 630.0},
        # Yahoo
        {"source": "Yahoo", "target": "free_pni", "value": 520.0},
        {"source": "Yahoo", "target": "transit", "value": 420.0},
        # EdgeCast
        {"source": "EdgeCast Verizon", "target": "transit", "value": 480.0},
        {"source": "EdgeCast Verizon", "target": "customer", "value": 300.0},
    ]

    total_s1 = sum(l["value"] for l in links_1_2)
    print(f"Total Stage 1->2 Throughput: {total_s1:.1f} Mbps")

if __name__ == "__main__":
    build_cdn_preset_data()
