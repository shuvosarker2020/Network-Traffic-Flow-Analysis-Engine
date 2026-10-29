"""
Metadata Generator for AegisFlow
Generates realistic multi-vendor inventory for 1,000+ devices and their interface mappings,
plus an ASN directory and GeoIP/Subnet database.
"""

import json
import random

def generate_inventory():
    random.seed(42)

    vendors = [
        {"vendor": "Cisco", "models": ["ASR-9904", "Nexus 9336C-FX2", "Catalyst 9500", "8201 Router"], "if_prefix": "HundredGigE0/0/0/"},
        {"vendor": "Juniper", "models": ["MX960", "PTX10001-36MR", "QFX5200-32C", "SRX4600"], "if_prefix": "et-0/0/"},
        {"vendor": "Huawei", "models": ["NetEngine 8000 X8", "CloudEngine 8850", "NE40E-X16"], "if_prefix": "100GE1/0/"},
        {"vendor": "Nokia", "models": ["7750 SR-12e", "7250 IXR-e", "7950 XRS-20"], "if_prefix": "1/1/c"},
        {"vendor": "ZTE", "models": ["ZXR10 M6000-8S", "ZXR10 9900"], "if_prefix": "gei-0/1/0/"},
        {"vendor": "MikroTik", "models": ["CCR2216-1G-12XS-2XQ", "CCR2004-16G-2S+"], "if_prefix": "sfp-sfpplus"}
    ]

    sites = [
        {"name": "Equinix NY4", "city": "Secaucus", "country": "US", "region": "North America", "lat": 40.7895, "lon": -74.0565},
        {"name": "Interxion FRA1", "city": "Frankfurt", "country": "DE", "region": "Europe", "lat": 50.1109, "lon": 8.6821},
        {"name": "Equinix TY2", "city": "Tokyo", "country": "JP", "region": "Asia-Pacific", "lat": 35.6762, "lon": 139.6503},
        {"name": "Telehouse London Docks", "city": "London", "country": "GB", "region": "Europe", "lat": 51.5074, "lon": -0.1278},
        {"name": "Equinix SG1", "city": "Singapore", "country": "SG", "region": "Asia-Pacific", "lat": 1.3521, "lon": 103.8198},
        {"name": "CoreSite LA1", "city": "Los Angeles", "country": "US", "region": "North America", "lat": 34.0522, "lon": -118.2437},
        {"name": "Teraco JB1", "city": "Johannesburg", "country": "ZA", "region": "Africa", "lat": -26.2041, "lon": 28.0473},
        {"name": "Equinix SP4", "city": "Sao Paulo", "country": "BR", "region": "South America", "lat": -23.5505, "lon": -46.6333},
        {"name": "Global Switch SYD", "city": "Sydney", "country": "AU", "region": "Oceania", "lat": -33.8688, "lon": 151.2093},
        {"name": "Equinix DX1", "city": "Dubai", "country": "AE", "region": "Middle East", "lat": 25.2048, "lon": 55.2708}
    ]

    roles = ["Edge/Border Gateway", "Core Backbone", "Peering Router", "DataCenter Leaf-Spine", "Aggregation"]

    devices = {}
    interfaces = {}

    # Generate 1,000 devices
    device_count = 1000
    for i in range(1, device_count + 1):
        v = random.choice(vendors)
        site = random.choice(sites)
        role = random.choice(roles)
        device_id = f"dev-{i:04d}"
        device_ip = f"10.{ (i >> 8) & 255 }.{ i & 255 }.1"
        hostname = f"{v['vendor'].lower()}-{site['city'].lower()[:3]}-{role[:4].lower()}-{i:03d}.net.infra"

        devices[device_id] = {
            "device_id": device_id,
            "hostname": hostname,
            "ip": device_ip,
            "vendor": v["vendor"],
            "model": random.choice(v["models"]),
            "role": role,
            "site": site["name"],
            "city": site["city"],
            "country": site["country"],
            "lat": site["lat"],
            "lon": site["lon"],
            "sampling_rate": 1000 if "Core" in role else 500,
            "flow_protocol": random.choice(["IPFIX", "NetFlow_v9", "NetFlow_v5", "sFlow_v5"]),
            "status": "ONLINE",
            "uptime_seconds": random.randint(100000, 30000000)
        }

        # Generate interfaces for each device (e.g. 10 to 48 interfaces each)
        if_count = random.randint(8, 24)
        for if_idx in range(1, if_count + 1):
            speed_bps = random.choice([10_000_000_000, 40_000_000_000, 100_000_000_000, 400_000_000_000])
            speed_str = "400GE" if speed_bps == 400_000_000_000 else ("100GE" if speed_bps == 100_000_000_000 else "10GE")
            if_type = random.choice(["Transit", "Peering", "Backbone", "Customer", "Cloud Interconnect"])
            
            aliases = {
                "Transit": ["Transit: Lumen AS3356", "Transit: Telia/Arelion AS1299", "Transit: Cogent AS174", "Transit: NTT AS2914"],
                "Peering": ["IXP: DE-CIX 100G Port", "IXP: AMS-IX PNI", "PNI: Google Cache AS15169", "PNI: Netflix OpenConnect AS2906", "PNI: Cloudflare AS13335"],
                "Backbone": [f"WAN Link to {random.choice(sites)['name']}", "Core Ring East-1", "Core Ring West-2"],
                "Customer": ["Enterprise Client 10G Dia", "Cloud DirectConnect 100G", "Broadband Aggregation VLAN 200"],
                "Cloud Interconnect": ["AWS Direct Connect 100G", "Azure ExpressRoute 50G", "GCP Cloud Interconnect 100G"]
            }

            if_name = f"{v['if_prefix']}{if_idx}"
            full_if_key = f"{device_ip}:{if_idx}"

            interfaces[full_if_key] = {
                "device_id": device_id,
                "device_ip": device_ip,
                "if_index": if_idx,
                "name": if_name,
                "alias": random.choice(aliases[if_type]),
                "type": if_type,
                "speed_bps": speed_bps,
                "speed_readable": speed_str,
                "status": "UP",
                "site": site["name"]
            }

    # ASN Directory with categorization
    asns = {
        "15169": {"name": "Google LLC", "category": "Peering / CDN", "country": "US", "transit_cost_usd_mbps": 0.0},
        "13335": {"name": "Cloudflare, Inc.", "category": "Peering / CDN", "country": "US", "transit_cost_usd_mbps": 0.0},
        "2906":  {"name": "Netflix Streaming Services", "category": "Peering / CDN", "country": "US", "transit_cost_usd_mbps": 0.0},
        "8075":  {"name": "Microsoft Corporation", "category": "Peering / Cloud", "country": "US", "transit_cost_usd_mbps": 0.0},
        "16509": {"name": "Amazon.com, Inc.", "category": "Peering / Cloud", "country": "US", "transit_cost_usd_mbps": 0.0},
        "3356":  {"name": "Lumen / Level3", "category": "Tier-1 Transit", "country": "US", "transit_cost_usd_mbps": 0.45},
        "1299":  {"name": "Arelion / Telia Carrier", "category": "Tier-1 Transit", "country": "SE", "transit_cost_usd_mbps": 0.42},
        "174":   {"name": "Cogent Communications", "category": "Tier-1 Transit", "country": "US", "transit_cost_usd_mbps": 0.25},
        "2914":  {"name": "NTT Communications", "category": "Tier-1 Transit", "country": "JP", "transit_cost_usd_mbps": 0.48},
        "6939":  {"name": "Hurricane Electric", "category": "Transit / Peering", "country": "US", "transit_cost_usd_mbps": 0.20},
        "3257":  {"name": "GTT Communications", "category": "Tier-1 Transit", "country": "US", "transit_cost_usd_mbps": 0.40},
        "64512": {"name": "Internal Corp DC East", "category": "Internal / Customer", "country": "US", "transit_cost_usd_mbps": 0.0},
        "64513": {"name": "Internal Corp DC West", "category": "Internal / Customer", "country": "US", "transit_cost_usd_mbps": 0.0},
        "64514": {"name": "Internal Edge VPC Cloud", "category": "Internal / Customer", "country": "US", "transit_cost_usd_mbps": 0.0}
    }

    with open("config/devices.json", "w") as f:
        json.dump(devices, f, indent=2)

    with open("config/interfaces.json", "w") as f:
        json.dump(interfaces, f, indent=2)

    with open("config/asns.json", "w") as f:
        json.dump(asns, f, indent=2)

    print(f"Generated {len(devices)} devices, {len(interfaces)} interfaces, {len(asns)} ASNs.")

if __name__ == "__main__":
    generate_inventory()
