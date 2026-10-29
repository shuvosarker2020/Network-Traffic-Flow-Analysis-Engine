"""
Carrier-Grade Multi-Vendor Flow Generator for AegisFlow
Simulates realistic production traffic across Cisco, Juniper, Huawei, Nokia, and MikroTik routers.
Supports both direct storage insertion and raw UDP binary packet generation for testing.
"""

import random
import time
import socket
import struct
import datetime
from typing import List, Dict, Any

from enrichment.pipeline import enrich_batch
from enrichment.snmp_cache import snmp_cache

# Realistic IP pools
INTERNAL_HOSTS = [
    f"10.0.{s}.{h}" for s in [1, 2, 10, 20, 50] for h in [5, 10, 20, 100, 150, 200]
] + [
    f"10.1.{s}.{h}" for s in [1, 5, 12] for h in [10, 20, 50, 80]
]

CLOUD_DESTINATIONS = [
    "8.8.8.8", "8.8.4.4", # Google DNS
    "1.1.1.1", "1.0.0.1", # Cloudflare DNS
    "142.250.190.46", "142.250.72.14", # Google Services
    "104.16.132.229", "104.16.133.229", # Cloudflare Edge
    "52.94.233.129", "54.239.28.85", # AWS
    "20.190.159.2", "40.126.31.2", # Microsoft Azure
    "198.38.118.140", # Netflix
    "4.69.130.1", # Lumen Transit
    "213.155.130.1", # Telia Transit
    "154.54.38.1", # Cogent Transit
    "129.250.3.1" # NTT Transit
]

SERVICES = [
    {"proto": 6, "port": 443, "weight": 45, "app": "HTTPS / TLS", "dscp": 0},
    {"proto": 17, "port": 443, "weight": 20, "app": "QUIC / HTTP3", "dscp": 0},
    {"proto": 17, "port": 53, "weight": 10, "app": "DNS", "dscp": 0},
    {"proto": 6, "port": 80, "weight": 8, "app": "HTTP", "dscp": 0},
    {"proto": 6, "port": 22, "weight": 4, "app": "SSH", "dscp": 16},
    {"proto": 17, "port": 5060, "weight": 3, "app": "SIP / VoIP", "dscp": 46}, # EF
    {"proto": 17, "port": 12000, "weight": 4, "app": "RTP Audio/Video", "dscp": 34}, # AF41
    {"proto": 6, "port": 179, "weight": 2, "app": "BGP", "dscp": 48}, # CS6
    {"proto": 6, "port": 9092, "weight": 2, "app": "Apache Kafka", "dscp": 0},
    {"proto": 6, "port": 6379, "weight": 2, "app": "Redis", "dscp": 0},
]

def generate_random_flow_records(count: int = 500, base_time: float = None) -> List[Dict[str, Any]]:
    if base_time is None:
        base_time = time.time()

    devices_list = list(snmp_cache.devices.values())
    if not devices_list:
        dev_sample = {"ip": "10.0.0.1", "device_id": "dev-0001", "vendor": "Cisco", "sampling_rate": 1000}
    else:
        dev_sample = None

    records = []
    service_choices = [s for s in SERVICES for _ in range(s["weight"])]

    for _ in range(count):
        dev = random.choice(devices_list) if devices_list else dev_sample
        exporter_ip = dev["ip"]
        sampling_rate = dev.get("sampling_rate", 1000)

        # Decide traffic scenario: 60% Outbound to Internet/Cloud, 25% Inbound, 15% East-West Internal
        scenario = random.choices(["OUTBOUND", "INBOUND", "INTERNAL"], weights=[60, 25, 15])[0]

        if scenario == "OUTBOUND":
            src_ip = random.choice(INTERNAL_HOSTS)
            dst_ip = random.choice(CLOUD_DESTINATIONS)
        elif scenario == "INBOUND":
            src_ip = random.choice(CLOUD_DESTINATIONS)
            dst_ip = random.choice(INTERNAL_HOSTS)
        else: # INTERNAL East-West
            src_ip = random.choice(INTERNAL_HOSTS)
            dst_ip = random.choice(INTERNAL_HOSTS)

        svc = random.choice(service_choices)
        proto = svc["proto"]
        dst_port = svc["port"]
        src_port = random.randint(1024, 65535)
        dscp = svc["dscp"]
        tos = dscp << 2

        # Packet and byte scaling
        raw_packets = random.randint(10, 500)
        raw_bytes = raw_packets * random.randint(300, 1480)

        scaled_packets = raw_packets * sampling_rate
        scaled_bytes = raw_bytes * sampling_rate

        in_if = random.randint(1, 16)
        out_if = random.randint(1, 16)

        # Realistic timestamp jitter within window
        rec_time = base_time - random.uniform(0, 300)

        records.append({
            "exporter_ip": exporter_ip,
            "version": 9,
            "timestamp": int(rec_time),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "next_hop": "10.254.254.1",
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "tcp_flags": 16 if proto == 6 else 0, # ACK flag
            "tos": tos,
            "dscp": dscp,
            "in_ifindex": in_if,
            "out_ifindex": out_if,
            "packets": scaled_packets,
            "bytes": scaled_bytes,
            "raw_packets": raw_packets,
            "raw_bytes": raw_bytes,
            "sampling_rate": sampling_rate,
            "src_as": 0,
            "dst_as": 0,
            "duration_ms": random.randint(50, 4500)
        })

    return enrich_batch(records)

def seed_initial_telemetry(storage, hours: int = 2, flows_per_batch: int = 600):
    """Pre-populates storage with realistic historical flows so analytics and graphs are immediately populated."""
    print(f"Seeding historical flow telemetry ({hours} hours)...")
    now = time.time()
    total_inserted = 0

    # Step in 5-minute increments
    step_sec = 300
    intervals = int((hours * 3600) / step_sec)

    for i in range(intervals):
        t = now - ((intervals - i) * step_sec)
        batch = generate_random_flow_records(count=flows_per_batch, base_time=t)
        inserted = storage.insert_flows(batch)
        total_inserted += inserted

    print(f"Successfully seeded {total_inserted} enriched flow records into storage engine.")
