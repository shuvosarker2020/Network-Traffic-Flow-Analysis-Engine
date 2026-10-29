"""
Cyber Threat & DDoS Attack Simulator for AegisFlow
Simulates realistic cyber security attacks: TCP SYN floods, DNS amplification, port scans, and lateral movement.
"""

import time
import random
from typing import List, Dict, Any
from enrichment.pipeline import enrich_batch

def generate_syn_flood_attack(target_ip: str = "10.0.1.50", packets_count: int = 150000) -> List[Dict[str, Any]]:
    """Simulates a massive distributed TCP SYN flood against an internal server."""
    records = []
    now = time.time()
    # 50 spoofed source IPs
    spoofed_sources = [f"{random.randint(11, 199)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(50)]

    for _ in range(400):
        src = random.choice(spoofed_sources)
        records.append({
            "exporter_ip": "10.0.0.1",
            "version": 9,
            "timestamp": int(now - random.uniform(0, 60)),
            "src_ip": src,
            "dst_ip": target_ip,
            "next_hop": "10.254.254.1",
            "src_port": random.randint(1024, 65535),
            "dst_port": 443,
            "protocol": 6, # TCP
            "tcp_flags": 2, # SYN only (no ACK!)
            "tos": 0,
            "dscp": 0,
            "in_ifindex": 1,
            "out_ifindex": 2,
            "packets": 5000,
            "bytes": 5000 * 64, # Small 64-byte SYN packets
            "raw_packets": 50,
            "raw_bytes": 50 * 64,
            "sampling_rate": 1000,
            "src_as": random.choice([3356, 1299, 174]),
            "dst_as": 64512,
            "duration_ms": 10
        })

    return enrich_batch(records)

def generate_dns_amplification_attack(target_ip: str = "10.0.1.50") -> List[Dict[str, Any]]:
    """Simulates a UDP DNS reflection amplification attack blasting a target IP."""
    records = []
    now = time.time()
    open_resolvers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "104.16.132.229"]

    for _ in range(300):
        res_ip = random.choice(open_resolvers)
        records.append({
            "exporter_ip": "10.0.0.1",
            "version": 9,
            "timestamp": int(now - random.uniform(0, 60)),
            "src_ip": res_ip,
            "dst_ip": target_ip,
            "next_hop": "10.254.254.1",
            "src_port": 53, # DNS server port
            "dst_port": random.randint(1024, 65535),
            "protocol": 17, # UDP
            "tcp_flags": 0,
            "tos": 0,
            "dscp": 0,
            "in_ifindex": 1,
            "out_ifindex": 2,
            "packets": 4000,
            "bytes": 4000 * 1420, # Large 1420-byte amplified responses
            "raw_packets": 40,
            "raw_bytes": 40 * 1420,
            "sampling_rate": 1000,
            "src_as": 15169,
            "dst_as": 64512,
            "duration_ms": 20
        })

    return enrich_batch(records)

def generate_lateral_movement_scan(infected_ip: str = "10.0.2.100", target_server: str = "10.1.5.20") -> List[Dict[str, Any]]:
    """Simulates internal reconnaissance and lateral movement hitting sensitive management ports."""
    records = []
    now = time.time()
    sensitive_ports = [445, 3389, 22, 5985, 135, 7001, 8080, 8443, 9092, 6379, 3306, 5432, 21, 23, 25, 110, 143, 389, 636, 1433, 1521, 2049, 2375, 2376, 5000, 5432, 5672, 8000, 8008, 8888, 9200, 9300, 11211, 27017]

    for port in sensitive_ports:
        records.append({
            "exporter_ip": "10.0.0.2",
            "version": 9,
            "timestamp": int(now - random.uniform(0, 120)),
            "src_ip": infected_ip,
            "dst_ip": target_server,
            "next_hop": "10.254.254.2",
            "src_port": random.randint(40000, 60000),
            "dst_port": port,
            "protocol": 6,
            "tcp_flags": 2, # SYN probe
            "tos": 0,
            "dscp": 0,
            "in_ifindex": 3,
            "out_ifindex": 4,
            "packets": 5,
            "bytes": 5 * 64,
            "raw_packets": 1,
            "raw_bytes": 64,
            "sampling_rate": 1,
            "src_as": 64512,
            "dst_as": 64513,
            "duration_ms": 5
        })

    return enrich_batch(records)

def inject_attacks_into_storage(storage):
    print("Simulating active DDoS and Lateral Movement attacks...")
    syn_flows = generate_syn_flood_attack()
    dns_flows = generate_dns_amplification_attack()
    lat_flows = generate_lateral_movement_scan()
    
    total = storage.insert_flows(syn_flows + dns_flows + lat_flows)
    print(f"Injected {total} attack flows into storage.")

def generate_custom_attack_flows(
    target_ip: str = "10.0.1.50",
    protocol: str = "TCP_SYN",
    target_port: int = 443,
    multiplier: float = 1.0
) -> List[Dict[str, Any]]:
    """
    Generates tailored cyber threat & DDoS attack flows against any user-specified IP address
    and protocol (TCP SYN Flood, UDP DNS Amp, UDP NTP Amp, ICMP Flood, HTTP L7, Lateral Scan).
    """
    records = []
    now = time.time()
    count = int(250 * multiplier)
    
    # Spoofed internet IPs from Tier-1 transit providers
    spoofed_sources = [
        f"{random.randint(11, 199)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        for _ in range(50)
    ]
    asn_pool = [3356, 1299, 174, 2914, 6939, 3257]
    proto_upper = protocol.upper()

    if "SYN" in proto_upper or proto_upper == "TCP":
        for _ in range(count):
            src = random.choice(spoofed_sources)
            pkts = int(random.randint(5000, 10000) * multiplier)
            records.append({
                "exporter_ip": "10.0.0.1",
                "version": 9,
                "timestamp": int(now - random.uniform(0, 3)),
                "src_ip": src,
                "dst_ip": target_ip,
                "next_hop": "10.254.254.1",
                "src_port": random.randint(1024, 65535),
                "dst_port": target_port or 443,
                "protocol": 6,
                "tcp_flags": 2, # Naked SYN probe
                "tos": 0,
                "dscp": 0,
                "in_ifindex": 1,
                "out_ifindex": 2,
                "packets": pkts,
                "bytes": pkts * 64, # Small 64-byte SYN probe
                "raw_packets": int(pkts / 100),
                "raw_bytes": int((pkts * 64) / 100),
                "sampling_rate": 1000,
                "src_as": random.choice(asn_pool),
                "dst_as": 64512,
                "duration_ms": 10
            })

    elif "DNS" in proto_upper:
        open_resolvers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "104.16.132.229", "9.9.9.9", "208.67.222.222"]
        for _ in range(count):
            res_ip = random.choice(open_resolvers)
            pkts = int(random.randint(4000, 8000) * multiplier)
            records.append({
                "exporter_ip": "10.0.0.1",
                "version": 9,
                "timestamp": int(now - random.uniform(0, 3)),
                "src_ip": res_ip,
                "dst_ip": target_ip,
                "next_hop": "10.254.254.1",
                "src_port": 53, # DNS server
                "dst_port": target_port or random.randint(1024, 65535),
                "protocol": 17,
                "tcp_flags": 0,
                "tos": 0,
                "dscp": 0,
                "in_ifindex": 1,
                "out_ifindex": 2,
                "packets": pkts,
                "bytes": pkts * 1420, # Large 1420-byte amplified responses
                "raw_packets": int(pkts / 100),
                "raw_bytes": int((pkts * 1420) / 100),
                "sampling_rate": 1000,
                "src_as": 15169,
                "dst_as": 64512,
                "duration_ms": 15
            })

    elif "NTP" in proto_upper:
        ntp_servers = ["129.6.15.28", "132.163.96.1", "216.239.35.0", "17.253.34.253"]
        for _ in range(count):
            srv_ip = random.choice(ntp_servers)
            pkts = int(random.randint(3500, 7000) * multiplier)
            records.append({
                "exporter_ip": "10.0.0.1",
                "version": 9,
                "timestamp": int(now - random.uniform(0, 3)),
                "src_ip": srv_ip,
                "dst_ip": target_ip,
                "next_hop": "10.254.254.1",
                "src_port": 123, # NTP Monlist
                "dst_port": target_port or random.randint(1024, 65535),
                "protocol": 17,
                "tcp_flags": 0,
                "tos": 0,
                "dscp": 0,
                "in_ifindex": 1,
                "out_ifindex": 2,
                "packets": pkts,
                "bytes": pkts * 850,
                "raw_packets": int(pkts / 100),
                "raw_bytes": int((pkts * 850) / 100),
                "sampling_rate": 1000,
                "src_as": random.choice(asn_pool),
                "dst_as": 64512,
                "duration_ms": 15
            })

    elif "ICMP" in proto_upper:
        for _ in range(count):
            src = random.choice(spoofed_sources)
            pkts = int(random.randint(3500, 7500) * multiplier)
            records.append({
                "exporter_ip": "10.0.0.1",
                "version": 9,
                "timestamp": int(now - random.uniform(0, 3)),
                "src_ip": src,
                "dst_ip": target_ip,
                "next_hop": "10.254.254.1",
                "src_port": 0,
                "dst_port": 0,
                "protocol": 1, # ICMP
                "tcp_flags": 0,
                "tos": 0,
                "dscp": 0,
                "in_ifindex": 1,
                "out_ifindex": 2,
                "packets": pkts,
                "bytes": pkts * 128,
                "raw_packets": int(pkts / 100),
                "raw_bytes": int((pkts * 128) / 100),
                "sampling_rate": 1000,
                "src_as": random.choice(asn_pool),
                "dst_as": 64512,
                "duration_ms": 10
            })

    elif "HTTP" in proto_upper:
        for _ in range(count):
            src = random.choice(spoofed_sources)
            pkts = int(random.randint(3000, 6000) * multiplier)
            records.append({
                "exporter_ip": "10.0.0.1",
                "version": 9,
                "timestamp": int(now - random.uniform(0, 3)),
                "src_ip": src,
                "dst_ip": target_ip,
                "next_hop": "10.254.254.1",
                "src_port": random.randint(1024, 65535),
                "dst_port": target_port or 80,
                "protocol": 6,
                "tcp_flags": 16, # ACK/Data
                "tos": 0,
                "dscp": 0,
                "in_ifindex": 1,
                "out_ifindex": 2,
                "packets": pkts,
                "bytes": pkts * 800, # HTTP GET Flood
                "raw_packets": int(pkts / 100),
                "raw_bytes": int((pkts * 800) / 100),
                "sampling_rate": 1000,
                "src_as": random.choice(asn_pool),
                "dst_as": 64512,
                "duration_ms": 25
            })

    elif "LATERAL" in proto_upper:
        sensitive_ports = [445, 3389, 22, 5985, 135, 7001, 8080, 9092, 6379, 3306, 5432, 21, 23, 25, 110, 143, 389, 636, 1433, 1521, 2049, 2375]
        for port in sensitive_ports:
            records.append({
                "exporter_ip": "10.0.0.2",
                "version": 9,
                "timestamp": int(now - random.uniform(0, 3)),
                "src_ip": "10.0.2.100",
                "dst_ip": target_ip,
                "next_hop": "10.254.254.2",
                "src_port": random.randint(40000, 60000),
                "dst_port": port,
                "protocol": 6,
                "tcp_flags": 2,
                "tos": 0,
                "dscp": 0,
                "in_ifindex": 3,
                "out_ifindex": 4,
                "packets": 15,
                "bytes": 15 * 64,
                "raw_packets": 2,
                "raw_bytes": 128,
                "sampling_rate": 1,
                "src_as": 64512,
                "dst_as": 64513,
                "duration_ms": 5
            })

    else: # COMBINED
        syn_records = generate_custom_attack_flows(target_ip, "TCP_SYN", target_port, multiplier * 0.5)
        dns_records = generate_custom_attack_flows(target_ip, "UDP_DNS", target_port, multiplier * 0.5)
        lat_records = generate_custom_attack_flows(target_ip, "LATERAL", target_port, 1.0)
        return syn_records + dns_records + lat_records

    return enrich_batch(records)

class AttackCampaignController:
    """
    Manages ongoing simulated attack campaigns with start/stop toggling,
    rate measurement, and live telemetry broadcast.
    """
    def __init__(self):
        self.is_active = False
        self.target_ip = "10.0.1.50"
        self.protocol = "TCP_SYN"
        self.target_port = 443
        self.intensity = "high"
        self.started_at = 0.0
        self.total_packets = 0
        self.total_bytes = 0
        self.current_mbps = 0.0
        self.current_pps = 0
        self.batches_sent = 0
        self.campaign_id = None

    def start_attack(self, target_ip: str, protocol: str, target_port: int = None, intensity: str = "high") -> Dict[str, Any]:
        self.target_ip = target_ip.strip() if target_ip else "10.0.1.50"
        self.protocol = (protocol or "TCP_SYN").upper()
        if target_port and str(target_port).isdigit():
            self.target_port = int(target_port)
        else:
            if "DNS" in self.protocol:
                self.target_port = 53
            elif "NTP" in self.protocol:
                self.target_port = 123
            elif "HTTP" in self.protocol:
                self.target_port = 80
            elif "LATERAL" in self.protocol:
                self.target_port = 445
            elif "ICMP" in self.protocol:
                self.target_port = 0
            else:
                self.target_port = 443

        self.intensity = intensity.lower() if intensity else "high"
        self.is_active = True
        self.started_at = time.time()
        self.total_packets = 0
        self.total_bytes = 0
        self.batches_sent = 0
        self.campaign_id = f"atk-{int(self.started_at)}"
        return self.get_status()

    def stop_attack(self) -> Dict[str, Any]:
        self.is_active = False
        self.current_mbps = 0.0
        self.current_pps = 0
        return self.get_status()

    def get_status(self) -> Dict[str, Any]:
        elapsed = round(time.time() - self.started_at, 1) if self.is_active and self.started_at > 0 else 0
        return {
            "active": self.is_active,
            "campaign_id": self.campaign_id,
            "target_ip": self.target_ip,
            "protocol": self.protocol,
            "target_port": self.target_port,
            "intensity": self.intensity,
            "elapsed_seconds": elapsed,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "current_mbps": self.current_mbps,
            "current_pps": self.current_pps,
            "batches_sent": self.batches_sent
        }

    def generate_next_batch(self) -> List[Dict[str, Any]]:
        if not self.is_active:
            return []
        
        multiplier = 1.0
        if self.intensity == "medium":
            multiplier = 0.5
        elif self.intensity == "extreme":
            multiplier = 3.0

        records = generate_custom_attack_flows(
            target_ip=self.target_ip,
            protocol=self.protocol,
            target_port=self.target_port,
            multiplier=multiplier
        )

        batch_packets = sum(r.get("packets", 0) for r in records)
        batch_bytes = sum(r.get("bytes", 0) for r in records)
        self.total_packets += batch_packets
        self.total_bytes += batch_bytes
        self.batches_sent += 1

        self.current_mbps = round((batch_bytes * 8.0) / (2.0 * 1000000.0), 2)
        self.current_pps = int(batch_packets / 2.0)

        return records

attack_controller = AttackCampaignController()
