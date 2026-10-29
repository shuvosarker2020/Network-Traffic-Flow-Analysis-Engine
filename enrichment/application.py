"""
Application & QoS / DSCP Classifier for AegisFlow
Maps L4 port and protocol to high-level applications (NBAR / Layer 7 classification) and DSCP priority classes.
"""

# Well-known Application Mapping
PORT_MAP = {
    80: ("HTTP", "Web"),
    443: ("HTTPS / TLS", "Web / Secure"),
    53: ("DNS", "Network Infrastructure"),
    22: ("SSH", "Management"),
    23: ("Telnet", "Management"),
    179: ("BGP", "Routing Protocol"),
    123: ("NTP", "Network Infrastructure"),
    161: ("SNMP", "Management"),
    162: ("SNMP-Trap", "Management"),
    5060: ("SIP / VoIP", "Voice & Video"),
    5061: ("SIP-TLS", "Voice & Video"),
    853: ("DNS over TLS", "Network Infrastructure"),
    8443: ("HTTPS-Alt", "Web / Secure"),
    8080: ("HTTP-Proxy", "Web"),
    9092: ("Apache Kafka", "Streaming / Messaging"),
    6379: ("Redis", "Database / Cache"),
    5432: ("PostgreSQL", "Database"),
    3306: ("MySQL", "Database"),
    27017: ("MongoDB", "Database"),
    6443: ("Kubernetes API", "Cloud / Container"),
    51820: ("WireGuard VPN", "VPN / Tunnel"),
    1194: ("OpenVPN", "VPN / Tunnel"),
    4500: ("IPsec NAT-T", "VPN / Tunnel"),
    500: ("IPsec IKE", "VPN / Tunnel"),
}

# DSCP / QoS class mappings
DSCP_MAP = {
    0: ("CS0 / Best Effort", "Normal"),
    8: ("CS1 / Low Priority", "Background"),
    10: ("AF11", "Bulk Data"),
    12: ("AF12", "Bulk Data"),
    14: ("AF13", "Bulk Data"),
    16: ("CS2 / OAM", "Network Management"),
    18: ("AF21", "Transactional Data"),
    20: ("AF22", "Transactional Data"),
    22: ("AF23", "Transactional Data"),
    24: ("CS3 / Broadcast", "Signaling"),
    26: ("AF31", "Call Signaling"),
    28: ("AF32", "Call Signaling"),
    30: ("AF33", "Call Signaling"),
    32: ("CS4 / Realtime", "Video"),
    34: ("AF41", "Interactive Video"),
    36: ("AF42", "Interactive Video"),
    38: ("AF43", "Interactive Video"),
    40: ("CS5 / Voice Broadcast", "Streaming"),
    46: ("EF / Expedited Forwarding", "Voice / Telephony"),
    48: ("CS6 / Routing", "Network Control / BGP/OSPF"),
    56: ("CS7 / Reserved", "Reserved")
}

def classify_application(protocol: int, src_port: int, dst_port: int) -> tuple[str, str]:
    """Returns (Application_Name, Category)."""
    # UDP 443 is often QUIC / HTTP3
    if protocol == 17 and (src_port == 443 or dst_port == 443):
        return ("QUIC / HTTP3", "Web / Streaming")

    # Check dst_port first (server port)
    if dst_port in PORT_MAP:
        return PORT_MAP[dst_port]
    # Check src_port (reverse return flow)
    if src_port in PORT_MAP:
        return PORT_MAP[src_port]

    # RTP dynamic range
    if protocol == 17 and (10000 <= src_port <= 20000 or 10000 <= dst_port <= 20000):
        return ("RTP Audio/Video", "Voice & Video")

    # Generic protocol identification
    if protocol == 6:
        return (f"TCP/{dst_port}", "Generic TCP")
    elif protocol == 17:
        return (f"UDP/{dst_port}", "Generic UDP")
    elif protocol == 1:
        return ("ICMP", "Network Infrastructure")
    elif protocol == 47:
        return ("GRE", "Tunnel")
    elif protocol == 50:
        return ("ESP / IPsec", "VPN / Tunnel")
    else:
        return (f"IP-Proto-{protocol}", "Other")

def classify_dscp(dscp_val: int) -> tuple[str, str]:
    """Returns (DSCP_Name, Traffic_Class)."""
    return DSCP_MAP.get(dscp_val, (f"DSCP-{dscp_val}", "Unassigned"))
