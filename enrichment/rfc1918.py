"""
RFC 1918 & Flow Direction Classifier for AegisFlow
Detects East-West vs North-South flows, vital for Lateral Movement detection.
"""

import ipaddress

RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"), # Carrier-Grade NAT
    ipaddress.ip_network("127.0.0.0/8"),
]

def is_internal_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in RFC1918_NETWORKS)
    except ValueError:
        return False

def classify_flow_direction(src_ip: str, dst_ip: str) -> str:
    src_internal = is_internal_ip(src_ip)
    dst_internal = is_internal_ip(dst_ip)

    if src_internal and dst_internal:
        return "East-West (Internal)"
    elif src_internal and not dst_internal:
        return "North-South (Outbound)"
    elif not src_internal and dst_internal:
        return "North-South (Inbound)"
    else:
        return "External (Transit / Internet)"
