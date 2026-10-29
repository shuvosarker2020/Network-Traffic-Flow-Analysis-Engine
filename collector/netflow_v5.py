"""
NetFlow v5 Parser for AegisFlow
Standard 48-byte record parser for Cisco IOS, IOS-XE, MikroTik RouterOS, and legacy devices.
"""

import socket
import struct
from typing import List, Dict, Any, Tuple

HEADER_FORMAT = "!HHIIIIBBH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
RECORD_FORMAT = "!IIIHHIIIIHHBBBBHHBBH"
RECORD_SIZE = struct.calcsize(RECORD_FORMAT)

def parse_netflow_v5(data: bytes, exporter_ip: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Parses a binary NetFlow v5 UDP payload into normalized flow records.
    """
    if len(data) < HEADER_SIZE:
        return {}, []

    (version, count, sys_uptime, unix_secs, unix_nsecs,
     flow_sequence, engine_type, engine_id, sampling_interval) = struct.unpack_from(HEADER_FORMAT, data, 0)

    if version != 5:
        return {}, []

    sampling_rate = sampling_interval & 0x3FFF
    if sampling_rate == 0:
        sampling_rate = 1

    header = {
        "version": 5,
        "count": count,
        "sys_uptime": sys_uptime,
        "unix_secs": unix_secs,
        "flow_sequence": flow_sequence,
        "engine_type": engine_type,
        "engine_id": engine_id,
        "sampling_rate": sampling_rate,
        "exporter_ip": exporter_ip
    }

    records = []
    offset = HEADER_SIZE

    for _ in range(count):
        if offset + 48 > len(data):
            break

        (src_ip_int, dst_ip_int, next_hop_int,
         input_snmp, output_snmp,
         dpkts, doctets,
         first_switched, last_switched,
         src_port, dst_port,
         pad1, tcp_flags, prot, tos,
         src_as, dst_as,
         src_mask, dst_mask, pad2) = struct.unpack_from("!IIIHHIIIIHHBBBBHHBBH", data, offset)

        src_ip = socket.inet_ntoa(struct.pack("!I", src_ip_int))
        dst_ip = socket.inet_ntoa(struct.pack("!I", dst_ip_int))
        next_hop = socket.inet_ntoa(struct.pack("!I", next_hop_int))

        # Scale by sampling rate for true wire-rate accounting
        scaled_packets = dpkts * sampling_rate
        scaled_bytes = doctets * sampling_rate

        record = {
            "exporter_ip": exporter_ip,
            "version": 5,
            "timestamp": unix_secs,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "next_hop": next_hop,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": prot,
            "tcp_flags": tcp_flags,
            "tos": tos,
            "dscp": (tos >> 2) & 0x3F,
            "in_ifindex": input_snmp,
            "out_ifindex": output_snmp,
            "packets": scaled_packets,
            "bytes": scaled_bytes,
            "raw_packets": dpkts,
            "raw_bytes": doctets,
            "sampling_rate": sampling_rate,
            "src_as": src_as,
            "dst_as": dst_as,
            "src_mask": src_mask,
            "dst_mask": dst_mask,
            "duration_ms": max(0, last_switched - first_switched) if last_switched >= first_switched else 0
        }
        records.append(record)
        offset += 48

    return header, records
