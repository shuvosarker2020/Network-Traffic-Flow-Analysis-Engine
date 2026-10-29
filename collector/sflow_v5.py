"""
sFlow v5 Parser for AegisFlow
RFC 3176 & sFlow v5 specification compliant parser for Arista, Juniper, Cisco Nexus, Huawei, and Linux host-sflow.
"""

import socket
import struct
import time
from typing import Dict, Any, List, Tuple

HEADER_FORMAT = "!II" # version, agent_address_type

def parse_sflow_v5(data: bytes, exporter_ip: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Parses sFlow v5 datagram, decodes flow samples (raw packet headers) and counters.
    """
    if len(data) < 28:
        return {}, []

    offset = 0
    version, addr_type = struct.unpack_from("!II", data, offset)
    offset += 8

    if version != 5:
        return {}, []

    if addr_type == 1: # IPv4
        agent_ip = socket.inet_ntoa(data[offset:offset+4])
        offset += 4
    elif addr_type == 2: # IPv6
        agent_ip = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
        offset += 16
    else:
        agent_ip = exporter_ip

    sub_agent_id, seq_no, sys_uptime, num_samples = struct.unpack_from("!IIII", data, offset)
    offset += 16

    header = {
        "version": 5,
        "agent_ip": agent_ip,
        "sub_agent_id": sub_agent_id,
        "seq_no": seq_no,
        "sys_uptime": sys_uptime,
        "num_samples": num_samples,
        "exporter_ip": exporter_ip
    }

    records = []
    now_ts = int(time.time())

    for _ in range(num_samples):
        if offset + 8 > len(data):
            break

        sample_type, sample_len = struct.unpack_from("!II", data, offset)
        offset += 8

        if offset + sample_len > len(data):
            break

        sample_data = data[offset : offset + sample_len]
        offset += sample_len

        # Standard Flow Sample (type=1) or Expanded Flow Sample (type=3)
        if sample_type in (1, 3):
            s_offset = 0
            if sample_type == 1:
                seq, src_id, sampling_rate, sample_pool, drops, in_if, out_if, num_records = struct.unpack_from(
                    "!IIIIIIII", sample_data, s_offset
                )
                s_offset += 32
            else: # Expanded flow sample
                seq, src_type, src_index, sampling_rate, sample_pool, drops, in_fmt, in_if, out_fmt, out_if, num_records = struct.unpack_from(
                    "!IIIIIIIIIII", sample_data, s_offset
                )
                s_offset += 44

            if sampling_rate <= 0:
                sampling_rate = 1

            for _ in range(num_records):
                if s_offset + 8 > len(sample_data):
                    break

                rec_format, rec_len = struct.unpack_from("!II", sample_data, s_offset)
                s_offset += 8

                if s_offset + rec_len > len(sample_data):
                    break

                rec_data = sample_data[s_offset : s_offset + rec_len]
                s_offset += rec_len

                # Format 1: Raw Packet Header
                if rec_format == 1 and len(rec_data) >= 16:
                    pkt_header_protocol, frame_len, stripped, hdr_size = struct.unpack_from("!IIII", rec_data, 0)
                    hdr_bytes = rec_data[16 : 16 + hdr_size]

                    # Decode Ethernet Header (14 bytes)
                    if len(hdr_bytes) >= 14:
                        eth_proto = struct.unpack("!H", hdr_bytes[12:14])[0]
                        ip_offset = 14
                        if eth_proto == 0x8100: # 802.1Q VLAN
                            eth_proto = struct.unpack("!H", hdr_bytes[16:18])[0]
                            ip_offset = 18

                        # IPv4 (0x0800)
                        if eth_proto == 0x0800 and len(hdr_bytes) >= ip_offset + 20:
                            ip_hdr = hdr_bytes[ip_offset : ip_offset + 20]
                            ver_ihl = ip_hdr[0]
                            ihl = (ver_ihl & 0x0F) * 4
                            tos = ip_hdr[1]
                            dscp = (tos >> 2) & 0x3F
                            total_length = struct.unpack("!H", ip_hdr[2:4])[0]
                            protocol = ip_hdr[9]
                            src_ip = socket.inet_ntoa(ip_hdr[12:16])
                            dst_ip = socket.inet_ntoa(ip_hdr[16:20])

                            src_port = 0
                            dst_port = 0
                            tcp_flags = 0

                            l4_offset = ip_offset + ihl
                            if protocol == 6 and len(hdr_bytes) >= l4_offset + 14: # TCP
                                src_port, dst_port = struct.unpack("!HH", hdr_bytes[l4_offset:l4_offset+4])
                                tcp_flags = hdr_bytes[l4_offset + 13]
                            elif protocol == 17 and len(hdr_bytes) >= l4_offset + 4: # UDP
                                src_port, dst_port = struct.unpack("!HH", hdr_bytes[l4_offset:l4_offset+4])

                            # sFlow accounting: 1 sampled packet represents `sampling_rate` packets
                            scaled_bytes = frame_len * sampling_rate
                            scaled_packets = 1 * sampling_rate

                            records.append({
                                "exporter_ip": agent_ip,
                                "version": 50, # sFlow v5 indicator
                                "timestamp": now_ts,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "next_hop": "0.0.0.0",
                                "src_port": src_port,
                                "dst_port": dst_port,
                                "protocol": protocol,
                                "tcp_flags": tcp_flags,
                                "tos": tos,
                                "dscp": dscp,
                                "in_ifindex": in_if,
                                "out_ifindex": out_if,
                                "packets": scaled_packets,
                                "bytes": scaled_bytes,
                                "raw_packets": 1,
                                "raw_bytes": frame_len,
                                "sampling_rate": sampling_rate,
                                "src_as": 0,
                                "dst_as": 0,
                                "duration_ms": 0
                            })

    return header, records
