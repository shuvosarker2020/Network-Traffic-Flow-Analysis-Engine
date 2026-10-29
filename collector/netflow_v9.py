"""
NetFlow v9 Parser for AegisFlow
Template-based dynamic parser supporting Cisco IOS-XR/NX-OS, Huawei NetStream v9, and Juniper J-Flow.
"""

import socket
import struct
import time
from typing import Dict, Any, List, Tuple

# Standard Information Element IDs for NetFlow v9
FIELD_IN_BYTES = 1
FIELD_IN_PKTS = 2
FIELD_FLOWS = 3
FIELD_PROTOCOL = 4
FIELD_SRC_TOS = 5
FIELD_TCP_FLAGS = 6
FIELD_L4_SRC_PORT = 7
FIELD_IPV4_SRC_ADDR = 8
FIELD_SRC_MASK = 9
FIELD_INPUT_SNMP = 10
FIELD_L4_DST_PORT = 11
FIELD_IPV4_DST_ADDR = 12
FIELD_DST_MASK = 13
FIELD_OUTPUT_SNMP = 14
FIELD_IPV4_NEXT_HOP = 15
FIELD_SRC_AS = 16
FIELD_DST_AS = 17
FIELD_BGP_IPV4_NEXT_HOP = 18
FIELD_LAST_SWITCHED = 21
FIELD_FIRST_SWITCHED = 22
FIELD_OUT_BYTES = 23
FIELD_OUT_PKTS = 24

class NetFlowV9TemplateStore:
    def __init__(self):
        # Key: (exporter_ip, source_id, template_id) -> list of (field_type, field_length)
        self.templates: Dict[Tuple[str, int, int], List[Tuple[int, int]]] = {}

    def add_template(self, exporter_ip: str, source_id: int, template_id: int, fields: List[Tuple[int, int]]):
        self.templates[(exporter_ip, source_id, template_id)] = fields

    def get_template(self, exporter_ip: str, source_id: int, template_id: int):
        return self.templates.get((exporter_ip, source_id, template_id))

# Global template store
template_store = NetFlowV9TemplateStore()

HEADER_FORMAT = "!HHIIII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def parse_netflow_v9(data: bytes, exporter_ip: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Parses a NetFlow v9 packet, updates dynamic templates, and decodes flow data records.
    """
    if len(data) < HEADER_SIZE:
        return {}, []

    version, count, sys_uptime, unix_secs, seq_no, source_id = struct.unpack_from(HEADER_FORMAT, data, 0)
    if version != 9:
        return {}, []

    header = {
        "version": 9,
        "count": count,
        "sys_uptime": sys_uptime,
        "unix_secs": unix_secs,
        "seq_no": seq_no,
        "source_id": source_id,
        "exporter_ip": exporter_ip
    }

    records = []
    offset = HEADER_SIZE

    while offset + 4 <= len(data):
        flowset_id, flowset_len = struct.unpack_from("!HH", data, offset)
        if flowset_len < 4 or offset + flowset_len > len(data):
            break

        flowset_data = data[offset + 4 : offset + flowset_len]

        if flowset_id == 0:
            # Template FlowSet
            fs_offset = 0
            while fs_offset + 4 <= len(flowset_data):
                tmpl_id, field_count = struct.unpack_from("!HH", flowset_data, fs_offset)
                fs_offset += 4
                fields = []
                for _ in range(field_count):
                    if fs_offset + 4 > len(flowset_data):
                        break
                    f_type, f_len = struct.unpack_from("!HH", flowset_data, fs_offset)
                    fields.append((f_type, f_len))
                    fs_offset += 4
                template_store.add_template(exporter_ip, source_id, tmpl_id, fields)

        elif flowset_id == 1:
            # Options Template FlowSet (skipped for basic flow telemetry)
            pass

        elif flowset_id >= 256:
            # Data FlowSet
            tmpl = template_store.get_template(exporter_ip, source_id, flowset_id)
            if tmpl:
                rec_len = sum(f[1] for f in tmpl)
                if rec_len > 0:
                    fs_offset = 0
                    while fs_offset + rec_len <= len(flowset_data):
                        parsed_rec = {
                            "exporter_ip": exporter_ip,
                            "version": 9,
                            "timestamp": unix_secs if unix_secs > 0 else int(time.time()),
                            "src_ip": "0.0.0.0",
                            "dst_ip": "0.0.0.0",
                            "next_hop": "0.0.0.0",
                            "src_port": 0,
                            "dst_port": 0,
                            "protocol": 0,
                            "tcp_flags": 0,
                            "tos": 0,
                            "dscp": 0,
                            "in_ifindex": 0,
                            "out_ifindex": 0,
                            "packets": 0,
                            "bytes": 0,
                            "raw_packets": 0,
                            "raw_bytes": 0,
                            "sampling_rate": 1,
                            "src_as": 0,
                            "dst_as": 0,
                            "duration_ms": 0
                        }

                        curr_f_offset = fs_offset
                        for f_type, f_len in tmpl:
                            f_bytes = flowset_data[curr_f_offset : curr_f_offset + f_len]
                            curr_f_offset += f_len

                            if f_type == FIELD_IPV4_SRC_ADDR and f_len == 4:
                                parsed_rec["src_ip"] = socket.inet_ntoa(f_bytes)
                            elif f_type == FIELD_IPV4_DST_ADDR and f_len == 4:
                                parsed_rec["dst_ip"] = socket.inet_ntoa(f_bytes)
                            elif f_type == FIELD_IPV4_NEXT_HOP and f_len == 4:
                                parsed_rec["next_hop"] = socket.inet_ntoa(f_bytes)
                            elif f_type == FIELD_L4_SRC_PORT and f_len == 2:
                                parsed_rec["src_port"] = struct.unpack("!H", f_bytes)[0]
                            elif f_type == FIELD_L4_DST_PORT and f_len == 2:
                                parsed_rec["dst_port"] = struct.unpack("!H", f_bytes)[0]
                            elif f_type == FIELD_PROTOCOL and f_len == 1:
                                parsed_rec["protocol"] = f_bytes[0]
                            elif f_type == FIELD_SRC_TOS and f_len == 1:
                                parsed_rec["tos"] = f_bytes[0]
                                parsed_rec["dscp"] = (f_bytes[0] >> 2) & 0x3F
                            elif f_type == FIELD_TCP_FLAGS and f_len == 1:
                                parsed_rec["tcp_flags"] = f_bytes[0]
                            elif f_type == FIELD_INPUT_SNMP:
                                parsed_rec["in_ifindex"] = int.from_bytes(f_bytes, "big")
                            elif f_type == FIELD_OUTPUT_SNMP:
                                parsed_rec["out_ifindex"] = int.from_bytes(f_bytes, "big")
                            elif f_type == FIELD_IN_BYTES:
                                val = int.from_bytes(f_bytes, "big")
                                parsed_rec["raw_bytes"] = val
                                parsed_rec["bytes"] = val
                            elif f_type == FIELD_IN_PKTS:
                                val = int.from_bytes(f_bytes, "big")
                                parsed_rec["raw_packets"] = val
                                parsed_rec["packets"] = val
                            elif f_type == FIELD_SRC_AS:
                                parsed_rec["src_as"] = int.from_bytes(f_bytes, "big")
                            elif f_type == FIELD_DST_AS:
                                parsed_rec["dst_as"] = int.from_bytes(f_bytes, "big")

                        records.append(parsed_rec)
                        fs_offset += rec_len

        offset += flowset_len

    return header, records
