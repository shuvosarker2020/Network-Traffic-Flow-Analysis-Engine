"""
IPFIX (RFC 7011 / 7012) Parser for AegisFlow
High-throughput parser for Nokia TiMOS cflowd, Juniper J-Flow IPFIX, Cisco IPFIX, and Huawei.
"""

import socket
import struct
import time
from typing import Dict, Any, List, Tuple

# Standard IPFIX Information Elements
IPFIX_OCTET_DELTA_COUNT = 1
IPFIX_PACKET_DELTA_COUNT = 2
IPFIX_PROTOCOL_IDENTIFIER = 4
IPFIX_IP_CLASS_OF_SERVICE = 5
IPFIX_TCP_CONTROL_BITS = 6
IPFIX_SOURCE_TRANSPORT_PORT = 7
IPFIX_SOURCE_IPV4_ADDRESS = 8
IPFIX_SOURCE_IPV4_PREFIX_LENGTH = 9
IPFIX_INGRESS_INTERFACE = 10
IPFIX_DESTINATION_TRANSPORT_PORT = 11
IPFIX_DESTINATION_IPV4_ADDRESS = 12
IPFIX_DESTINATION_IPV4_PREFIX_LENGTH = 13
IPFIX_EGRESS_INTERFACE = 14
IPFIX_IP_NEXT_HOP_IPV4_ADDRESS = 15
IPFIX_BGP_SOURCE_AS_NUMBER = 16
IPFIX_BGP_DESTINATION_AS_NUMBER = 17
IPFIX_FLOW_START_MILLISECONDS = 152
IPFIX_FLOW_END_MILLISECONDS = 153

class IPFIXTemplateStore:
    def __init__(self):
        # Key: (exporter_ip, observation_domain_id, template_id) -> list of (element_id, length, enterprise_number)
        self.templates: Dict[Tuple[str, int, int], List[Tuple[int, int, int]]] = {}

    def add_template(self, exporter_ip: str, domain_id: int, template_id: int, elements: List[Tuple[int, int, int]]):
        self.templates[(exporter_ip, domain_id, template_id)] = elements

    def get_template(self, exporter_ip: str, domain_id: int, template_id: int):
        return self.templates.get((exporter_ip, domain_id, template_id))

ipfix_store = IPFIXTemplateStore()

HEADER_FORMAT = "!HHIII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def parse_ipfix(data: bytes, exporter_ip: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Parses IPFIX message, manages enterprise templates, and decodes records.
    """
    if len(data) < HEADER_SIZE:
        return {}, []

    version, total_len, export_time, seq_no, domain_id = struct.unpack_from(HEADER_FORMAT, data, 0)
    if version != 10:
        return {}, []

    header = {
        "version": 10,
        "total_len": total_len,
        "export_time": export_time,
        "seq_no": seq_no,
        "observation_domain_id": domain_id,
        "exporter_ip": exporter_ip
    }

    records = []
    offset = HEADER_SIZE

    while offset + 4 <= len(data) and offset < total_len:
        set_id, set_length = struct.unpack_from("!HH", data, offset)
        if set_length < 4 or offset + set_length > len(data):
            break

        set_data = data[offset + 4 : offset + set_length]

        if set_id == 2:
            # Template Set
            s_offset = 0
            while s_offset + 4 <= len(set_data):
                tmpl_id, field_count = struct.unpack_from("!HH", set_data, s_offset)
                s_offset += 4
                elements = []
                for _ in range(field_count):
                    if s_offset + 4 > len(set_data):
                        break
                    ie_id, ie_len = struct.unpack_from("!HH", set_data, s_offset)
                    s_offset += 4
                    enterprise_num = 0
                    if (ie_id & 0x8000) != 0:
                        # Enterprise bit set
                        ie_id = ie_id & 0x7FFF
                        if s_offset + 4 <= len(set_data):
                            enterprise_num = struct.unpack_from("!I", set_data, s_offset)[0]
                            s_offset += 4
                    elements.append((ie_id, ie_len, enterprise_num))
                ipfix_store.add_template(exporter_ip, domain_id, tmpl_id, elements)

        elif set_id >= 256:
            # Data Set
            tmpl = ipfix_store.get_template(exporter_ip, domain_id, set_id)
            if tmpl:
                rec_len = sum(e[1] for e in tmpl)
                if rec_len > 0:
                    s_offset = 0
                    while s_offset + rec_len <= len(set_data):
                        rec = {
                            "exporter_ip": exporter_ip,
                            "version": 10,
                            "timestamp": export_time if export_time > 0 else int(time.time()),
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

                        curr = s_offset
                        for ie_id, ie_len, ent in tmpl:
                            chunk = set_data[curr : curr + ie_len]
                            curr += ie_len

                            if ie_id == IPFIX_SOURCE_IPV4_ADDRESS and ie_len == 4:
                                rec["src_ip"] = socket.inet_ntoa(chunk)
                            elif ie_id == IPFIX_DESTINATION_IPV4_ADDRESS and ie_len == 4:
                                rec["dst_ip"] = socket.inet_ntoa(chunk)
                            elif ie_id == IPFIX_IP_NEXT_HOP_IPV4_ADDRESS and ie_len == 4:
                                rec["next_hop"] = socket.inet_ntoa(chunk)
                            elif ie_id == IPFIX_SOURCE_TRANSPORT_PORT and ie_len == 2:
                                rec["src_port"] = struct.unpack("!H", chunk)[0]
                            elif ie_id == IPFIX_DESTINATION_TRANSPORT_PORT and ie_len == 2:
                                rec["dst_port"] = struct.unpack("!H", chunk)[0]
                            elif ie_id == IPFIX_PROTOCOL_IDENTIFIER and ie_len == 1:
                                rec["protocol"] = chunk[0]
                            elif ie_id == IPFIX_IP_CLASS_OF_SERVICE and ie_len == 1:
                                rec["tos"] = chunk[0]
                                rec["dscp"] = (chunk[0] >> 2) & 0x3F
                            elif ie_id == IPFIX_TCP_CONTROL_BITS and ie_len >= 1:
                                rec["tcp_flags"] = chunk[0]
                            elif ie_id == IPFIX_INGRESS_INTERFACE:
                                rec["in_ifindex"] = int.from_bytes(chunk, "big")
                            elif ie_id == IPFIX_EGRESS_INTERFACE:
                                rec["out_ifindex"] = int.from_bytes(chunk, "big")
                            elif ie_id == IPFIX_OCTET_DELTA_COUNT:
                                val = int.from_bytes(chunk, "big")
                                rec["raw_bytes"] = val
                                rec["bytes"] = val
                            elif ie_id == IPFIX_PACKET_DELTA_COUNT:
                                val = int.from_bytes(chunk, "big")
                                rec["raw_packets"] = val
                                rec["packets"] = val
                            elif ie_id == IPFIX_BGP_SOURCE_AS_NUMBER:
                                rec["src_as"] = int.from_bytes(chunk, "big")
                            elif ie_id == IPFIX_BGP_DESTINATION_AS_NUMBER:
                                rec["dst_as"] = int.from_bytes(chunk, "big")

                        records.append(rec)
                        s_offset += rec_len

        offset += set_length

    return header, records
