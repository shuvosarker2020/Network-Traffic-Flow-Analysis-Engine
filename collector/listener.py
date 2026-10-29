"""
High-Throughput Asynchronous UDP Flow Listener for AegisFlow
Listens concurrently on ports for NetFlow v5, v9, IPFIX, and sFlow.
"""

import asyncio
import logging
from typing import Callable, Optional

from collector.netflow_v5 import parse_netflow_v5
from collector.netflow_v9 import parse_netflow_v9
from collector.ipfix import parse_ipfix
from collector.sflow_v5 import parse_sflow_v5

logger = logging.getLogger("AegisFlow.Listener")

class FlowDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, proto_type: str, callback: Callable):
        super().__init__()
        self.proto_type = proto_type
        self.callback = callback
        self.transport = None
        self.packet_count = 0
        self.flow_count = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        exporter_ip = addr[0]
        self.packet_count += 1
        records = []

        try:
            if self.proto_type == "netflow_v5":
                _, records = parse_netflow_v5(data, exporter_ip)
            elif self.proto_type == "netflow_v9":
                _, records = parse_netflow_v9(data, exporter_ip)
            elif self.proto_type == "ipfix":
                _, records = parse_ipfix(data, exporter_ip)
            elif self.proto_type == "sflow":
                _, records = parse_sflow_v5(data, exporter_ip)
            elif self.proto_type == "auto":
                # Auto-detect version by inspect first 2 bytes
                if len(data) >= 2:
                    ver = int.from_bytes(data[0:2], "big")
                    if ver == 5:
                        _, records = parse_netflow_v5(data, exporter_ip)
                    elif ver == 9:
                        _, records = parse_netflow_v9(data, exporter_ip)
                    elif ver == 10:
                        _, records = parse_ipfix(data, exporter_ip)
                    elif int.from_bytes(data[0:4], "big") == 5: # sFlow v5 4-byte version
                        _, records = parse_sflow_v5(data, exporter_ip)

            if records:
                self.flow_count += len(records)
                self.callback(records)
        except Exception as e:
            logger.debug(f"Error parsing datagram from {exporter_ip}: {e}")

class FlowListenerManager:
    def __init__(self, queue: asyncio.Queue):
        self.queue = queue
        self.transports = []

    def handle_records(self, records: list):
        try:
            self.queue.put_nowait(records)
        except asyncio.QueueFull:
            logger.warning("Flow ingest queue is full! Dropping batch.")

    async def start_listeners(self, config: dict):
        loop = asyncio.get_running_loop()
        listeners_cfg = config.get("listeners", {})

        ports_to_start = [
            ("netflow_v5", listeners_cfg.get("netflow_v5", {}).get("port", 2055)),
            ("netflow_v9", listeners_cfg.get("netflow_v9", {}).get("port", 2056)),
            ("ipfix", listeners_cfg.get("ipfix", {}).get("port", 4739)),
            ("sflow", listeners_cfg.get("sflow", {}).get("port", 6343)),
        ]

        for proto_name, port in ports_to_start:
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda p=proto_name: FlowDatagramProtocol(p, self.handle_records),
                    local_addr=("0.0.0.0", port)
                )
                self.transports.append(transport)
                logger.info(f"Started {proto_name} listener on UDP port {port}")
            except Exception as e:
                logger.warning(f"Could not bind {proto_name} on UDP port {port}: {e}")

    def stop_listeners(self):
        for t in self.transports:
            t.close()
        self.transports.clear()
