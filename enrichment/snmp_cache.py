"""
Device & Interface SNMP Telemetry Cache for AegisFlow
Resolves router IP and ifIndex to device hostname, vendor, site, interface name, speed, and alias.
"""

import json
import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("AegisFlow.SNMPCache")

class SNMPTelemetryCache:
    def __init__(self, devices_file: str = "config/devices.json", interfaces_file: str = "config/interfaces.json"):
        self.devices: Dict[str, Dict[str, Any]] = {}
        self.device_by_ip: Dict[str, Dict[str, Any]] = {}
        self.interfaces: Dict[str, Dict[str, Any]] = {}
        self.load_metadata(devices_file, interfaces_file)

    def load_metadata(self, devices_file: str, interfaces_file: str):
        if os.path.exists(devices_file):
            try:
                with open(devices_file, "r") as f:
                    self.devices = json.load(f)
                    for dev_id, dev in self.devices.items():
                        self.device_by_ip[dev.get("ip")] = dev
                logger.info(f"Loaded {len(self.devices)} devices into SNMP cache.")
            except Exception as e:
                logger.error(f"Failed to load devices: {e}")

        if os.path.exists(interfaces_file):
            try:
                with open(interfaces_file, "r") as f:
                    self.interfaces = json.load(f)
                logger.info(f"Loaded {len(self.interfaces)} interfaces into SNMP cache.")
            except Exception as e:
                logger.error(f"Failed to load interfaces: {e}")

    def get_device(self, exporter_ip: str) -> Optional[Dict[str, Any]]:
        dev = self.device_by_ip.get(exporter_ip)
        if not dev and exporter_ip and exporter_ip != "0.0.0.0":
            # Auto-discover and register any router streaming flows immediately
            dev_id = f"dev-{exporter_ip.replace('.', '-')}"
            new_dev = {
                "device_id": dev_id,
                "hostname": f"router-{exporter_ip}",
                "ip": exporter_ip,
                "vendor": "Auto-Discovered",
                "model": "Generic Flow Exporter",
                "role": "Edge / Core Router",
                "site": "Auto-Discovered Site",
                "city": "Unknown",
                "country": "LOCAL",
                "flow_protocol": "NetFlow / IPFIX",
                "sampling_rate": 1000,
                "status": "ONLINE"
            }
            self.devices[dev_id] = new_dev
            self.device_by_ip[exporter_ip] = new_dev
            logger.info(f"Auto-discovered and registered new flow exporter router: {exporter_ip} ({dev_id})")
            return new_dev
        return dev

    def get_interface(self, exporter_ip: str, if_index: int) -> Dict[str, Any]:
        key = f"{exporter_ip}:{if_index}"
        if key in self.interfaces:
            return self.interfaces[key]

        # Dynamic fallback for interfaces not yet explicitly declared
        dev = self.get_device(exporter_ip)
        vendor = dev.get("vendor", "Generic") if dev else "Generic"
        pfx = "ge-0/0/" if vendor == "Juniper" else ("100GE1/0/" if vendor == "Huawei" else "Gi0/0/0/")
        return {
            "device_id": dev.get("device_id", "unknown") if dev else "dev-unknown",
            "device_ip": exporter_ip,
            "if_index": if_index,
            "name": f"{pfx}{if_index}",
            "alias": f"Interface {if_index}",
            "type": "Data",
            "speed_bps": 100_000_000_000,
            "speed_readable": "100GE",
            "status": "UP",
            "site": dev.get("site", "Central DC") if dev else "Default Site"
        }

snmp_cache = SNMPTelemetryCache()
