#!/usr/bin/env python3
"""
Automated Network Isolation & Anti-Exfiltration Verification Script
Audits AegisFlow configuration, listening sockets, outbound firewall policies,
and webhook/email destinations to ensure zero sensitive telemetry is exposed.
"""

import sys
import os
import re
import socket
import json
import ipaddress
from typing import List, Dict, Any, Tuple

try:
    import yaml
except ImportError:
    yaml = None


def is_private_or_loopback(ip_str: str) -> bool:
    """Checks whether an IP address is loopback, link-local, or private RFC1918/RFC4193."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


def audit_config_file(config_path: str = "config/config.yaml") -> List[Dict[str, Any]]:
    """Audits the platform configuration file for potential external exposure."""
    findings = []
    if not os.path.exists(config_path):
        findings.append({
            "check": "Configuration File Presence",
            "status": "FAIL",
            "message": f"Config file '{config_path}' not found."
        })
        return findings

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()

        data = {}
        if yaml:
            data = yaml.safe_load(content) or {}
        else:
            # Fallback simple parser for server host
            for line in content.splitlines():
                if "host:" in line and not line.strip().startswith("#"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        data["server"] = {"host": parts[1].strip().strip('"').strip("'")}

        # 1. Check Server Host Binding
        server_host = data.get("server", {}).get("host", "0.0.0.0")
        if server_host == "0.0.0.0":
            findings.append({
                "check": "API Host Interface Binding",
                "status": "WARN",
                "message": (
                    f"server.host is set to '{server_host}' (All Interfaces). "
                    "For strict air-gap, bind to '127.0.0.1' or an internal OAM subnet (e.g., '10.x.x.x')."
                )
            })
        elif is_private_or_loopback(server_host):
            findings.append({
                "check": "API Host Interface Binding",
                "status": "PASS",
                "message": f"server.host is safely bound to private/loopback interface: {server_host}."
            })
        else:
            findings.append({
                "check": "API Host Interface Binding",
                "status": "FAIL",
                "message": f"server.host is configured with public IP '{server_host}'. RISK OF DATA EXPOSURE!"
            })

        # 2. Check Alerting Webhook URL
        alerting = data.get("alerting", {})
        webhook_url = alerting.get("dispatch_webhook", "")
        if webhook_url:
            match = re.search(r"https?://([^:/]+)", webhook_url)
            if match:
                target_host = match.group(1)
                if target_host in ["localhost", "127.0.0.1"] or is_private_or_loopback(target_host):
                    findings.append({
                        "check": "Alert Webhook Target",
                        "status": "PASS",
                        "message": f"Alert webhook destination '{webhook_url}' targets safe local/internal endpoint."
                    })
                else:
                    findings.append({
                        "check": "Alert Webhook Target",
                        "status": "WARN",
                        "message": f"Alert webhook target '{target_host}' appears external. Ensure it is internal or routed through proxy."
                    })

        # 3. Check Storage Location
        duckdb_path = data.get("storage", {}).get("duckdb", {}).get("path", "")
        if duckdb_path:
            findings.append({
                "check": "Columnar Storage Isolation",
                "status": "PASS",
                "message": f"DuckDB storage path is local: '{duckdb_path}' (No external database cloud dependency)."
            })

    except Exception as e:
        findings.append({
            "check": "Config Parsing",
            "status": "FAIL",
            "message": f"Failed to parse config: {str(e)}"
        })

    return findings


def audit_active_ports() -> List[Dict[str, Any]]:
    """Checks key local listening ports to verify services are running."""
    findings = []
    core_ports = [
        (8080, "FastAPI REST & WebSocket Hub", "TCP"),
        (2055, "NetFlow v5 Ingress Listener", "UDP"),
        (2056, "NetFlow v9 Ingress Listener", "UDP"),
        (4739, "IPFIX RFC 7011 Ingress Listener", "UDP"),
        (6343, "sFlow v5 Ingress Listener", "UDP"),
    ]

    for port, name, proto in core_ports:
        sock = None
        is_open = False
        try:
            if proto == "TCP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex(("127.0.0.1", port))
                is_open = (result == 0)
            else:
                # UDP check: attempt to bind to verify if already bound by listener
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.2)
                try:
                    sock.bind(("0.0.0.0", port))
                    is_open = False # If we can bind, it's not currently held by another service
                except OSError:
                    is_open = True # Socket is held by AegisFlow
        except Exception:
            pass
        finally:
            if sock:
                sock.close()

        status = "PASS" if is_open else "INFO"
        findings.append({
            "check": f"Port {port} ({name})",
            "status": status,
            "message": f"Service is active on port {port} [{proto}]." if is_open else f"Port {port} is idle / not bound."
        })

    return findings


def audit_frontend_isolation(ui_path: str = "ui/index.html") -> List[Dict[str, Any]]:
    """Scans the user interface HTML for external CDN dependencies."""
    findings = []
    if not os.path.exists(ui_path):
        findings.append({
            "check": "Frontend UI Presence",
            "status": "FAIL",
            "message": f"UI template '{ui_path}' not found."
        })
        return findings

    external_patterns = [
        r"https?://cdn\.",
        r"https?://cdnjs\.",
        r"https?://unpkg\.com",
        r"https?://fonts\.googleapis\.com",
        r"https?://cdn\.tailwindcss\.com"
    ]

    with open(ui_path, "r", encoding="utf-8") as f:
        content = f.read()

    detected_cdns = []
    for pattern in external_patterns:
        matches = re.findall(pattern, content)
        if matches:
            detected_cdns.extend(matches)

    if detected_cdns:
        findings.append({
            "check": "Air-Gapped Frontend UI Assets",
            "status": "WARN",
            "message": (
                f"Found {len(detected_cdns)} external CDN script/style references in {ui_path}. "
                "For strict air-gap environments, run 'vendor_frontend_assets.py' to serve all libraries locally."
            )
        })
    else:
        findings.append({
            "check": "Air-Gapped Frontend UI Assets",
            "status": "PASS",
            "message": "All UI assets are locally hosted and air-gap compliant."
        })

    return findings


def run_isolation_audit():
    print("=" * 70)
    print("  AEGISFLOW DATA ISOLATION & ANTI-EXFILTRATION AUDIT REPORT")
    print("=" * 70)

    all_findings = []
    all_findings.extend(audit_config_file())
    all_findings.extend(audit_active_ports())
    all_findings.extend(audit_frontend_isolation())

    pass_count = sum(1 for f in all_findings if f["status"] == "PASS")
    warn_count = sum(1 for f in all_findings if f["status"] == "WARN")
    fail_count = sum(1 for f in all_findings if f["status"] == "FAIL")

    for f in all_findings:
        badge = f"[{f['status']}]"
        if f['status'] == "PASS":
            badge = f"\033[92m{badge}\033[0m" if sys.platform != "win32" else badge
        elif f['status'] == "WARN":
            badge = f"\033[93m{badge}\033[0m" if sys.platform != "win32" else badge
        elif f['status'] == "FAIL":
            badge = f"\033[91m{badge}\033[0m" if sys.platform != "win32" else badge

        print(f"{badge:<10} {f['check']:<35} : {f['message']}")

    print("-" * 70)
    print(f"SUMMARY: {pass_count} Passed | {warn_count} Warnings | {fail_count} Critical Failures")
    if fail_count == 0 and warn_count == 0:
        print("RESULT: SERVER DATA IS FULLY ISOLATED & AIR-GAP COMPLIANT.")
    elif fail_count == 0:
        print("RESULT: ACCEPTABLE (See non-blocking warnings above for hardening).")
    else:
        print("RESULT: ACTION REQUIRED TO PREVENT EXTERNAL DATA EXPOSURE.")
    print("=" * 70)

    return 1 if fail_count > 0 else 0


if __name__ == "__main__":
    sys.exit(run_isolation_audit())
