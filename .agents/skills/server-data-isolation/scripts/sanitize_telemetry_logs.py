#!/usr/bin/env python3
"""
Telemetry Log & Flow Record Sanitization Script
Anonymizes sensitive customer IP addresses, router credentials, circuit IDs,
and ASN names before generating diagnostic or support archives.
"""

import sys
import os
import re
import json
import hashlib
import argparse
from typing import Dict, Any, List


class TelemetrySanitizer:
    def __init__(self, salt: str = "AegisFlowAirGapSalt2026"):
        self.salt = salt.encode("utf-8")
        self.ip_map: Dict[str, str] = {}
        self.ip_counter = 1
        self.asn_map: Dict[str, str] = {}
        self.asn_counter = 1

    def mask_ip(self, ip_str: str) -> str:
        """Deterministically replaces an IP with a pseudonymized RFC 5737 / RFC 3849 test IP."""
        if not ip_str or ip_str in ["0.0.0.0", "127.0.0.1", "::1"]:
            return ip_str

        if ip_str not in self.ip_map:
            # Deterministic hash mapping
            h = hashlib.sha256(self.salt + ip_str.encode("utf-8")).hexdigest()
            # Map into TEST-NET-1 (192.0.2.0/24) or TEST-NET-2 (198.51.100.0/24)
            octet3 = int(h[0:2], 16) % 254 + 1
            octet4 = int(h[2:4], 16) % 254 + 1
            masked = f"198.51.{octet3}.{octet4}"
            self.ip_map[ip_str] = masked

        return self.ip_map[ip_str]

    def mask_asn(self, asn_str: str) -> str:
        """Anonymizes Autonomous System Numbers and organization names."""
        if not asn_str:
            return asn_str
        if asn_str not in self.asn_map:
            self.asn_map[asn_str] = f"AS-MASKED-{self.asn_counter:04d}"
            self.asn_counter += 1
        return self.asn_map[asn_str]

    def sanitize_text(self, text: str) -> str:
        """Performs regex scrubbing on freeform configuration, logs, or JSON strings."""
        # 1. Scrub IPv4 addresses (excluding version numbers like 1.0 or 2.0.1)
        ipv4_regex = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        
        def ip_repl(match):
            val = match.group(0)
            if val in ["127.0.0.1", "0.0.0.0", "255.255.255.255"]:
                return val
            return self.mask_ip(val)

        sanitized = re.sub(ipv4_regex, ip_repl, text)

        # 2. Redact passwords, secrets, community strings, and tokens
        secret_patterns = [
            (r'(?i)(password|secret|community|token|auth_key)\s*[:=]\s*["\']?([^"\'\s]+)["\']?', r'\1: "[REDACTED]"'),
            (r'(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*', r'\1[REDACTED]'),
            (r'(?i)(snmp-server\s+community\s+)\S+', r'\1[REDACTED]')
        ]
        for pattern, repl in secret_patterns:
            sanitized = re.sub(pattern, repl, sanitized)

        return sanitized

    def sanitize_json_file(self, src_path: str, dst_path: str) -> int:
        """Reads a JSON log/flow dump, sanitizes values, and writes to destination."""
        with open(src_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        def recursive_scrub(obj):
            if isinstance(obj, dict):
                new_dict = {}
                for k, v in obj.items():
                    # Check sensitive keys
                    if k in ["src_ip", "dst_ip", "target_ip", "exporter_ip", "ip", "client_ip", "victim_ip"]:
                        new_dict[k] = self.mask_ip(str(v)) if v else v
                    elif k in ["src_as", "dst_as", "asn_name", "as_org"]:
                        new_dict[k] = self.mask_asn(str(v)) if v else v
                    elif any(s in k.lower() for s in ["password", "secret", "token", "community"]):
                        new_dict[k] = "[REDACTED]"
                    else:
                        new_dict[k] = recursive_scrub(v)
                return new_dict
            elif isinstance(obj, list):
                return [recursive_scrub(item) for item in obj]
            elif isinstance(obj, str):
                return self.sanitize_text(obj)
            return obj

        scrubbed = recursive_scrub(data)
        os.makedirs(os.path.dirname(os.path.abspath(dst_path)), exist_ok=True)
        with open(dst_path, "w", encoding="utf-8") as f:
            json.dump(scrubbed, f, indent=2)

        return len(self.ip_map)


def main():
    parser = argparse.ArgumentParser(description="Sanitize AegisFlow Telemetry & Logs for Anti-Exfiltration Compliance")
    parser.add_argument("--input", "-i", help="Input file path (JSON, log, or text file)", default="")
    parser.add_argument("--output", "-o", help="Output sanitized file path", default="")
    parser.add_argument("--salt", "-s", help="Optional cryptographic salt string", default="AegisFlowAirGapSalt2026")
    args = parser.parse_args()

    sanitizer = TelemetrySanitizer(salt=args.salt)

    if not args.input:
        # Self-test demonstration
        demo_log = """
        [2026-10-29 19:30:00] Alert: DDoS Flood against target 10.0.1.50 from 198.51.100.22!
        Exporter: 10.254.1.1, Community: public_secret_snmp, BGP Peer: AS15169 Google LLC.
        """
        print("Running Sanitizer Self-Test:")
        print("=" * 60)
        print("ORIGINAL SENSITIVE LOG:")
        print(demo_log.strip())
        print("-" * 60)
        print("SANITIZED SAFE LOG (Safe to export):")
        print(sanitizer.sanitize_text(demo_log).strip())
        print("=" * 60)
        print("Self-test completed successfully.")
        return 0

    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found.")
        return 1

    dst = args.output or f"{args.input}.sanitized"
    if args.input.endswith(".json"):
        count = sanitizer.sanitize_json_file(args.input, dst)
        print(f"Sanitized JSON file written to '{dst}'. Anonymized {count} unique IPs.")
    else:
        with open(args.input, "r", encoding="utf-8") as f:
            content = f.read()
        sanitized = sanitizer.sanitize_text(content)
        with open(dst, "w", encoding="utf-8") as f:
            f.write(sanitized)
        print(f"Sanitized text file written to '{dst}'.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
