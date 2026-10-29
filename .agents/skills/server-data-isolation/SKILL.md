---
name: server-data-isolation
description: >-
  Enforces strict on-premise air-gap security, zero data exfiltration, and complete isolation
  of network flow intelligence, router configs, customer IPs, ASN peering matrices, and reports.
  Use whenever hardening deployments, auditing data boundaries, configuring alerting webhooks/SMTP,
  preparing support bundles, or verifying that no sensitive network telemetry leaves the server.
---

# Server Data Isolation & Zero-Exfiltration Security Skill

AegisFlow processes sensitive carrier-grade telemetry including router interfaces, BGP routing tables, internal IP conversations, customer bandwidth consumption, and security threat vectors. This skill provides standard operating procedures, architectural controls, and executable audit tools to guarantee that **no network information, telemetry records, topologies, configurations, or reports ever leave the host server or internal private network**.

---

## 1. Core Principles of Data Isolation

1. **Zero External Egress (Air-Gap Compliance)**:
   The flow intelligence engine is completely self-contained. It never phones home, uses no external telemetry/analytics beacons, and requires zero cloud dependencies.
2. **Strict Internal Socket Binding**:
   All management REST APIs, WebSockets, and metrics listeners must bind strictly to `127.0.0.1` (loopback) or designated internal OAM (Operations, Administration, and Maintenance) interfaces.
3. **Ingress-Only Telemetry Collectors**:
   UDP flow collection ports (2055 NetFlow v5, 2056 NetFlow v9, 4739 IPFIX, 6343 sFlow) are **unidirectional ingress listeners**. They accept incoming UDP packets from monitored network devices and never transmit traffic back or initiate outbound sockets.
4. **Internal-Only Alert & Webhook Destinations**:
   Outbound alerting (SMTP, Webhooks, Syslog) must be strictly filtered against an internal RFC 1918 CIDR whitelist (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`). Any destination resolving to a public or external IP is immediately dropped and blocked.
5. **Local Data Spooling & Zero Cloud Storage**:
   Historical flow logs, DuckDB columnar OLAP tables, ClickHouse partitions, and executive PDF/HTML reports are stored strictly on local NVMe/SSD partitions with strict operating system access controls.
6. **Air-Gapped UI Self-Hosting**:
   Web dashboards must operate 100% offline without querying external CDNs (such as cdnjs, Google Fonts, or jsdelivr) when deployed in air-gapped environments.

---

## 2. Step-by-Step Isolation Procedures

### Step 1: Run the Automated Network Isolation Audit
Execute the automated audit script to verify that no listening sockets or active TCP/UDP streams are exposed to the public internet:

```bash
python .agents/skills/server-data-isolation/scripts/verify_network_isolation.py
```
This script audits:
- All open TCP and UDP listening ports.
- Verifies that HTTP/REST API endpoints are bound to authorized internal addresses.
- Verifies that external DNS lookups for third-party trackers are blocked.
- Checks outbound connectivity to confirm egress firewall isolation.

Detailed reference: [verify_network_isolation.py](./scripts/verify_network_isolation.py)

---

### Step 2: Validate Server & Storage Configuration
Review [`config/config.yaml`](file:///d:/AI-Projects/Traffic-flow-Analysis-Engine/config/config.yaml):

1. **API Host Binding**:
   - For single-server localhost access: set `server.host: "127.0.0.1"`
   - For internal NOC jumpbox access: set `server.host: "<INTERNAL_PRIVATE_IP>"` (e.g. `10.254.1.50`)
   - Never bind to an interface with a public routable IP.
2. **Storage Isolation**:
   - Verify `storage.duckdb.path` points to a local path (e.g., `data/aegisflow.duckdb`).
   - If using ClickHouse (`storage.clickhouse`), verify the host is `127.0.0.1` or an internal cluster IP, with TLS and authentication enabled.
3. **Alerting & Webhook Whitelist**:
   - Ensure `alerting.dispatch_webhook` points to an internal receiver (`http://localhost:...` or internal SIEM).
   - Ensure `email_notifications` use an internal SMTP relay host (`host: "mail.internal.noc"` or localhost) or local disk spooling (`reports/spool/`).

---

### Step 3: Sanitize Diagnostic Bundles & Flow Logs
When exporting logs or database records for diagnostics, offline analysis, or support, always sanitize customer IPs, router names, and credentials using:

```bash
python .agents/skills/server-data-isolation/scripts/sanitize_telemetry_logs.py --input-dir data/ --output-dir data/sanitized/
```

This ensures:
- IPv4/IPv6 addresses are masked using deterministic HMAC-SHA256 (e.g. `10.0.1.50` $\rightarrow$ `10.200.x.x` or pseudonymized hashes).
- Autonomous System (ASN) names are anonymized (`AS15169 Google` $\rightarrow$ `AS-CONFIDENTIAL-01`).
- Interface descriptions containing customer identifiers, circuit IDs, and VLAN tags are stripped.
- Passwords and SNMP community strings in configuration dumps are completely redacted.

Detailed reference: [sanitize_telemetry_logs.py](./scripts/sanitize_telemetry_logs.py)

---

### Step 4: Verify Air-Gapped Frontend Asset Hosting
For high-security / air-gapped environments where the dashboard machine has zero internet access:
1. Run the asset vendoring script to package all CSS, fonts, and JS libraries locally:
   ```bash
   python .agents/skills/server-data-isolation/scripts/vendor_frontend_assets.py --mode audit
   ```
2. Verify that `ui/index.html` references local vendor directories (`ui/vendor/echarts.min.js`, `ui/vendor/leaflet.js`, etc.) instead of external public CDN URLs.

Detailed reference: [vendor_frontend_assets.py](./scripts/vendor_frontend_assets.py)

---

### Step 5: Apply Host Firewall & Kernel Egress Lockdown
To enforce cryptographic and kernel-level assurance that no packets leave the server:

- **Linux (iptables / nftables)**: Apply the rules in [firewall_and_network_hardening.md](./references/firewall_and_network_hardening.md) to block all `OUTPUT` traffic to non-RFC1918 destinations.
- **Windows Server (Windows Defender Firewall)**: Apply outbound blocking rules for the Python runtime executable to restrict egress to internal subnets only.

---

## 3. Quick Reference Matrix: Isolation Safeguards

| Component | Default Behavior | Hardened Air-Gap Enforcement |
|---|---|---|
| **NetFlow / IPFIX / sFlow Listeners** | Listens on UDP 2055, 2056, 4739, 6343 | Strict ingress-only; UDP sockets reject outbound writes. |
| **FastAPI REST API / WebSocket** | Port 8080 | Bind to `127.0.0.1` or internal management VLAN (`10.x.x.x`). |
| **DuckDB / ClickHouse Storage** | Local columnar file in `data/` | Stored on encrypted volume (BitLocker / LUKS) with 90-day automatic TTL. |
| **Executive Reports & PDF/HTML** | Generated in `reports/spool/` | Dispatched only via local spool or internal SMTP relay. |
| **Alert Webhooks** | HTTP POST to configured URL | Validates destination IP is RFC 1918 / loopback before issuing socket request. |
| **Support & Diagnostic Logs** | Raw JSON / Parquet / DuckDB | Run through `sanitize_telemetry_logs.py` to mask IPs, ASNs, and credentials. |

---

## 4. Verification & Validation Checklist

Before declaring an AegisFlow deployment isolated:
- [ ] Run `python .agents/skills/server-data-isolation/scripts/verify_network_isolation.py` and confirm 0 violations.
- [ ] Confirm no external outbound connections in `netstat -ano` or `ss -tupn`.
- [ ] Verify `alerting.dispatch_webhook` and `smtp.host` resolve strictly to RFC 1918 / loopback IPs.
- [ ] Confirm all flow storage directories (`data/`, `reports/spool/`) have restricted file permissions (`chmod 700` / Windows ACL Admin only).
- [ ] Review [airgap_deployment_checklist.md](./references/airgap_deployment_checklist.md) for full compliance sign-off.
