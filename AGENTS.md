# AegisFlow Air-Gap & Zero-Exfiltration Security Mandate

## CRITICAL SECURITY DIRECTIVE: STRICT DATA ISOLATION

This repository processes carrier-grade network flow records (NetFlow, IPFIX, sFlow), router interface topologies, BGP peering agreements, and cybersecurity attack intelligence. Under NO circumstances should any project data be exposed, transmitted, or leaked outside the host server.

### 1. Mandatory Data Boundaries
- **No External Network Calls**: Never make outbound network requests, telemetry pings, or phone-home calls to third-party APIs, analytics platforms, or external cloud storage.
- **Strict Local & RFC 1918 Binding**: All REST endpoints, WebSockets, background daemons, and storage engines must bind strictly to `127.0.0.1` (loopback) or private RFC 1918 IP addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Alert & Webhook Whitelisting**: Notification dispatchers (Webhooks, SMTP) must validate destination IP addresses before issuing socket connections. Any destination resolving to a public routable IP must be blocked.
- **Local Data Storage**: All historical flow tables (DuckDB / ClickHouse) and executive reports must remain within the server's local file storage (`data/`, `reports/spool/`).

### 2. Air-Gapped UI & Asset Hosting
- In air-gapped production environments, all web assets (Tailwind CSS, FontAwesome, ECharts, Leaflet) must be served from local disk (`ui/vendor/`) rather than external CDNs.
- Run `python .agents/skills/server-data-isolation/scripts/vendor_frontend_assets.py` to audit or vendor local assets.

### 3. Log & Diagnostic Sanitization
- Prior to creating diagnostic archives or sharing logs, run `python .agents/skills/server-data-isolation/scripts/sanitize_telemetry_logs.py` to irreversibly mask customer IPs, router names, and credentials.

### 4. Verification & Auditing
- Verify system isolation at any time by executing:
  `python .agents/skills/server-data-isolation/scripts/verify_network_isolation.py`
