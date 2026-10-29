# Carrier-Grade Air-Gap Deployment Checklist

Use this checklist prior to commissioning or auditing any AegisFlow installation in critical infrastructure, defense networks, financial institutions, or on-premise carrier datacenters.

---

## Phase 1: Host System & OS Hardening

- [ ] **Dedicated Management VLAN**: The host OS management interface is attached to an isolated, non-routable OAM VLAN.
- [ ] **Default Route Nullification / Strict Firewall**: The default gateway either does not have public internet transit or has strict egress firewall rules dropping all non-internal outbound SYN/UDP packets.
- [ ] **DNS Resolver Isolation**: The system's `/etc/resolv.conf` (or Windows DNS settings) points exclusively to an internal authoritative DNS server; all public resolvers (e.g. `8.8.8.8`, `1.1.1.1`) are blocked at the perimeter.
- [ ] **NTP Synchronization**: Host time is synced via internal Stratum-1/2 NTP servers inside the management network; no external pool lookups.

---

## Phase 2: AegisFlow Service Configuration

- [ ] **Local Interface Binding**:
  - In `config/config.yaml`, ensure `server.host` is configured to `127.0.0.1` (if accessed via reverse proxy / SSH tunnel) or a private RFC 1918 address (e.g., `10.254.10.15`).
- [ ] **Flow Listeners Verification**:
  - Ports `UDP 2055`, `2056`, `4739`, and `6343` are configured as ingress-only. Monitored routers and switches stream flow telemetry to these ports; the listeners never send response packets back.
- [ ] **Alerting & Webhook Destination Validation**:
  - `alerting.dispatch_webhook` and `reports/notifier.py` target exclusively RFC 1918 internal subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or `localhost`.
  - External notification services (public Slack, public Discord, external email relays) are disabled unless routed through an internal security gateway.
- [ ] **Local Disk Spooling**:
  - Automated executive reports are stored locally in `reports/spool/` with restricted filesystem permissions (`chmod 700`).

---

## Phase 3: Storage & Cryptographic Hardening

- [ ] **Storage Encryption at Rest**:
  - The `data/` directory (housing `aegisflow.duckdb` or ClickHouse data roots) resides on an encrypted volume (LUKS on Linux, BitLocker on Windows).
- [ ] **Retention TTL Policy**:
  - `retention_days` is configured (default: 90 days). Older partition chunks are automatically purged by DuckDB / ClickHouse `TTL` expressions to prevent unbounded accumulation.
- [ ] **Access Control**:
  - Read access to the database files is restricted to the specific service account running the AegisFlow daemon.

---

## Phase 4: UI & Frontend Air-Gap Verification

- [ ] **Offline Frontend Assets**:
  - Run `python .agents/skills/server-data-isolation/scripts/vendor_frontend_assets.py --mode audit` to confirm that all JavaScript libraries (ECharts, Leaflet, Tailwind) and stylesheets are served from local disk (`ui/vendor/`) with 0 external CDN requests.

---

## Phase 5: Verification & Compliance Sign-Off

- [ ] Execute `python .agents/skills/server-data-isolation/scripts/verify_network_isolation.py` and achieve a **PASS** result across all categories.
- [ ] Run network socket inspection (`ss -tupn` or `netstat -ano`) to verify no outbound ESTABLISHED connections to non-RFC1918 IPs exist.
- [ ] Ensure that before any diagnostic or log bundle is extracted, `sanitize_telemetry_logs.py` has been executed to scrub production IP addresses and router credentials.
