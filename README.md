# AegisFlow | Carrier-Grade Flow Intelligence, Observability & DDoS Defense Engine

AegisFlow is a high-performance, low-resource Network Intelligence, Observability, and DDoS Detection platform inspired by **Kentik**, designed for telecom carriers, ISPs, large data centers, and multi-cloud enterprises.

It ingests, enriches, and analyzes flow telemetry across **1,000+ network devices** and **millions of interfaces** with multi-month historical retention, sub-second query latency, and automated cyber defense.

---

## 🌟 Key Highlights & Architecture

```
                  ┌─────────────────────────────────────────────────────────────┐
                  │ Multi-Vendor Hardware Routers & Switches (1,000+ Exporters) │
                  │  Cisco · Juniper · Huawei · Nokia · ZTE · MikroTik         │
                  └──────────────┬───────────────────────────────┬──────────────┘
                                 │ NetFlow v5/v9, IPFIX, sFlow   │
                                 ▼                               ▼
                 ┌───────────────────────────────────────────────────────────────┐
                 │       High-Throughput Asynchronous UDP Flow Listener         │
                 │   UDP 2055 (NetFlow v5) · UDP 2056 (NetFlow v9)              │
                 │   UDP 4739 (IPFIX RFC 7011) · UDP 6343 (sFlow v5)            │
                 └───────────────────────────────┬───────────────────────────────┘
                                                 │ Async Queue
                                                 ▼
                 ┌───────────────────────────────────────────────────────────────┐
                 │                Contextual Enrichment Pipeline                 │
                 │  • SNMP Inventory: 15,000+ Interfaces (Speed, Name, Alias)    │
                 │  • GeoIP2 & ASN: Country, City, Lat/Lon, Autonomous System    │
                 │  • L4/L7 Service: NBAR Classification (HTTPS, DNS, QUIC, BGP) │
                 │  • Direction: East-West (Internal) vs North-South (Transit)   │
                 └───────────────────────────────┬───────────────────────────────┘
                                                 │ Microsecond Batching
                                                 ▼
        ┌─────────────────────────────────────────────────────────────────────────────────┐
        │                          Dual Columnar Storage Engine                           │
        │   • Embedded Engine: DuckDB Vectorized Columnar OLAP (Zero external server)    │
        │   • Distributed Engine: ClickHouse Cluster (Partitioned MergeTree, TTL 90d)    │
        │   • Pre-aggregated 5-minute & 1-hour Materialized Views for historical rollups │
        └───────────────┬─────────────────────────────────────────────────┬───────────────┘
                        │ Analytical SQL Aggregations                     │ Real-time Stream
                        ▼                                                 ▼
        ┌───────────────────────────────┐               ┌─────────────────────────────────┐
        │  Analytics & Planning Core    │               │  Real-Time Threat & DDoS Engine │
        │  • Top Talkers & Conversations│               │  • Volumetric DDoS Floods       │
        │  • ASN Peering & Cost Matrix  │               │  • TCP SYN Flood (RFC flags)    │
        │  • Interface IN/OUT Saturated │               │  • UDP / DNS Reflection Amp     │
        │  • Site-to-Site WAN Tracking  │               │  • East-West Lateral Movement   │
        │  • QoS / CBQoS Tag Validation │               │  • Reconnaissance Port Scans    │
        │  • Capacity Exhaustion Model  │               │  • Automated BGP Flowspec Rules │
        │  • 95th Percentile Burstable  │               └────────────────┬────────────────┘
        └───────────────┬───────────────┘                                │
                        │                                                │
                        └───────────────────────┬────────────────────────┘
                                                ▼
                        ┌─────────────────────────────────────────────────┐
                        │      FastAPI REST & WebSocket Hub (Port 8080)   │
                        │      Kentik-Styled Dark Mode NOC Web Dashboard  │
                        └─────────────────────────────────────────────────┘
```

---

## 🚀 Core Capabilities

### 1. Multi-Vendor Protocol Support
- **Cisco Systems**: NetFlow v5, NetFlow v9, and IPFIX across ASR 9000, Nexus 9000, Catalyst 9500, and 8000 Series routers.
- **Juniper Networks**: J-Flow, sFlow, and IPFIX across PTX, MX, and QFX series.
- **Huawei**: NetStream v5/v9 and IPFIX across NetEngine 8000 and CloudEngine switches.
- **Nokia**: TiMOS cflowd & IPFIX across 7750 SR, 7250 IXR, and 7950 XRS.
- **ZTE**: NetFlow/IPFIX across ZXR10 series.
- **MikroTik**: RouterOS Traffic-Flow (NetFlow v5 & IPFIX).

### 2. Deep Contextual Enrichment
- **Device & Interface Telemetry**: Automatic mapping of exporter IP + `ifIndex` to device hostname, site, vendor, interface name (e.g. `100GE1/0/1`, `xe-0/0/0`), provisioned speed (10G, 100G, 400G), and human-readable aliases (`"Transit: Lumen AS3356"`, `"IXP: DE-CIX Frankfurt"`).
- **Autonomous System (AS) Analysis**: BGP routing context mapping traffic flowing across borders and between ISPs, categorizing traffic into **Tier-1 Paid Transit**, **Free IXP Peering**, and **Internal/Customer**.
- **Peering Cost Optimization**: Identifies high-volume traffic draining expensive upstream transit links that could be routed over settlement-free IXP or PNI peering, calculating monthly dollar savings.
- **GeoIP & Cloud Metadata**: Appends country, city, coordinates, cloud regions (AWS, Azure, GCP), and datacenters.
- **Traffic Direction**: Segregates East-West (DC-to-DC internal) from North-South (Internet/Transit) flows.

### 3. Real-Time DDoS Detection & Cyber Defense
- **TCP SYN Floods**: Identifies naked SYN spikes with abnormal SYN-to-ACK ratios.
- **UDP Amplification**: Detects DNS (port 53), NTP (port 123), Memcached (port 11211), and SSDP reflection attacks.
- **Volumetric Floods**: Triggers automated alerts when target IPs exceed configurable Mbps and PPS thresholds.
- **East-West Lateral Movement**: Flags unauthorized cross-subnet traversals hitting critical infrastructure ports (SMB 445, RDP 3389, SSH 22, WinRM 5985).
- **Reconnaissance Port Scanning**: Detects horizontal and vertical scanning across 30+ distinct destination ports.
- **Automated BGP Flowspec Mitigation**: Instantly generates RFC 5575 / RFC 8955 BGP Flowspec rules and RTBH scripts with one-click border mitigation.

### 4. QoS / CBQoS Validation
- Monitors DSCP priority distribution (CS0, EF, AF41, CS6).
- Flags policy compliance violations (e.g., mission-critical Voice/VoIP or BGP routing improperly marked as CS0 Best Effort).

### 5. Capacity Planning & Bandwidth Exhaustion Forecasting
- Historical regression analysis projecting future saturation dates for 100G/400G links.
- Generates "Days until 85% Warning" and "Exhaustion Date" alerts.

### 6. 95th Percentile Burstable Invoicing & Chargebacks
- Standard telecommunications 95th percentile burstable calculation (discards top 5% bursts over 30-day billing cycles).
- Multi-tenant departmental and customer chargeback reports.

---

## 📊 Database Architecture for 1-3 Month Retention

For 1,000 devices and millions of interfaces generating billions of flows, AegisFlow uses a **dual-engine columnar architecture**:

1. **Embedded Mode (DuckDB)**:
   - Uses vectorized columnar execution with zero external daemon requirements.
   - Ideal for single-node deployments, labs, and edge collectors.
   - Automatically maintains `raw_flows` and `flows_5m_rollup` tables.

2. **Distributed Carrier Mode (ClickHouse)**:
   - Schema defined in `storage/schema_clickhouse.sql`.
   - Table `raw_flows` partitioned by month (`toYYYYMM(timestamp)`), compressed with LZ4 and Zstandard, with a 90-day automatic pruning TTL (`TTL timestamp + INTERVAL 90 DAY`).
   - Materialized View `mv_flows_5m` continuously populates `flows_5m_rollup` (SummingMergeTree) for sub-second long-term trend analysis over 180+ days.

---

## 🛠️ Quick Start

### 1. Requirements
- Python 3.10+
- Dependencies installed via `pip install -r requirements.txt`

### 2. Launch the Engine
```bash
python run.py
```
Open your browser to:
👉 **`http://localhost:8080`**

### 3. Run Integration Tests
```bash
python tests/test_engine.py
python tests/check_api.py
```

### 4. Send Live UDP NetFlow Packets
```bash
python tests/send_udp_flow.py
```

### 5. Multi-Node Production Deployment (Docker Compose)
```bash
cd deploy
docker compose up -d
```

---

## 📡 API Reference Summary

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/overview` | Network KPI totals (Gbps, PPS, active flows, devices) |
| `GET` | `/api/v1/top-talkers/sources` | Top source IP talkers with GeoIP and ASN |
| `GET` | `/api/v1/top-talkers/destinations` | Top destination targets |
| `GET` | `/api/v1/conversations` | Source-to-destination conversation pairs |
| `GET` | `/api/v1/peering/matrix` | ASN-to-ASN traffic matrix with peering savings |
| `GET` | `/api/v1/interfaces/utilization` | Interface-level IN/OUT utilization percentage & saturation badges |
| `GET` | `/api/v1/site-to-site` | WAN traffic between datacenters and clouds |
| `GET` | `/api/v1/geomap` | Geographic source-destination flow coordinates |
| `GET` | `/api/v1/security/ddos` | Active DDoS attacks with generated BGP Flowspec rules |
| `GET` | `/api/v1/security/anomalies` | Port scans and East-West lateral movement |
| `POST`| `/api/v1/security/mitigate` | One-click BGP Flowspec mitigation dispatcher |
| `GET` | `/api/v1/qos/breakdown` | DSCP / ToS traffic distribution and CBQoS validation |
| `GET` | `/api/v1/capacity/forecast` | Bandwidth exhaustion date projection |
| `GET` | `/api/v1/billing/p95` | 95th Percentile burstable rate calculation |
| `GET` | `/api/v1/devices` | Inventory of 1,000+ routers and switches |
| `GET` | `/api/v1/raw-flows` | Columnar SQL flow query explorer |
| `WS`  | `/ws/live` | WebSocket feed for live pulse updates |
