# AegisFlow | Carrier-Grade Flow Intelligence, Observability & DDoS Defense Platform

[![Security: Air-Gapped](https://img.shields.io/badge/Security-Air--Gapped%20Zero--Exfiltration-emerald.svg)](#-air-gap-security--zero-exfiltration-mandate)
[![Protocols: NetFlow / IPFIX / sFlow](https://img.shields.io/badge/Protocols-NetFlow%20v5%2Fv9%20%7C%20IPFIX%20%7C%20sFlow-cyan.svg)](#-multi-vendor-hardware--protocol-support)
[![Engine: Columnar OLAP](https://img.shields.io/badge/Storage-DuckDB%20%7C%20ClickHouse-blue.svg)](#-high-performance-columnar-storage-1-3-month-retention)
[![Visualizations: Kentik Studio](https://img.shields.io/badge/Visualizations-Sankey%20%7C%20Bars%20%7C%20Table%20%7C%20Treemap-purple.svg)](#-multi-view-traffic-visualization-studio-graph-change-options)
[![License: Proprietary](https://img.shields.io/badge/License-Carrier--Enterprise-slate.svg)](#)

Inspired by **[Kentik Network Intelligence & Observability](https://www.kentik.com/)**, **AegisFlow** is a carrier-grade network telemetry, multi-dimensional traffic engineering, automated DDoS mitigation, and capacity planning platform. 

It is engineered from the ground up to ingest, enrich, and analyze continuous flow telemetry across **1,000+ multi-vendor routers and switches** and **over 1,000,000 interfaces** while maintaining low compute overhead, sub-second analytical query latency, and **1 to 3+ months of historical retention**.

---

## 📑 Table of Contents

1. [Architectural Overview & Data Flow](#-architectural-overview--data-flow)
2. [Multi-Vendor Hardware & Protocol Support](#-multi-vendor-hardware--protocol-support)
3. [Zero-Touch Ingestion vs. Optional Device Registration](#-zero-touch-ingestion-vs-optional-device-registration)
4. [Multi-Condition Filtering, Date Selection & Saved Reports Engine](#-multi-condition-filtering-date-selection--saved-reports-engine)
   - [Granular Multi-Attribute Filter Capabilities](#granular-multi-attribute-filter-capabilities)
   - [Custom Date Range Filtering & Historical Presets](#custom-date-range-filtering--historical-presets)
   - [Traffic Pattern Demand Comparison Studio (DoD, WoW, MoM)](#traffic-pattern-demand-comparison-studio-dod-wow-mom)
   - [Automated Report Generator & Notifications](#automated-report-generator--notifications)
5. [Upstream Bandwidth Management & Smart IIG Traffic Shift (>1,000 Gbps)](#-upstream-bandwidth-management--smart-iig-traffic-shift-1000-gbps)
6. [Mobile App & Progressive Web App (PWA) Support](#-mobile-app--progressive-web-app-pwa-support)
7. [Multi-View Traffic Visualization Studio (Graph Change Options)](#-multi-view-traffic-visualization-studio-graph-change-options)
8. [Interactive Cyber Attack Injection Range (Start / Stop)](#-interactive-cyber-attack-injection-range-start--stop)
9. [DDoS Radar, Anomaly Detection & BGP Flowspec Mitigation](#-ddos-radar-anomaly-detection--bgp-flowspec-mitigation)
10. [Advanced Traffic Engineering & Analytics](#-advanced-traffic-engineering--analytics)
   - [ASN-to-ASN Peering & Cost Optimization](#asn-to-asn-peering--cost-optimization)
   - [Interface Capacity Saturation & IN/OUT Ratios](#interface-capacity-saturation--inout-ratios)
   - [QoS & CBQoS Policy Validation](#qos--cbqos-policy-validation)
   - [Site-to-Site WAN & Cloud Interconnect Tracking](#site-to-site-wan--cloud-interconnect-tracking)
   - [Capacity Planning & Linear Bandwidth Forecast](#capacity-planning--linear-bandwidth-forecast)
   - [95th Percentile Burstable Invoicing & Billing](#95th-percentile-burstable-invoicing--billing)
11. [High-Performance Columnar Storage (1-3 Month Retention)](#-high-performance-columnar-storage-1-3-month-retention)
12. [Air-Gap Security & Zero-Exfiltration Mandate](#-air-gap-security--zero-exfiltration-mandate)
13. [Quick Start & Deployment Guide](#-quick-start--deployment-guide)
14. [REST API & WebSocket Reference](#-rest-api--websocket-reference)

---

## 🏛️ Architectural Overview & Data Flow

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
                                                 │ Async Non-Blocking Ring Queue
                                                 ▼
                 ┌───────────────────────────────────────────────────────────────┐
                 │                Contextual Enrichment Pipeline                 │
                 │  • SNMP Inventory: 15,000+ Interfaces (Speed, Name, Alias)    │
                 │  • GeoIP2 & ASN: Country, City, Coordinates, Cloud VPC        │
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
        │  • Top Talkers & Convs        │               │  • Volumetric DDoS Floods       │
        │  • ASN Peering & Cost Matrix  │               │  • TCP SYN Flood (Naked SYN)    │
        │  • Interface IN/OUT Ratios    │               │  • UDP / DNS Reflection Amp     │
        │  • Site-to-Site WAN Tracking  │               │  • East-West Lateral Movement   │
        │  • Capacity Exhaustion Model  │               │  • Port Scan Reconnaissance     │
        │  • 95th Percentile Burstable  │               │  • RFC 5575 BGP Flowspec Gen    │
        └───────────────┬───────────────┘               └────────────────┬────────────────┘
                        │                                                │
                        └───────────────────────┬────────────────────────┘
                                                ▼
                        ┌────────────────────────────────────────────────┐
                        │      FastAPI REST & WebSocket Hub (:8080)      │
                        │  • Multi-Condition Pattern Engine & Queries    │
                        │  • Scheduled Executive Report Generator        │
                        │  • Real-Time Threat Mitigator & Attack Range   │
                        └───────────────────────┬────────────────────────┘
                                                ▼
                        ┌────────────────────────────────────────────────┐
                        │ Kentik-Styled Dark Mode Observability Console  │
                        │ 🌊 5-Stage Sankey Flow · 📊 Ranked Bars        │
                        │ 📋 Searchable Table (CSV) · 📈 Area Trend Wave │
                        │ 🗂️ Treemap Matrix · ☀️ Radial Sunburst Flow    │
                        └────────────────────────────────────────────────┘
```

---

## 🔌 Multi-Vendor Hardware & Protocol Support

AegisFlow natively decodes flow telemetry exported by edge routers, core switches, and cloud gateways:

| Vendor | Supported Hardware Lines | Supported Protocols | Ingestion Port |
|---|---|---|---|
| **Cisco Systems** | ASR 9000, ASR 1000, NCS 5500, Nexus 9000/7000, Catalyst 9500 | NetFlow v5, NetFlow v9, IPFIX | UDP `2055`, `2056`, `4739` |
| **Juniper Networks**| PTX 10000, MX 960/480/240, QFX 10000, EX Series | J-Flow, IPFIX, sFlow v5 | UDP `2056`, `4739`, `6343` |
| **Huawei** | NetEngine 8000, NE40E, CloudEngine 12800/8800 | NetStream v5/v9, IPFIX, sFlow | UDP `2055`, `2056`, `4739`, `6343` |
| **Nokia (Alcatel)** | 7750 SR, 7950 XRS, 7250 IXR (TiMOS) | cflowd, IPFIX | UDP `2056`, `4739` |
| **ZTE** | ZXR10 Series (M6000, 9900) | NetStream, IPFIX | UDP `2056`, `4739` |
| **MikroTik** | Cloud Core Routers (CCR2004, CCR2116, CCR1072, RB) | Traffic-Flow (NetFlow v5/v9, IPFIX) | UDP `2055`, `2056`, `4739` |

---

## ⚡ Zero-Touch Ingestion vs. Optional Device Registration

```
Router / Switch (Cisco, Juniper, Huawei, Nokia, MikroTik)
                   │
                   │ NetFlow v5/v9, IPFIX, sFlow
                   ▼
       [ AegisFlow UDP Listeners ]
                   │
        Is Exporter IP in Cache?
        ├── NO  (Zero-Touch) ──────► Auto-Discover & Register Device Instantly
        │                            Generate Dynamic Interface IDs
        │                            Immediately Visible in Analytics & Sankey
        │
        └── YES (Pre-Configured) ──► Enrich with SNMP Hostnames, 100G Speeds,
                                     Physical PoP/Datacenter & Description Aliases
```

### 1. Do You Need to Add Devices Manually?
**NO.** You do **not** need to manually pre-register devices in AegisFlow before sending traffic:
- **Instant Zero-Touch Discovery**: As soon as any router begins exporting flow packets to UDP 2055, 2056, 4739, or 6343, AegisFlow detects the exporter IP address, automatically provisions the device record, decodes all ingress flow records, and makes the traffic visible across all dashboards and reports.
- **Dynamic Interface Synthesis**: Any unmapped interface is assigned carrier naming (e.g. `Gi0/0/0/<ifindex>` or `100GE1/0/<ifindex>`), allowing full traffic measurement without waiting for SNMP polling.

### 2. Optional SNMP Metadata Enrichment
Manual registration or SNMP polling can be used to enrich telemetry with human-friendly metadata:
- **Router Hostnames**: Mapping `10.254.1.1` $\rightarrow$ `cisco-ny4-edge-001.net.infra`.
- **Interface Capacities & Descriptions**: Labeling `ifIndex 14` as `HundredGigE0/0/0/14 (100 Gbps)` with alias `"Transit to Lumen AS3356 [100G PNI]"`, enabling percentage-based link saturation alarms (>80%).
- **Physical Datacenter / PoP Assignment**: Grouping devices by physical site (e.g., `Equinix NY4`, `Telehouse London`, `Equinix SG1`).

---

## 🎯 Multi-Condition Filtering, Date Selection & Saved Reports Engine

AegisFlow features a multi-attribute pattern matching engine that lets network architects query complex traversal scenarios, perform granular date/time selection, execute demand-driven pattern comparisons, and schedule automated executive reports:

### Granular Multi-Attribute Filter Capabilities
1. **ASN-to-ASN & Specific IP / Prefix**: e.g., Filter traffic originating in **AS3356 (Lumen)** heading to **AS15169 (Google)** targeting destination prefix `8.8.8.0/24`.
2. **Source Prefix to Ingress Interface**: e.g., Trace internal subnet `10.0.0.0/16` traversing border interface `HundredGigE0/0/0/1`.
3. **Destination Prefix & Device**: e.g., Trace traffic destined for cloud prefix `52.94.0.0/16` routed via `juniper-fra1-core-002`.
4. **Upstream Provider & Service Pool**: Filter by Tier-1 carrier (`Tata Communications`, `Bharti Airtel`, `Telia`, etc.) and delivery tier (`IPT`, `PNI`, `MixCDN`, `Baishan`, `IX`, `GGC`, `FNA`).
5. **Country, Protocol & Flow Direction**: Filter by ISO country code (`US`, `DE`, `JP`), L4 protocol (`TCP`, `UDP`, `ICMP`), DSCP tags, and direction (`East-West` vs `North-South`).

---

### 📅 Custom Date Range Filtering & Historical Presets

Operators can filter flow telemetry by exact historical date and time boundaries across the Traffic Pattern Studio, Raw Flow Explorer, and Multi-Parameter tables:

```
[ Quick Presets: Today | Yesterday | Last 7 Days | Last 30 Days ]
[ Start Time: 2026-10-23 00:00:00 ] ────► [ End Time: 2026-10-30 23:59:59 ]
```

- **Dynamic Analytical Time-Bucketing**:
  The backend dynamically computes optimal time bucket resolution according to the selected duration:
  - $\le 2\text{ hours}$: **60-second** high-resolution buckets.
  - $\le 24\text{ hours}$: **5-minute (300s)** operational buckets.
  - $\le 7\text{ days}$: **30-minute (1800s)** rolling trend buckets.
  - $\le 30\text{ days}$: **2-hour (7200s)** capacity buckets.
  - $> 30\text{ days}$: **1-day (86400s)** executive macro buckets.
- **Timestamp Anchoring**:
  When querying historical datasets or demo archives, relative queries automatically anchor to the latest flow timestamp in the database (`MAX(timestamp)`), guaranteeing smooth, gapless traffic curves without empty results.
- **Synchronized Query Execution**:
  Passing `start_time` and `end_time` (ISO 8601 or `YYYY-MM-DD HH:MM:SS`) filters raw flows, Sankey flows, ranked bars, area trend charts, and multi-parameter carrier tables simultaneously.

---

### ⇄ Traffic Pattern Demand Comparison Studio (DoD, WoW, MoM)

The **Demand Comparison Studio** enables network planners, capacity engineers, and NOC directors to detect demand shifts, verify diurnal curves, and isolate anomalies by comparing any two historical timeframes side-by-side:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                            Demand Horizon Comparison Switcher                               │
│   [ 📅 Day to Day (DoD) ]   [ 🗓️ Week to Week (WoW) ]   [ 📊 Month by Month (MoM) ]   [ ⏱️ Custom Dates ] │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
                                           │
       ┌───────────────────────────────────┴───────────────────────────────────┐
       ▼                                                                       ▼
┌───────────────────────────────────────┐               ┌───────────────────────────────────────┐
│     Current Period (Solid Wave)       │               │      Baseline Period (Dashed Wave)     │
│  e.g. Current Monday 00:00 - 23:59    │  VS           │  e.g. Previous Monday 00:00 - 23:59   │
│  Throughput: 11,125 Mbps (109.3 TB)   │               │  Throughput: 10,940 Mbps (107.5 TB)   │
└───────────────────────────────────────┘               └───────────────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ 📈 Synchronized Dual-Wave Overlay Timeseries  ·  📊 Side-by-Side Grouped Comparison Bars   │
│ 📋 Dimensional Delta Variance Table (Top Surging/Dropping ASNs, Protocols, Upstreams)      │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

#### Comparison Modes:
1. **Day to Day (DoD)**:
   Compares 24 hours of traffic against the preceding 24 hours (or a specific target calendar day against the day prior), bucketed into 24 synchronized hourly points.
2. **Week to Week (WoW)**:
   Compares a 7-day rolling window against the prior 7-day window, day-matched (Monday to Monday, Sunday to Sunday) across 7 synchronized daily points to account for weekend demand drops.
3. **Month to Month (MoM)**:
   Compares a 30-day billing cycle against the prior 30-day baseline across 30 synchronized daily points, exposing long-term subscriber growth trends.
4. **Custom Horizon Comparison**:
   Enables arbitrary range comparisons (e.g. Peak Event Window vs Normal Baseline Day) with user-defined start and end timestamps for both the current and baseline horizons.

#### Comparative Metrics & Intelligence:
- **KPI Variance Cards**:
  - **Throughput Delta**: Net change in average wire-rate ($\Delta\text{ Mbps}$ and $\% \text{ variance}$).
  - **Transferred Volume Delta**: Absolute shift in total byte volume ($\Delta\text{ GB / TB}$).
  - **Peak Wire-Rate Comparison**: Peak current Mbps vs peak baseline Mbps.
  - **Divergence Status**: Automated categorization into `NORMAL_VARIANCE` ($\pm 15\%$), `SURGE_SPIKE` ($> +15\%$), or `DROP_DIVERGENCE` ($< -15\%$).
- **Multi-View Comparative Visualizations**:
  - **Dual-Wave Overlay Timeseries**: Renders the Current curve (solid emerald/cyan wave) against the Baseline curve (dashed amber wave) with synchronized cursor tooltips showing simultaneous current vs baseline Mbps and packet rates.
  - **Side-by-Side Grouped Bars**: Displays adjacent bars for Current and Baseline per time interval, immediately highlighting specific hours or days of divergence.
  - **Dimensional Delta Variance Analysis**: Identifies exact traffic surges and drops across:
    - *Autonomous Systems (Top Surging vs Dropping ASNs)*
    - *Applications & L4/L7 Protocols (HTTPS, DNS, QUIC, BGP, etc.)*
    - *Upstream Providers (Tata, Airtel, Telia, Cogent, etc.)*
    - *Router Interfaces & Links*
- **One-Click CSV Export**:
  Export complete comparative intervals, baseline values, delta percentages, and dimensional changes directly into CSV for executive capacity audits and board presentations.

---

### Automated Report Generator & Notifications
- **Scheduled Triggers**: Run reports automatically on a recurring schedule (**Hourly**, **Daily**, **Weekly**, or **On-Demand**).
- **Multi-Channel Delivery**:
  - **Email (SMTP)**: Dispatches a responsive, dark-mode Executive HTML report summarizing peak Mbps, total TB, flow counts, top ASN pairs, and top conversations. Automatic fallback disk spooling (`reports/spool/`) ensures zero lost reports if the SMTP relay is unreachable.
  - **Webhooks**: Dispatches rich JSON alert cards to internal **Slack**, **Microsoft Teams**, or SIEM HTTP endpoints.
  - **CSV & HTML Export**: Instant one-click file exports.
  - **In-App Notification Center**: Persistent audit trail for NetOps teams.

---

## 🌐 Upstream Bandwidth Management & Smart IIG Traffic Shift (>1,000 Gbps)

AegisFlow is built to handle carrier-scale **>1,000 Gbps (1 Terabit/s+)** aggregate traffic across multiple upstream providers and services, automatically detecting congestion and calculating optimal traffic shifts to alternative IIGs with available headroom.

```
                  ┌─────────────────────────────────────────────────────────────┐
                  │ Carrier Total Capacity: 3.5 Tbps (3,500 Gbps) Across Upstreams│
                  └──────────────┬───────────────────────────────┬──────────────┘
                                 │                               │
                ┌────────────────┴───────────────┐               │
                ▼                                ▼               ▼
     [ Tata Communications ]            [ Bharti Airtel ]   [ Cogent / NTT / Telia ]
        Capacity: 300 Gbps                 Capacity: 250 Gbps     Combined: 650 Gbps
        Utilized: 277 Gbps (92.4%) ⚠️       Utilized: 145 Gbps     Headroom: 380 Gbps
        Headroom: 23 Gbps                  Headroom: 105 Gbps
                │                                ▲
                └───────── Traffic Shift ────────┘
                      Shift 52.2 Gbps via BGP
                   (Google, Cloudflare, Meta ASNs)
```

### 1. Multi-Upstream & Service Support
Operators can configure purchased bandwidth capacity, warning/critical thresholds, BGP communities, and cost per Mbps for:
- **Upstream Providers**: e.g. Tata Communications, Bharti Airtel, Cogent, NTT Global, Telia Arelion, SEA-ME-WE Consortium, etc.
- **Service Categories**:
  - **`IPT` (IP Transit)**: Global paid internet transit connections.
  - **`PNI` (Private Network Interconnect)**: Dedicated direct peering with Google, Meta, Microsoft, AWS.
  - **`MixCDN` (Multi-CDN Aggregation)**: Dynamic web and video delivery caches.
  - **`Baishan` (BaishanCloud)**: Asia-Pacific edge caching and CDN delivery.
  - **`IX` (Internet Exchange)**: National/Regional settlement-free peering (e.g. BDIX, DE-CIX).
  - **`GGC` (Google Global Cache)**: On-net caching nodes for zero-transit YouTube delivery.
  - **`FNA` (Facebook Network Appliance)**: On-net caching nodes for Meta traffic.
  - **Custom Services**: Enter any custom delivery pool (Akamai AAP, Netflix OCA, Cloudflare CDN) on demand.

### 2. Real-Time Over-Utilization Alerts & Smart Shift Engine
- **Capacity Utilization**: Computes real-time wire-rate Gbps against purchased capacity every 5 seconds.
- **Congestion Triggers**: Triggers automated Warning (>80%) and Critical (>90%) alerts in the UI, webhooks, and mobile PWA.
- **Automated Traffic Shift Recommendations**:
  - Automatically identifies target available IIGs with sufficient headroom.
  - Analyzes top talkers on the congested link to select candidate ASNs (e.g. `AS15169 Google`, `AS13335 Cloudflare`, `AS32934 Meta`) and destination prefixes.
  - Generates ready-to-deploy **BGP Routing Policies** for Cisco IOS-XR, Juniper Junos, and Huawei VRP (Local-Preference adjustments, community tagging, AS-path prepending).
  - Features one-click **"⚡ Deploy Traffic Shift"** directly from the dashboard.

### 3. Multi-Parameter Flow Mapping (>1,000 Gbps Scale)
Correlates live flow traffic against Upstream Providers and Services across 5 multi-parameter dimensions:
1. **IP to IP**: Maps individual host-to-host flows to the carrier upstream carrying the packets.
2. **Prefix to Prefix (/24 Subnets)**: Aggregates enterprise and subscriber subnets across carrier links.
3. **Device to IP**: Tracks which edge router interface egresses traffic to specific destination IPs.
4. **ASN to ASN**: Maps origin Autonomous System to destination Autonomous System traversal.
5. **Upstream to Service**: High-level carrier delivery matrix showing bandwidth share per service pool.
- Includes instantaneous search filter and one-click **"📥 CSV Export"**.

---

## 📱 Mobile App & Progressive Web App (PWA) Support

AegisFlow is fully mobile-ready and can be operated seamlessly from smartphones and tablets:

1. **Progressive Web App (PWA)**:
   - Web App Manifest ([`ui/manifest.json`](file:///d:/AI-Projects/Traffic-flow-Analysis-Engine/ui/manifest.json)) and Service Worker ([`ui/sw.js`](file:///d:/AI-Projects/Traffic-flow-Analysis-Engine/ui/sw.js)) enable operators to tap **"Add to Home Screen"** on iOS Safari and Android Chrome to install AegisFlow as a standalone native-like mobile app.
   - Offline-capable UI shell and fast asset caching.
2. **Responsive Mobile Navigation**:
   - Fixed **Bottom Mobile Navigation Bar** for one-thumb switching between *NOC Overview*, *IIG Shift*, *CDN Sankey*, *Security*, and *Alerts*.
   - Off-canvas drawer menu for accessing full 13 platform modules on handheld screens.
3. **Mobile API Hub (`/api/v1/mobile/summary`)**:
   - Compact, high-speed JSON payload tailored for mobile apps, smartwatch widgets, and push notification integrations.

---

## 🎨 Multi-View Traffic Visualization Studio (Graph Change Options)

The platform provides a 1-click **Graph View Switcher Toolbar** inside the Traffic Pattern Studio:

```
[ 🌊 Sankey Flow ]  [ 📊 Ranked Bars ]  [ 📋 Flow Table (CSV) ]  [ 📈 Area Trend ]  [ 🗂️ Treemap ]  [ ☀️ Sunburst ]
```

### 1. 🌊 Sankey Flow Diagram (CDN Entry & Exit)
- Dedicated preset: **"CDN Traffic Network Entry and Exit ★ Saved View"**.
- Implements the exact 5-stage network traversal hierarchy:
  1. **Source CDN / Provider**: `EdgeCast Verizon`, `Facebook`, `Apple`, `Google Youtube`, `Yahoo`, `Amazon + AWS`, `Akamai`, `Netflix`.
  2. **Interconnect Type**: `customer`, `free_pni`, `transit`, `paid_pni`.
  3. **Ingress PoP / Site**: `SFO1`, `NYC1`, `ORD1`.
  4. **Egress PoP / Device**: `ORD1`, `SFO1`.
  5. **Destination Prefix**: `12.0.0.0/9`, `96.6.0.0/22`, `66.100.0.0/15`, `205.158.0.0/16`, `15.143.96.0/23`, `144.224.0.0/16`, `141.193.36.0/22`, `17.0.0.0/21`.
- Smooth bezier ribbons with upstream/downstream path highlighting and wire-rate tooltips in Mbps.

### 2. 📊 Ranked Horizontal Bar Chart
- Ranked throughput (Mbps) and packet rate (PPS) bars.
- Subcategory toggle:
  - *Top CDN Providers*
  - *Destination Subnet Prefixes*
  - *Interconnect Types*

### 3. 📋 Interactive Flow Data Table
- High-density tabulated view with columns: `Rank`, `Source Provider / ASN`, `Interconnect`, `Ingress PoP`, `Egress PoP`, `Destination Prefix`, `Application`, `Throughput (Mbps)`, `Total Volume (GB)`, `Packet Rate (PPS)`, and visual `% Share` progress bar.
- Live multi-column instant search filter.
- **"📥 Export CSV"** button to download active dataset.

### 4. 📈 Time-Series Area Trend Wave
- 1-minute bucketed wire-rate (Mbps) and packet rate (PPS) dual-gradient wave over the selected time window.

### 5. 🗂️ Hierarchical Treemap Matrix
- Bandwidth-proportional area blocks supporting clickable drilldown: Provider $\rightarrow$ Interconnect / Site $\rightarrow$ Subnet.

### 6. ☀️ Radial Sunburst Flow
- Multi-tier concentric rings illustrating core-to-edge flow distribution.

---

## ⚔️ Interactive Cyber Attack Injection Range (Start / Stop)

AegisFlow includes a built-in **Cyber Attack Injection & Stress Test Console** enabling NetOps and SecOps teams to validate detection thresholds, alerting pipelines, and automated mitigation rules:

```
[ Target Victim IP: 10.0.1.50 ]  [ Vector: UDP_DNS ]  [ Port: 53 ]  [ Intensity: High (~800 Mbps) ]
[ ▶ Start Attack ]  [ ⏹ Stop Attack ]
```

### Attack Controls & Parameters:
1. **Start & Stop Controls**:
   - Available via the header (**"Inject Test Attack"** / pulsating **"Stop Attack"**) and directly inside the **Security Tab**.
   - Spawns a non-blocking background async worker (`attack_campaign_worker`) injecting batches of 250 attack flows every 2 seconds.
   - Clicking **"Stop Attack"** immediately halts traffic generation and logs total blasted packets.
2. **Victim IP Customization**:
   - Target any arbitrary internal or external IPv4 address.
   - One-click presets: `10.0.1.50` (Web DC), `10.0.2.10` (DB Pool), `10.1.5.20` (Core App Jumpbox).
3. **Attack Protocols & Vectors**:
   - **`TCP_SYN` (TCP SYN Flood)**: 64-byte naked SYN packets (`syn & !ack`) without ACK to exhaust TCP state tables.
   - **`UDP_DNS` (DNS Amplification)**: 1,420-byte amplified DNS payloads on source port 53.
   - **`UDP_NTP` (NTP Monlist)**: Port 123 amplified reflection requests.
   - **`ICMP` (Ping Storm)**: Protocol 1 ICMP Echo requests saturating ingress pipes.
   - **`HTTP` (Layer 7 Flood)**: HTTP GET floods targeting web server endpoints.
   - **`LATERAL` (East-West Movement)**: Internal RFC 1918 traffic scanning ports 445 (SMB), 3389 (RDP), 22 (SSH), 5985 (WinRM).
   - **`COMBINED` (Multi-Vector Assault)**: Hybrid assault blending volumetric reflection with SYN floods.
4. **Volume & Intensity**:
   - `Medium`: ~150 Mbps, 25,000 PPS.
   - `High`: ~800+ Mbps, 120,000 PPS (Triggers critical DDoS Radar thresholds).
   - `Extreme`: Carrier-scale flood (3.5 to 8.5+ Gbps, 750,000+ PPS).
5. **Real-Time Telemetry**:
   - WebSocket broadcast (`ATTACK_TICK`) pushes live throughput, PPS, total blasted packets, and elapsed timer to the UI.

---

## 🛡️ DDoS Radar, Anomaly Detection & BGP Flowspec Mitigation

```
Flow Stream ──► [ Volumetric Detector ] ──► Bandwidth > 500 Mbps ────┐
            ──► [ SYN Flood Detector ] ──► SYN/ACK Ratio > 85% ─────┼──► RFC 5575 BGP Flowspec
            ──► [ UDP Amp Detector ]   ──► Port 53/123 PPS > 20k ───┤    Mitigation Rule
            ──► [ Lateral Movement ]   ──► Internal SMB/RDP/SSH ────┘
```

### Generated RFC 5575 BGP Flowspec Sample
```text
flow-spec route {
  match {
    destination 10.0.1.50/32;
    protocol tcp;
    tcp-flags (syn & !ack);
  }
  then rate-limit 0;
}
```
- **One-Click Mitigation**: Operators can click **"Deploy Flowspec"** to dispatch the filter rule to edge BGP speakers or inject RTBH (Remotely Triggered Black Hole) null routes via `/api/v1/security/mitigate`.

---

## 📈 Advanced Traffic Engineering & Analytics

### ASN-to-ASN Peering & Cost Optimization
- Maps traffic traversing upstream transit providers vs. settlement-free IXPs.
- Calculates cost savings by identifying heavy destinations currently sent over paid transit (e.g. AS3356 Lumen) that could be offloaded to direct peering (e.g. AS15169 Google, AS13335 Cloudflare).

### Interface Capacity Saturation & IN/OUT Ratios
- Tracks IN/OUT utilization percentage against provisioned physical capacity (10G, 40G, 100G, 400G).
- Visual warning badges for interfaces operating above 80% saturation.

### QoS & CBQoS Policy Validation
- Classifies traffic into DSCP priority pools: EF (Voice/VoIP), AF41 (Video), CS6 (BGP/Network Control), and CS0 (Best Effort).
- Flags policy degradation violations (e.g., mission-critical routing or voice packets marked Best Effort).

### Site-to-Site WAN & Cloud Interconnect Tracking
- Measures real-time cross-datacenter WAN traffic between physical facilities (Equinix NY4, Telehouse FRA1, Equinix SG1, Equinix TY2) and Cloud VPCs (AWS us-east-1, Azure West Europe, GCP asia-east1).

### Capacity Planning & Linear Bandwidth Forecast
- Evaluates 30-day historical slope regression to project future link exhaustion dates.
- Generates actionable alerts (e.g. *"NY4 Core Interface HundredGigE0/0/0/1 will hit 85% capacity in 14 days"*).

### 95th Percentile Burstable Invoicing & Billing
- Telecommunications-standard 95th percentile burstable billing calculator: discards top 5% peak usage samples across the monthly billing cycle.
- Segments bandwidth consumption by customer, ASN, or departmental cost center.

---

## 💾 High-Performance Columnar Storage (1-3 Month Retention)

To store billions of flow records over 1 to 3+ months with minimal storage overhead:

1. **Embedded Mode (DuckDB)**:
   - Vectorized columnar execution engine running embedded in the process with zero external database daemons.
   - Partition-level retention maintenance drops data older than `retention_days` (default 90 days) without disk fragmentation.
2. **Distributed Carrier Mode (ClickHouse)**:
   - DDL schema in [`storage/schema_clickhouse.sql`](file:///d:/AI-Projects/Traffic-flow-Analysis-Engine/storage/schema_clickhouse.sql).
   - Table `raw_flows` partitioned by month (`toYYYYMM(timestamp)`), compressed with LZ4 and Zstandard:
     ```sql
     ENGINE = MergeTree()
     PARTITION BY toYYYYMM(timestamp)
     ORDER BY (timestamp, exporter_ip, src_ip, dst_ip)
     TTL timestamp + INTERVAL 90 DAY DELETE;
     ```
   - SummingMergeTree Materialized Views continuously generate 5-minute pre-aggregated rollups (`flows_5m_rollup`) for instant multi-month trend analysis over 180+ days.

---

## 🔒 Air-Gap Security & Zero-Exfiltration Mandate

AegisFlow processes sensitive network flow records, internal IP addresses, and BGP routing matrices. To guarantee **zero data exfiltration and complete air-gap compliance**:

1. **Zero External Calls**:
   - No phone-home telemetry, no remote analytics beacons, and no cloud dependencies.
2. **Strict Local / RFC 1918 Binding**:
   - REST API and WebSockets bind to `127.0.0.1` or internal private management interfaces (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
3. **Active Egress Whitelist Guard**:
   - Both [`alerting/alert_manager.py`](file:///d:/AI-Projects/Traffic-flow-Analysis-Engine/alerting/alert_manager.py) and [`reports/notifier.py`](file:///d:/AI-Projects/Traffic-flow-Analysis-Engine/reports/notifier.py) validate destination IPs before opening socket connections. Any attempt to send webhooks to public internet IPs is immediately blocked with an air-gap violation alert.
4. **Offline UI Asset Self-Hosting**:
   - Run `python .agents/skills/server-data-isolation/scripts/vendor_frontend_assets.py --download` to vendor all CSS/JS assets locally into `ui/vendor/` for 100% offline environments.
5. **Log & Telemetry Sanitization**:
   - Run `python .agents/skills/server-data-isolation/scripts/sanitize_telemetry_logs.py` to mask customer IPs and scrub credentials before generating diagnostic bundles.
6. **Isolation Verification**:
   - Run `python .agents/skills/server-data-isolation/scripts/verify_network_isolation.py` to audit open sockets and verify that no unauthorized outbound connections exist.
7. **Workspace Security Directives**:
   - Permanent project rules are enforced in [`GEMINI.md`](file:///d:/AI-Projects/Traffic-flow-Analysis-Engine/GEMINI.md) and [`AGENTS.md`](file:///d:/AI-Projects/Traffic-flow-Analysis-Engine/AGENTS.md).

---

## 🚀 Quick Start & Deployment Guide

### 1. Prerequisites
- Python 3.10+
- Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```

### 2. Start AegisFlow
```bash
python run.py
```
Open your web browser:
👉 **`http://localhost:8080`**

### 3. Verify System & Run Tests
```bash
# Verify API & analytics
python tests/check_api.py

# Verify Multi-Condition Filtering & Saved Reports
python tests/check_pattern_and_reports.py

# Verify Cyber Attack Range Controller
python tests/test_attack_controller.py
python tests/test_live_attack_campaign.py

# Verify Air-Gap Isolation Audit
python .agents/skills/server-data-isolation/scripts/verify_network_isolation.py
```

### 4. Send Test NetFlow UDP Packets
```bash
python tests/send_udp_flow.py
```

### 5. Multi-Node Production Deployment (Docker Compose)
```bash
cd deploy
docker compose up -d
```

---

## 📡 REST API & WebSocket Reference

### Overview & Visualizations
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/overview` | Network KPI totals (Gbps, PPS, active flows, devices) |
| `GET` | `/api/v1/top-talkers/sources` | Top source IP talkers with GeoIP and ASN |
| `GET` | `/api/v1/top-talkers/destinations` | Top destination targets |
| `GET` | `/api/v1/conversations` | Source-to-destination conversation pairs |
| `GET` | `/api/v1/peering/matrix` | ASN-to-ASN traffic matrix with peering savings |
| `GET` | `/api/v1/interfaces/utilization` | Interface IN/OUT utilization % & saturation alarms |
| `GET` | `/api/v1/site-to-site` | WAN traffic between datacenters and clouds |
| `GET` | `/api/v1/geomap` | Geographic source-destination flow coordinates |

### Multi-Condition Filtering, Date Horizons & Demand Comparison
| Method | Endpoint | Description |
|---|---|---|
| `POST`| `/api/v1/pattern/query` | Executes multi-condition filter queries with optional date bounds |
| `POST`| `/api/v1/pattern/compare` | Runs Day-to-Day, Week-to-Week, Month-to-Month & Custom pattern demand comparisons |
| `GET` | `/api/v1/pattern/compare` | Quick query execution for pattern demand comparisons |
| `GET` | `/api/v1/pattern/options` | Dynamic filter dropdown options (ASNs, devices, interfaces, upstreams, services) |
| `GET` | `/api/v1/health` | System health check, storage status, and active timestamp |
| `GET` | `/api/v1/reports` | Lists all saved scheduled reports |
| `POST`| `/api/v1/reports` | Creates a new condition-based automated report |
| `POST`| `/api/v1/reports/{id}/run`| Executes report on-demand and dispatches email/webhook |
| `GET` | `/api/v1/reports/{id}/export/html` | Generates executive HTML report |
| `GET` | `/api/v1/reports/{id}/export/csv` | Exports matched flow records to CSV |
| `GET` | `/api/v1/notifications` | Returns in-app alert audit history |

### Security, Attack Injection & Mitigation
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/security/ddos` | Active DDoS attacks with generated BGP Flowspec rules |
| `GET` | `/api/v1/security/anomalies` | Port scans and East-West lateral movement |
| `POST`| `/api/v1/security/mitigate` | One-click BGP Flowspec mitigation dispatcher |
| `POST`| `/api/v1/simulate/attack/start` | Starts background attack injection (custom IP, protocol, rate) |
| `POST`| `/api/v1/simulate/attack/stop` | Halts active attack campaign |
| `GET` | `/api/v1/simulate/attack/status` | Returns live attack campaign telemetry (Mbps, PPS, total packets) |

### Upstream Bandwidth Management & Traffic Shifting
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/upstreams` | Real-time utilization %, wire-rate Gbps, and headroom across upstreams |
| `POST`| `/api/v1/upstreams` | Creates new Upstream Provider & Service with purchased bandwidth |
| `PUT` | `/api/v1/upstreams/{id}` | Updates upstream provider capacity and thresholds |
| `DELETE`| `/api/v1/upstreams/{id}`| Removes an upstream provider configuration |
| `GET` | `/api/v1/upstreams/shift-suggestions` | Smart traffic shift recommendations to alternative available IIGs |
| `POST`| `/api/v1/upstreams/shift-execute` | Deploys/simulates recommended BGP traffic shift policy |
| `GET` | `/api/v1/upstreams/multi-parameter-flows` | Multi-parameter flow mapping (IP-to-IP, Prefix-to-Prefix, Device-to-IP, ASN-to-ASN) |
| `GET` | `/api/v1/mobile/summary` | Lightweight executive summary tailored for mobile apps and PWA |

### Engineering, Capacity & Billing
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/qos/breakdown` | DSCP / ToS traffic distribution and CBQoS validation |
| `GET` | `/api/v1/capacity/forecast` | Bandwidth exhaustion date projection |
| `GET` | `/api/v1/billing/p95` | 95th Percentile burstable rate calculation |
| `GET` | `/api/v1/devices` | Inventory of 1,000+ routers and switches |
| `GET` | `/api/v1/raw-flows` | Columnar SQL flow query explorer |
| `WS`  | `/ws/live` | WebSocket feed for real-time pulse and attack ticks |

---

## 📄 License & Confidentiality
AegisFlow is developed for carrier and enterprise network intelligence. Flow telemetry, customer topologies, and routing metadata remain strictly on-premise in compliance with the **AegisFlow Air-Gap & Zero-Exfiltration Security Mandate**.
