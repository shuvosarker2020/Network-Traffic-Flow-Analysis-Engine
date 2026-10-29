# Data Retention, Cryptographic Shredding & Secure Purge Procedures

This guide details procedures for managing flow retention windows, executing cryptographic shredding, and permanently purging sensitive telemetry data from disk.

---

## 1. Automated Rolling Retention (1-3 Months)

AegisFlow enforces rolling data retention using columnar partition drops:

- **DuckDB**:
  - The embedded driver runs a scheduled maintenance thread every 24 hours that executes:
    ```sql
    DELETE FROM raw_flows WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '90 DAY';
    CHECKPOINT;
    ```
- **ClickHouse**:
  - Table definitions in [`storage/schema_clickhouse.sql`](file:///d:/AI-Projects/Traffic-flow-Analysis-Engine/storage/schema_clickhouse.sql) enforce native partition-level retention:
    ```sql
    ENGINE = MergeTree()
    PARTITION BY toYYYYMM(timestamp)
    ORDER BY (timestamp, exporter_ip, src_ip, dst_ip)
    TTL timestamp + INTERVAL 90 DAY DELETE;
    ```
  - When ClickHouse drops a monthly partition via TTL, all underlying columnar compressed blocks are immediately unlinked from the filesystem without fragmentation.

---

## 2. Emergency Cryptographic Data Shredding

In decommissioning scenarios or security incidents where flow intelligence must be permanently wiped according to **NIST SP 800-88 Rev 1 (Guidelines for Media Sanitization)**:

### On Linux:
```bash
# 1. Stop the AegisFlow daemon
systemctl stop aegisflow

# 2. Cryptographically shred DuckDB database files (3-pass overwrite)
shred -u -z -n 3 data/aegisflow.duckdb*

# 3. Securely wipe spooled executive reports and alert history
shred -u -z -n 3 reports/spool/*.html reports/spool/*.csv

# 4. Wipe log files
shred -u -z -n 3 data/*.log
```

### On Windows Server (PowerShell / Cipher):
```powershell
# 1. Stop python service
Stop-Process -Name python -Force

# 2. Remove files
Remove-Item -Recurse -Force data\aegisflow.duckdb*
Remove-Item -Recurse -Force reports\spool\*

# 3. Overwrite unallocated disk space on the volume (3-pass wipe)
cipher /w:D:\AI-Projects\Traffic-flow-Analysis-Engine\data
```

---

## 3. Ephemeral Memory Safety

- AegisFlow stores temporary in-memory ingestion batches in a fixed-size ring queue.
- When batches are flushed to columnar storage, buffer memory references are cleared and reclaimed by the garbage collector.
- No raw packet payloads or decryption keys are ever cached in system temporary directories (`/tmp` or `%TEMP%`).
