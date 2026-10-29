"""
95th Percentile & Customer Chargeback Invoicing Engine for AegisFlow
Implements telecom standard 95th percentile burstable billing and multi-tenant chargebacks.
"""

from typing import List, Dict, Any
from storage.engine import BaseStorageEngine

class BillingEngine:
    def __init__(self, storage: BaseStorageEngine):
        self.storage = storage

    def calculate_95th_percentile(self, interface_filter: str = None, days: int = 30) -> Dict[str, Any]:
        """
        Calculates 95th percentile burstable billing rate across 5-minute data samples.
        """
        where_clause = f"timestamp >= NOW() - INTERVAL '{days} DAY'"
        if interface_filter:
            where_clause += f" AND in_if_name = '{interface_filter}'"

        sql = f"""
        SELECT 
            time_bucket(INTERVAL '300 SECOND', timestamp) AS bucket,
            SUM(bytes) * 8.0 / (300.0 * 1000000.0) AS mbps,
            SUM(bytes) AS bytes
        FROM raw_flows
        WHERE {where_clause}
        GROUP BY bucket
        ORDER BY mbps ASC;
        """
        rows = self.storage.query(sql)

        if not rows:
            # Fallback for fresh test system
            return {
                "period_days": days,
                "total_samples": 0,
                "p95_mbps": 0.0,
                "max_peak_mbps": 0.0,
                "average_mbps": 0.0,
                "total_transfer_tb": 0.0,
                "estimated_invoice_usd": 0.0
            }

        sample_count = len(rows)
        # 95th percentile index (0-indexed)
        p95_index = int(0.95 * sample_count)
        p95_index = min(p95_index, sample_count - 1)
        p95_mbps = rows[p95_index]["mbps"]
        max_peak = rows[-1]["mbps"]
        avg_mbps = sum(r["mbps"] for r in rows) / sample_count
        total_bytes = sum(r["bytes"] for r in rows)
        total_tb = total_bytes / (1024 ** 4)

        # Standard carrier commitment calculation ($1.25 per Mbps for burst over commit)
        commit_rate_mbps = 5000.0
        billable_burst = max(0.0, p95_mbps - commit_rate_mbps)
        invoice_total = (commit_rate_mbps * 0.85) + (billable_burst * 1.45)

        return {
            "period_days": days,
            "total_samples": sample_count,
            "p95_mbps": round(p95_mbps, 2),
            "max_peak_mbps": round(max_peak, 2),
            "average_mbps": round(avg_mbps, 2),
            "commit_rate_mbps": commit_rate_mbps,
            "billable_burst_mbps": round(billable_burst, 2),
            "total_transfer_tb": round(total_tb, 3),
            "estimated_invoice_usd": round(invoice_total, 2)
        }

    def generate_tenant_chargeback_report(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Generates departmental and customer bandwidth chargeback summary.
        """
        sql = f"""
        SELECT 
            dst_cloud AS tenant_or_group,
            SUM(bytes) AS bytes,
            SUM(packets) AS packets,
            ROUND(SUM(bytes) / (1024.0 * 1024.0 * 1024.0 * 1024.0), 3) AS transfer_tb
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{days} DAY'
        GROUP BY dst_cloud
        ORDER BY bytes DESC;
        """
        rows = self.storage.query(sql)
        # Assign price per TB (e.g. $15.00 / TB)
        rate_per_tb = 15.0
        for r in rows:
            r["rate_per_tb_usd"] = rate_per_tb
            r["chargeback_cost_usd"] = round(r["transfer_tb"] * rate_per_tb, 2)
        return rows
