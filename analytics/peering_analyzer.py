"""
ASN-to-ASN & Peering Analytics for AegisFlow
Computes autonomous system traffic matrix, peering vs transit distribution, and cost optimization opportunities.
"""

from typing import List, Dict, Any
from storage.engine import BaseStorageEngine
from enrichment.bgp_asn import asn_analyzer

class PeeringAnalyzer:
    def __init__(self, storage: BaseStorageEngine):
        self.storage = storage

    def get_asn_matrix(self, limit: int = 20, minutes: int = 60) -> List[Dict[str, Any]]:
        """Calculates ASN-to-ASN traffic conversations."""
        sql = f"""
        SELECT 
            src_as,
            src_as_name,
            dst_as,
            dst_as_name,
            dst_as_category,
            SUM(bytes) AS bytes,
            SUM(packets) AS packets,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
        GROUP BY src_as, src_as_name, dst_as, dst_as_name, dst_as_category
        ORDER BY bytes DESC
        LIMIT {limit};
        """
        rows = self.storage.query(sql)
        for r in rows:
            eval_res = asn_analyzer.evaluate_peering_opportunity(r["src_as"], r["dst_as"], r["mbps"])
            r["peering_candidate"] = eval_res["peering_candidate"]
            r["monthly_transit_cost_usd"] = eval_res["monthly_transit_cost_estimate_usd"]
            r["potential_monthly_savings_usd"] = eval_res["potential_monthly_savings_usd"]
        return rows

    def get_transit_vs_peering_summary(self, minutes: int = 60) -> Dict[str, Any]:
        """Summarizes ratio between Paid Transit, Free Peering, and Internal/Customer traffic."""
        sql = f"""
        SELECT 
            dst_as_category,
            SUM(bytes) AS bytes,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
        GROUP BY dst_as_category
        ORDER BY bytes DESC;
        """
        rows = self.storage.query(sql)
        total_bytes = sum(r.get("bytes", 0) for r in rows)
        summary = {"categories": rows, "total_bytes": total_bytes}
        return summary
