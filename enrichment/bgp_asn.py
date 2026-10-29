"""
BGP ASN & Peering Optimization Analyzer for AegisFlow
Categorizes Autonomous Systems (Tier-1 Transit, Settlement-free Peering, IXP, Internal)
and calculates peering optimization opportunities to reduce transit costs.
"""

import json
import os
from typing import Dict, Any

class ASNPeeringAnalyzer:
    def __init__(self, asns_file: str = "config/asns.json"):
        self.asns: Dict[str, Dict[str, Any]] = {}
        if os.path.exists(asns_file):
            try:
                with open(asns_file, "r") as f:
                    self.asns = json.load(f)
            except Exception:
                pass

    def get_asn_info(self, asn: int) -> Dict[str, Any]:
        asn_str = str(asn)
        if asn_str in self.asns:
            return self.asns[asn_str]
        
        # Heuristic categorization for unlisted ASNs
        if asn == 0:
            return {"name": "Local / Non-BGP", "category": "Internal", "country": "LOCAL", "transit_cost_usd_mbps": 0.0}
        if 64512 <= asn <= 65534:
            return {"name": f"Private ASN {asn}", "category": "Internal / Customer", "country": "LOCAL", "transit_cost_usd_mbps": 0.0}
        return {"name": f"AS{asn}", "category": "Transit / Peer", "country": "UNKNOWN", "transit_cost_usd_mbps": 0.35}

    def evaluate_peering_opportunity(self, src_asn: int, dst_asn: int, total_mbps: float) -> Dict[str, Any]:
        """
        Determines whether traffic sending to dst_asn over transit could be saved via IXP/PNI peering.
        """
        src_info = self.get_asn_info(src_asn)
        dst_info = self.get_asn_info(dst_asn)

        is_peering_candidate = "Peering" in dst_info.get("category", "") or "CDN" in dst_info.get("category", "")
        transit_cost_per_mbps = dst_info.get("transit_cost_usd_mbps", 0.35)
        monthly_cost_if_transit = total_mbps * transit_cost_per_mbps * 720 # hours in a month roughly

        return {
            "src_asn": src_asn,
            "src_name": src_info["name"],
            "dst_asn": dst_asn,
            "dst_name": dst_info["name"],
            "dst_category": dst_info["category"],
            "peering_candidate": is_peering_candidate,
            "monthly_transit_cost_estimate_usd": round(monthly_cost_if_transit, 2),
            "potential_monthly_savings_usd": round(monthly_cost_if_transit, 2) if is_peering_candidate else 0.0
        }

asn_analyzer = ASNPeeringAnalyzer()
