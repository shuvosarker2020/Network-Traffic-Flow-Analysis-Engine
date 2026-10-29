"""
QoS & CBQoS Validation Engine for AegisFlow
Verifies mission-critical traffic tagging (EF, AF41, CS6) and detects DSCP mismatches.
"""

from typing import List, Dict, Any
from storage.engine import BaseStorageEngine

class QoSAnalyzer:
    def __init__(self, storage: BaseStorageEngine):
        self.storage = storage

    def get_qos_breakdown(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Returns traffic volume per DSCP class."""
        sql = f"""
        SELECT 
            dscp,
            dscp_name,
            qos_class,
            SUM(bytes) AS bytes,
            SUM(packets) AS packets,
            ROUND(SUM(bytes) * 8.0 / ({minutes} * 60.0 * 1000000.0), 2) AS mbps,
            COUNT(*) AS flow_count
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
        GROUP BY dscp, dscp_name, qos_class
        ORDER BY bytes DESC;
        """
        rows = self.storage.query(sql)
        total_bytes = sum(r.get("bytes", 0) for r in rows)
        for r in rows:
            r["percentage"] = round((r.get("bytes", 0) / max(1, total_bytes)) * 100.0, 2)
        return rows

    def validate_policy_compliance(self, minutes: int = 60) -> Dict[str, Any]:
        """
        Detects mission-critical protocols improperly tagged as CS0 (Best Effort).
        For example: Voice (SIP/RTP) tagged as Best Effort instead of EF,
        or BGP routing tagged as Best Effort instead of CS6.
        """
        sql = f"""
        SELECT 
            application,
            dscp_name,
            COUNT(*) as violations_count,
            SUM(bytes) as violation_bytes
        FROM raw_flows
        WHERE timestamp >= NOW() - INTERVAL '{minutes} MINUTE'
          AND application IN ('SIP / VoIP', 'RTP Audio/Video', 'BGP')
          AND dscp = 0
        GROUP BY application, dscp_name;
        """
        violations = self.storage.query(sql)
        return {
            "compliant": len(violations) == 0,
            "violations": violations,
            "status": "POLICY_VIOLATION_DETECTED" if violations else "ALL_POLICIES_VALID"
        }
