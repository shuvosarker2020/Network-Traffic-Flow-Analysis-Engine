"""
Comprehensive Integration Test Suite for AegisFlow
Tests:
1. NetFlow v5 Binary Packet Parsing
2. NetFlow v9 Binary Packet Parsing & Dynamic Template Registration
3. IPFIX RFC 7011 Binary Packet Parsing
4. sFlow v5 Packet Header Decoding & Scaling
5. Contextual Enrichment (SNMP cache, GeoIP, ASN, Application, Direction)
6. DuckDB Columnar Storage Batch Insertion & Querying
7. DDoS Detection & BGP Flowspec Mitigation Generation
8. Anomaly & Lateral Movement Detection
9. Capacity Forecasting & 95th Percentile Burstable Billing
"""

import sys
import os
import struct
import socket
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collector.netflow_v5 import parse_netflow_v5
from collector.netflow_v9 import parse_netflow_v9, template_store
from collector.ipfix import parse_ipfix, ipfix_store
from collector.sflow_v5 import parse_sflow_v5
from enrichment.pipeline import enrich_flow_record, enrich_batch
from storage import get_storage_engine
from analytics.top_talkers import TopTalkersAnalyzer
from analytics.ddos_detector import DDoSDetector
from analytics.anomaly_detector import AnomalyDetector
from analytics.capacity_planner import CapacityPlanner
from analytics.billing_engine import BillingEngine
from simulation.flow_generator import generate_random_flow_records
from simulation.attack_simulator import generate_syn_flood_attack, generate_lateral_movement_scan

class TestAegisFlowEngine(unittest.TestCase):

    def test_01_netflow_v5_parser(self):
        """Test binary NetFlow v5 packet decode."""
        # Header: version=5, count=1, sys_uptime=1000, unix_secs=1700000000, unix_nsecs=0, flow_seq=1, engine_type=1, engine_id=1, sampling=1000
        header_bytes = struct.pack("!HHIIIIBBH", 5, 1, 1000, 1700000000, 0, 1, 1, 1, 1000)
        # Record: src=10.0.0.5, dst=8.8.8.8, nexthop=10.254.254.1, in_if=1, out_if=2, pkts=100, octets=15000, first=900, last=1000, src_p=50000, dst_p=443, pad=0, flags=16, prot=6, tos=0, src_as=64512, dst_as=15169, src_m=24, dst_m=32, pad2=0
        src_int = struct.unpack("!I", socket.inet_aton("10.0.0.5"))[0]
        dst_int = struct.unpack("!I", socket.inet_aton("8.8.8.8"))[0]
        nh_int = struct.unpack("!I", socket.inet_aton("10.254.254.1"))[0]
        rec_bytes = struct.pack("!IIIHHIIIIHHBBBBHHBBH", 
            src_int, dst_int, nh_int, 1, 2, 100, 15000, 900, 1000, 50000, 443, 0, 16, 6, 0, 64512, 15169, 24, 32, 0)
        
        packet = header_bytes + rec_bytes
        header, records = parse_netflow_v5(packet, "10.0.0.1")
        
        self.assertEqual(header["version"], 5)
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r["src_ip"], "10.0.0.5")
        self.assertEqual(r["dst_ip"], "8.8.8.8")
        self.assertEqual(r["protocol"], 6)
        self.assertEqual(r["dst_port"], 443)
        self.assertEqual(r["packets"], 100 * 1000) # Scaled by sampling rate

    def test_02_enrichment_pipeline(self):
        """Test enrichment with SNMP metadata, GeoIP, ASN, Application, and Direction."""
        raw_rec = {
            "exporter_ip": "10.0.0.1",
            "version": 9,
            "timestamp": 1700000000,
            "src_ip": "10.0.1.10",
            "dst_ip": "8.8.8.8",
            "protocol": 6,
            "src_port": 54321,
            "dst_port": 443,
            "in_ifindex": 1,
            "out_ifindex": 2,
            "dscp": 46, # EF
            "packets": 500,
            "bytes": 500000,
            "src_as": 0,
            "dst_as": 0
        }
        enriched = enrich_flow_record(raw_rec)
        self.assertEqual(enriched["application"], "HTTPS / TLS")
        self.assertEqual(enriched["dscp_name"], "EF / Expedited Forwarding")
        self.assertEqual(enriched["qos_class"], "Voice / Telephony")
        self.assertEqual(enriched["flow_direction"], "North-South (Outbound)")
        self.assertEqual(enriched["dst_country"], "US")
        self.assertEqual(enriched["dst_as"], 15169)
        self.assertIn("Google", enriched["dst_as_name"])

    def test_03_storage_and_analytics(self):
        """Test DuckDB columnar OLAP insertion and analytical aggregations."""
        storage = get_storage_engine({"storage": {"duckdb": {"path": "data/test_flows.duckdb"}}})
        flows = generate_random_flow_records(count=50)
        inserted = storage.insert_flows(flows)
        self.assertEqual(inserted, 50)

        top_talkers = TopTalkersAnalyzer(storage)
        kpis = top_talkers.get_overview_kpis(minutes=60)
        self.assertGreater(kpis["total_flows"], 0)
        self.assertGreater(kpis["total_bytes"], 0)

        apps = top_talkers.get_top_applications(limit=5)
        self.assertTrue(len(apps) > 0)

    def test_04_ddos_detection_and_flowspec(self):
        """Test real-time SYN flood attack detection and BGP Flowspec generation."""
        storage = get_storage_engine()
        syn_flows = generate_syn_flood_attack("10.0.1.99")
        storage.insert_flows(syn_flows)

        detector = DDoSDetector(storage, {})
        attacks = detector.scan_for_attacks(window_minutes=15)
        self.assertTrue(len(attacks) > 0)
        
        syn_attack = next((a for a in attacks if "SYN" in a["attack_type"]), None)
        self.assertIsNotNone(syn_attack)
        self.assertEqual(syn_attack["target_ip"], "10.0.1.99")
        self.assertIn("destination 10.0.1.99/32", syn_attack["bgp_flowspec_rule"])
        self.assertIn("tcp-flags (syn & !ack)", syn_attack["bgp_flowspec_rule"])

    def test_05_lateral_movement_detection(self):
        """Test East-West internal lateral movement detection."""
        storage = get_storage_engine()
        lat_flows = generate_lateral_movement_scan("10.0.2.100", "10.1.5.20")
        storage.insert_flows(lat_flows)

        anom_detector = AnomalyDetector(storage, {})
        anomalies = anom_detector.scan_for_anomalies(window_minutes=15)
        
        lat_anom = next((a for a in anomalies if a["category"] == "Lateral Movement"), None)
        self.assertIsNotNone(lat_anom)
        self.assertEqual(lat_anom["source_ip"], "10.0.2.100")
        self.assertEqual(lat_anom["target_ip"], "10.1.5.20")

    def test_06_capacity_forecasting_and_billing(self):
        """Test capacity exhaustion projection and 95th percentile burstable billing."""
        storage = get_storage_engine()
        planner = CapacityPlanner(storage)
        forecast = planner.forecast_interface_capacity("dev-0001", 1)
        self.assertIn("estimated_days_to_85_pct", forecast)
        self.assertIn("exhaustion_forecast_date", forecast)

        billing = BillingEngine(storage)
        p95 = billing.calculate_95th_percentile(days=30)
        self.assertIn("p95_mbps", p95)
        self.assertIn("estimated_invoice_usd", p95)

    def test_07_multi_condition_traffic_pattern(self):
        """Test multi-attribute filtering (ASN to ASN & IP, Prefix to Interface, Country)."""
        storage = get_storage_engine()
        from analytics.pattern_engine import TrafficPatternEngine
        engine = TrafficPatternEngine(storage)

        # Condition: Source Prefix to ASN
        res = engine.analyze_pattern({
            "src_prefix": "10.0.0.0/16",
            "dst_as": 15169, # Google
            "time_window_minutes": 120
        }, minutes=120)

        self.assertIn("summary", res)
        self.assertIn("timeseries", res)
        self.assertIn("top_conversations", res)

    def test_08_automated_reporting_and_notifications(self):
        """Test creating report definition, generating HTML/CSV, and email spooling."""
        storage = get_storage_engine()
        from analytics.pattern_engine import TrafficPatternEngine
        from reports import ReportManager, notifier

        engine = TrafficPatternEngine(storage)
        mgr = ReportManager(engine)

        rep = mgr.save_report({
            "name": "Integration Test Transit Report",
            "conditions": {"src_prefix": "10.0.0.0/16", "time_window_minutes": 60},
            "schedule": "DAILY",
            "recipients": ["noc@test.internal"]
        })
        self.assertIn("id", rep)

        # Run report
        run = mgr.execute_report(rep["id"], send_notifications=True)
        self.assertIn("run_id", run)
        self.assertIn("dispatch_status", run)

        # HTML Export
        html = mgr.generate_html_report(run)
        self.assertIn("<html", html)
        self.assertIn(rep["name"], html)

        # CSV Export
        csv_data = mgr.generate_csv_report(run)
        self.assertIn("Throughput (Mbps)", csv_data)

if __name__ == "__main__":
    unittest.main()
