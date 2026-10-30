"""
Integration & End-to-End Test for Date Range Filtering & Traffic Pattern Demand Comparison (DoD, WoW, MoM)
Tests:
1. Multi-Condition Pattern Query with Exact Date & Time Range (/api/v1/pattern/query)
2. Day-to-Day (DoD) Traffic Pattern Demand Comparison (/api/v1/pattern/compare)
3. Week-to-Week (WoW) Traffic Pattern Demand Comparison (/api/v1/pattern/compare)
4. Month-by-Month (MoM) Traffic Pattern Demand Comparison (/api/v1/pattern/compare)
5. Custom Range Comparison (/api/v1/pattern/compare)
6. Filtered Pattern Comparison (by ASN 15169 Google, Upstream Provider Tata)
7. Multi-Parameter Flow Correlation with Date Range (/api/v1/upstreams/multi-parameter-flows)
8. Raw Flows Date Interval Filter (/api/v1/raw-flows)
9. Pattern Filter Options with Upstream & Services (/api/v1/pattern/options)
"""

import unittest
import urllib.request
import json

BASE_URL = "http://localhost:8080/api/v1"

class TestDateFilterAndPatternComparison(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Verify server is reachable
        try:
            res = urllib.request.urlopen(f"{BASE_URL}/health", timeout=5)
            assert res.status == 200
        except Exception as e:
            raise unittest.SkipTest(f"AegisFlow server not running at {BASE_URL}: {e}")

    def test_01_pattern_query_custom_date_range(self):
        """Test POST /api/v1/pattern/query with exact historical date range."""
        payload = json.dumps({
            "start_time": "2026-10-29 10:00:00",
            "end_time": "2026-10-30 10:00:00"
        }).encode("utf-8")
        req = urllib.request.Request(f"{BASE_URL}/pattern/query", data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertIn("summary", data)
            self.assertIn("timeseries", data)
            summary = data["summary"]
            self.assertGreater(summary.get("flow_count", 0), 0)
            self.assertGreater(summary.get("total_bytes", 0), 0)
            self.assertGreater(summary.get("avg_mbps", 0.0), 0.0)
            print(f"\n1. Date Filtered Pattern Query (2026-10-29 10:00 to 2026-10-30 10:00):")
            print(f"   Matched Flows:      {summary['flow_count']:,}")
            print(f"   Total Data Volume:  {summary['total_bytes'] / (1024**4):.2f} TB")
            print(f"   Wire-Rate:          {summary['avg_mbps']:,} Mbps")
            print(f"   Timeseries Points:  {len(data['timeseries'])}")

    def test_02_day_to_day_comparison(self):
        """Test Day-to-Day (DoD) comparison: 24 synchronized hourly points."""
        payload = json.dumps({
            "compare_mode": "DAY_TO_DAY",
            "criteria": {"selected_date": "2026-10-30"}
        }).encode("utf-8")
        req = urllib.request.Request(f"{BASE_URL}/pattern/compare", data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertEqual(data["status"], "SUCCESS")
            self.assertEqual(data["compare_mode"], "DAY_TO_DAY")
            self.assertIn("summary_delta", data)
            self.assertIn("divergence", data)
            self.assertIn("timeseries_comparison", data)
            self.assertEqual(len(data["timeseries_comparison"]), 24)

            sm = data["summary_delta"]
            print(f"\n2. Day-to-Day (DoD) Pattern Comparison:")
            print(f"   Current Wire-Rate:  {sm['current_avg_mbps']:,} Mbps")
            print(f"   Baseline Wire-Rate: {sm['baseline_avg_mbps']:,} Mbps")
            print(f"   Throughput Delta:   {sm['delta_mbps']} Mbps ({sm['pct_change_mbps']}%)")
            print(f"   Volume Delta:       {sm['delta_gb']} GB")
            print(f"   Trend & Divergence: {sm['trend']} | {data['divergence']['status']}")
            self.assertIn(sm["trend"], ["GROWTH", "REDUCTION", "STABLE"])

    def test_03_week_to_week_comparison(self):
        """Test Week-to-Week (WoW) comparison across 7 daily points."""
        payload = json.dumps({
            "compare_mode": "WEEK_TO_WEEK",
            "criteria": {}
        }).encode("utf-8")
        req = urllib.request.Request(f"{BASE_URL}/pattern/compare", data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertEqual(data["status"], "SUCCESS")
            self.assertEqual(data["compare_mode"], "WEEK_TO_WEEK")
            self.assertEqual(len(data["timeseries_comparison"]), 7)

            sm = data["summary_delta"]
            print(f"\n3. Week-to-Week (WoW) Pattern Comparison:")
            print(f"   Current Wire-Rate:  {sm['current_avg_mbps']:,} Mbps")
            print(f"   Baseline Wire-Rate: {sm['baseline_avg_mbps']:,} Mbps")
            print(f"   Throughput Delta:   {sm['delta_mbps']} Mbps ({sm['pct_change_mbps']}%)")
            print(f"   Synchronized Steps: {len(data['timeseries_comparison'])} days")
            self.assertIn("top_asns", data["dimensional_deltas"])
            self.assertIn("top_applications", data["dimensional_deltas"])

    def test_04_month_by_month_comparison(self):
        """Test Month-by-Month (MoM) comparison across 30 daily points."""
        payload = json.dumps({
            "compare_mode": "MONTH_BY_MONTH",
            "criteria": {}
        }).encode("utf-8")
        req = urllib.request.Request(f"{BASE_URL}/pattern/compare", data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertEqual(data["status"], "SUCCESS")
            self.assertEqual(data["compare_mode"], "MONTH_BY_MONTH")
            self.assertEqual(len(data["timeseries_comparison"]), 30)

            sm = data["summary_delta"]
            print(f"\n4. Month-by-Month (MoM) Pattern Comparison:")
            print(f"   Current Wire-Rate:  {sm['current_avg_mbps']:,} Mbps")
            print(f"   Baseline Wire-Rate: {sm['baseline_avg_mbps']:,} Mbps")
            print(f"   Volume Delta:       {sm['delta_gb']} GB")

    def test_05_custom_horizon_comparison(self):
        """Test Custom Horizon comparison between two custom periods."""
        payload = json.dumps({
            "compare_mode": "CUSTOM",
            "criteria": {},
            "period_current": {
                "start_time": "2026-10-30 08:00:00",
                "end_time": "2026-10-30 16:00:00"
            },
            "period_baseline": {
                "start_time": "2026-10-29 08:00:00",
                "end_time": "2026-10-29 16:00:00"
            }
        }).encode("utf-8")
        req = urllib.request.Request(f"{BASE_URL}/pattern/compare", data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertEqual(data["status"], "SUCCESS")
            self.assertEqual(data["compare_mode"], "CUSTOM")
            self.assertEqual(len(data["timeseries_comparison"]), 12)
            print(f"\n5. Custom Horizon Comparison (8-Hour Window):")
            print(f"   Delta Mbps: {data['summary_delta']['delta_mbps']} Mbps ({data['summary_delta']['pct_change_mbps']}%)")

    def test_06_filtered_comparison_by_asn_and_upstream(self):
        """Test comparing traffic pattern with ASN filter and Upstream Provider filter."""
        # 1. Filtered by Google AS15169
        payload1 = json.dumps({
            "compare_mode": "DAY_TO_DAY",
            "criteria": {"dst_as": 15169}
        }).encode("utf-8")
        req1 = urllib.request.Request(f"{BASE_URL}/pattern/compare", data=payload1, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req1) as resp:
            self.assertEqual(resp.status, 200)
            data1 = json.loads(resp.read().decode())
            self.assertGreater(data1["summary_delta"]["current_avg_mbps"], 0.0)
            print(f"\n6. Filtered Comparison:")
            print(f"   Google AS15169 DoD: Current {data1['summary_delta']['current_avg_mbps']} Mbps vs Baseline {data1['summary_delta']['baseline_avg_mbps']} Mbps")

        # 2. Filtered by Upstream Provider Tata
        payload2 = json.dumps({
            "compare_mode": "DAY_TO_DAY",
            "criteria": {"upstream_provider": "Tata Communications"}
        }).encode("utf-8")
        req2 = urllib.request.Request(f"{BASE_URL}/pattern/compare", data=payload2, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req2) as resp:
            self.assertEqual(resp.status, 200)
            data2 = json.loads(resp.read().decode())
            self.assertEqual(data2["status"], "SUCCESS")
            print(f"   Tata Communications DoD: Current {data2['summary_delta']['current_avg_mbps']} Mbps")

    def test_07_raw_flows_date_filtering(self):
        """Test GET /api/v1/raw-flows with start_time and end_time parameters."""
        url = f"{BASE_URL}/raw-flows?start_time=2026-10-29%2010:00:00&end_time=2026-10-30%2010:00:00&limit=8"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            flows = json.loads(resp.read().decode())
            self.assertGreater(len(flows), 0)
            print(f"\n7. GET /api/v1/raw-flows with Date Bounds: Returned {len(flows)} flows successfully")

    def test_08_multi_parameter_flows_date_filtering(self):
        """Test GET /api/v1/upstreams/multi-parameter-flows with date filtering."""
        url = f"{BASE_URL}/upstreams/multi-parameter-flows?group_by=ASN_TO_ASN&start_time=2026-10-29%2010:00:00&end_time=2026-10-30%2010:00:00&limit=10"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            mp_data = json.loads(resp.read().decode())
            self.assertGreater(mp_data["total_records"], 0)
            self.assertGreater(mp_data["total_gbps"], 0.0)
            print(f"\n8. Multi-Parameter Flows (ASN to ASN with Date Range): {mp_data['total_records']} records, {mp_data['total_gbps']} Gbps")

    def test_09_pattern_options_upstreams_and_services(self):
        """Test GET /api/v1/pattern/options contains upstream providers and services."""
        with urllib.request.urlopen(f"{BASE_URL}/pattern/options") as resp:
            self.assertEqual(resp.status, 200)
            opts = json.loads(resp.read().decode())
            self.assertIn("upstream_providers", opts)
            self.assertIn("services", opts)
            self.assertGreater(len(opts["upstream_providers"]), 0)
            self.assertGreater(len(opts["services"]), 0)
            print(f"\n9. Filter Autocomplete Options:")
            print(f"   Upstream Providers: {opts['upstream_providers'][:5]}")
            print(f"   Services:           {opts['services']}")

if __name__ == "__main__":
    unittest.main()
