"""
Integration & End-to-End Test for Upstream Providers & IIG Traffic Shifting (>1,000 Gbps Scale)
Tests:
1. Upstream Providers CRUD (Tata, Airtel, Cogent, NTT, Telia, GGC, FNA, MixCDN, Baishan, IX)
2. Capacity & Utilization Calculation (>1,000 Gbps / Terabit scale)
3. Automated Traffic Shift Suggestions with BGP route policies
4. Multi-Parameter Flow Mapping (IP-to-IP, Prefix-to-Prefix, Device-to-IP, ASN-to-ASN, Upstream-to-Service)
5. Mobile API Hub (/api/v1/mobile/summary)
6. PWA Manifest & Service Worker verification
"""

import urllib.request
import json
import time

BASE_URL = "http://localhost:8080/api/v1"

def test_upstream_traffic_shifter():
    print("=" * 70)
    print("  TESTING UPSTREAM BANDWIDTH & IIG TRAFFIC SHIFT ENGINE (>1000 Gbps)")
    print("=" * 70)

    # 1. Test GET /api/v1/upstreams
    print("\n1. Testing Upstream Utilization & Terabit Summary:")
    res = urllib.request.urlopen(f"{BASE_URL}/upstreams?minutes=5")
    assert res.status == 200
    data = json.loads(res.read().decode())
    summary = data["summary"]
    print(f"   Total Purchased Capacity: {summary['total_capacity_tbps']} Tbps ({summary['total_capacity_gbps']} Gbps)")
    print(f"   Current Total Utilized:   {summary['total_utilized_gbps']} Gbps ({summary['overall_utilization_pct']}%)")
    print(f"   Overall Available Headroom: {summary['overall_headroom_gbps']} Gbps")
    print(f"   Congested IIG Links:      {summary['congested_count']}")
    assert summary["total_capacity_gbps"] >= 1000.0, "Capacity should exceed 1,000 Gbps scale"
    assert len(data["upstreams"]) >= 5, "Should have at least 5 upstream providers configured"

    # Verify standard services exist
    service_names = {u["service_name"] for u in data["upstreams"]}
    print(f"   Configured Services: {sorted(list(service_names))}")
    for required_svc in ["IPT", "PNI", "MixCDN", "Baishan", "IX", "GGC", "FNA"]:
        assert required_svc in service_names, f"Service {required_svc} must be supported"

    # 2. Test Adding a New Upstream Provider & Service On-Demand
    print("\n2. Testing On-Demand Upstream Provider Addition:")
    new_provider_payload = json.dumps({
        "provider_name": "SEA-ME-WE-5 Consortium",
        "service_name": "IPT",
        "capacity_gbps": 500.0,
        "warn_threshold_pct": 80.0,
        "crit_threshold_pct": 90.0,
        "cost_per_mbps": 0.30,
        "associated_asns": [45454],
        "associated_interfaces": ["HundredGigE0/0/0/50", "HundredGigE0/0/0/51"]
    }).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}/upstreams", data=new_provider_payload, headers={"Content-Type": "application/json"})
    res = urllib.request.urlopen(req)
    assert res.status == 200
    created_resp = json.loads(res.read().decode())
    new_id = created_resp["upstream"]["id"]
    print(f"   Created Upstream: {new_id} ({created_resp['upstream']['provider_name']} - {created_resp['upstream']['service_name']} - {created_resp['upstream']['capacity_gbps']} Gbps)")
    assert created_resp["upstream"]["capacity_gbps"] == 500.0

    # 3. Test Automated Traffic Shift Suggestions
    print("\n3. Testing Smart Traffic Shift Suggestions & BGP Policy Generation:")
    res = urllib.request.urlopen(f"{BASE_URL}/upstreams/shift-suggestions?minutes=5")
    assert res.status == 200
    suggestions = json.loads(res.read().decode())
    print(f"   Active Shift Recommendations: {len(suggestions)}")
    assert len(suggestions) > 0, "Should generate traffic shift suggestion for congested link"

    top_s = suggestions[0]
    print(f"   Recommendation: {top_s['title']}")
    print(f"   Source IIG:     {top_s['source_upstream']['provider_name']} at {top_s['source_upstream']['utilization_pct']}%")
    print(f"   Target IIG:     {top_s['target_upstream']['provider_name']} (Headroom: {top_s['target_upstream']['headroom_gbps']} Gbps)")
    print(f"   Shift Amount:   {top_s['shift_amount_gbps']} Gbps")
    print(f"   Candidate ASNs: {[a['name'] for a in top_s['candidate_asns']]}")
    assert "cisco_iosxr" in top_s["bgp_commands"]
    assert "juniper_junos" in top_s["bgp_commands"]
    assert "route-policy" in top_s["bgp_commands"]["cisco_iosxr"]
    assert "local-preference" in top_s["bgp_commands"]["juniper_junos"]

    # 4. Test Traffic Shift Execution Dispatcher
    print("\n4. Testing Traffic Shift Deployment Dispatcher:")
    exec_payload = json.dumps(top_s).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}/upstreams/shift-execute", data=exec_payload, headers={"Content-Type": "application/json"})
    res = urllib.request.urlopen(req)
    assert res.status == 200
    exec_resp = json.loads(res.read().decode())
    print(f"   Shift Deployment: {exec_resp['status']} - {exec_resp['message']}")
    assert exec_resp["status"] == "EXECUTED"

    # 5. Test Multi-Parameter Flow Mapping
    print("\n5. Testing Multi-Parameter Flow Correlation:")
    for mode in ["IP_TO_IP", "PREFIX_TO_PREFIX", "DEVICE_TO_IP", "ASN_TO_ASN", "UPSTREAM_TO_SERVICE"]:
        res = urllib.request.urlopen(f"{BASE_URL}/upstreams/multi-parameter-flows?group_by={mode}&minutes=60&limit=10")
        assert res.status == 200
        mapping_data = json.loads(res.read().decode())
        print(f"   [{mode:<20}] Total Records: {mapping_data['total_records']}, Wire-Rate: {mapping_data['total_gbps']} Gbps")
        assert mapping_data["group_by"] == mode

    # 6. Test Mobile API Hub
    print("\n6. Testing Mobile App Endpoint (/api/v1/mobile/summary):")
    res = urllib.request.urlopen(f"{BASE_URL}/mobile/summary")
    assert res.status == 200
    mob = json.loads(res.read().decode())
    print(f"   Network Status:     {mob['network_status']}")
    print(f"   Capacity:           {mob['total_capacity_tbps']} Tbps")
    print(f"   Total Utilized:     {mob['total_utilized_gbps']} Gbps")
    print(f"   Congested IIGs:     {mob['congested_upstreams_count']}")
    print(f"   Shift Suggestions:  {mob['shift_suggestions_count']}")
    assert "total_capacity_tbps" in mob
    assert "upstreams" in mob

    # 7. Test PWA Manifest & Service Worker
    print("\n7. Testing PWA Manifest & Service Worker Static Hosting:")
    man_res = urllib.request.urlopen("http://localhost:8080/static/manifest.json")
    assert man_res.status == 200
    manifest = json.loads(man_res.read().decode())
    print(f"   PWA Name:    {manifest['name']}")
    print(f"   PWA Display: {manifest['display']}")
    assert manifest["display"] == "standalone"

    sw_res = urllib.request.urlopen("http://localhost:8080/static/sw.js")
    assert sw_res.status == 200
    sw_code = sw_res.read().decode()
    print(f"   Service Worker: Loaded ({len(sw_code)} bytes)")
    assert "addEventListener('install'" in sw_code

    # 8. Clean up created upstream
    print("\n8. Cleaning up created test upstream:")
    del_req = urllib.request.Request(f"{BASE_URL}/upstreams/{new_id}", method="DELETE")
    res = urllib.request.urlopen(del_req)
    assert res.status == 200
    print(f"   Cleaned up test upstream {new_id} successfully.")

    print("\n" + "=" * 70)
    print("  ALL UPSTREAM BANDWIDTH & TRAFFIC SHIFT TESTS PASSED (100% OK)!")
    print("=" * 70)


if __name__ == "__main__":
    test_upstream_traffic_shifter()
