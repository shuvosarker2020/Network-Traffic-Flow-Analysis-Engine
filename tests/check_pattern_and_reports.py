import urllib.request
import json

def test_pattern_and_reports():
    base_url = "http://localhost:8080/api/v1"
    print("Testing Multi-Condition Filtering & Automated Reporting APIs:")
    print("=" * 65)

    # 1. Multi-Condition Pattern Query: ASN to ASN & Specific IP
    req_body = json.dumps({
        "src_as": 3356, # Lumen Transit
        "dst_as": 15169, # Google
        "dst_country": "US",
        "time_window_minutes": 120
    }).encode("utf-8")
    req = urllib.request.Request(f"{base_url}/pattern/query", data=req_body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        print(f"[200] POST /pattern/query (ASN 3356 -> 15169 & US) -> Wire-Rate: {data['summary'].get('avg_mbps', 0)} Mbps, Flows: {data['summary'].get('flow_count', 0)}")

    # 2. Multi-Condition Pattern Query: Source Prefix to Interface & Destination Prefix & Device
    req_body2 = json.dumps({
        "src_prefix": "10.0.0.0/16",
        "dst_prefix": "8.8.8.0/24",
        "time_window_minutes": 60
    }).encode("utf-8")
    req2 = urllib.request.Request(f"{base_url}/pattern/query", data=req_body2, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req2) as resp:
        data2 = json.loads(resp.read().decode())
        print(f"[200] POST /pattern/query (Prefix 10.0.0.0/16 -> 8.8.8.0/24) -> Wire-Rate: {data2['summary'].get('avg_mbps', 0)} Mbps, Top Convs: {len(data2.get('top_conversations', []))}")

    # 3. Filter Options Autocomplete
    with urllib.request.urlopen(f"{base_url}/pattern/options") as resp:
        opts = json.loads(resp.read().decode())
        print(f"[200] GET  /pattern/options -> ASNs: {len(opts.get('asns', []))}, Devices: {len(opts.get('devices', []))}, Interfaces: {len(opts.get('interfaces', []))}")

    # 4. List Reports
    with urllib.request.urlopen(f"{base_url}/reports") as resp:
        reports = json.loads(resp.read().decode())
        print(f"[200] GET  /reports -> Saved Reports: {len(reports)}")

    # 5. Create a Custom Multi-Condition Report
    custom_report = {
        "name": "Lumen Transit to Google DC Saturation Report",
        "description": "Monitors traffic from AS3356 to AS15169 over 100GE links with automated daily email dispatch.",
        "conditions": {
            "src_as": 3356,
            "dst_as": 15169,
            "src_prefix": "10.0.0.0/16",
            "time_window_minutes": 60
        },
        "schedule": "DAILY",
        "recipients": ["netops-lead@carrier.internal", "capacity-planning@company.com"],
        "webhook_url": "http://localhost:8080/api/v1/alerts/mock-webhook",
        "status": "ACTIVE"
    }
    req_rep = urllib.request.Request(f"{base_url}/reports", data=json.dumps(custom_report).encode("utf-8"), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req_rep) as resp:
        saved_rep = json.loads(resp.read().decode())["report"]
        rep_id = saved_rep["id"]
        print(f"[200] POST /reports -> Created Report ID: {rep_id} ('{saved_rep['name']}')")

    # 6. Execute Report and Trigger Automated Notification
    req_run = urllib.request.Request(f"{base_url}/reports/{rep_id}/run?notify=true", method="POST")
    with urllib.request.urlopen(req_run) as resp:
        run_res = json.loads(resp.read().decode())["run"]
        email_status = run_res["dispatch_status"]["email"]["status"]
        print(f"[200] POST /reports/{rep_id}/run -> Executed! Wire-Rate: {run_res['avg_mbps']} Mbps, Email Status: {email_status}")

    # 7. HTML Export
    with urllib.request.urlopen(f"{base_url}/reports/{rep_id}/export/html") as resp:
        html = resp.read().decode()
        print(f"[200] GET  /reports/{rep_id}/export/html -> Generated HTML ({len(html)} bytes)")

    # 8. CSV Export
    with urllib.request.urlopen(f"{base_url}/reports/{rep_id}/export/csv") as resp:
        csv_text = resp.read().decode()
        print(f"[200] GET  /reports/{rep_id}/export/csv -> Generated CSV ({len(csv_text.splitlines())} lines)")

    # 9. In-App Notifications List
    with urllib.request.urlopen(f"{base_url}/notifications") as resp:
        notifs = json.loads(resp.read().decode())
        print(f"[200] GET  /notifications -> Logged In-App Alerts: {len(notifs)}")

    print("=" * 65)
    print("ALL MULTI-CONDITION FILTER & REPORTING TESTS PASSED (100% OK)!")

if __name__ == "__main__":
    test_pattern_and_reports()
