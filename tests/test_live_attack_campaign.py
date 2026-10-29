"""
Test live simulated attack campaign start, run, and stop
"""
import urllib.request
import json
import time

def test_attack_campaign():
    base_url = "http://localhost:8080/api/v1/simulate/attack"
    print("Testing Custom Target IP & Protocol Attack Injection:")
    print("=" * 60)

    # 0. Ensure stopped initially
    stop_req = urllib.request.Request(f"{base_url}/stop", data=b"{}", headers={"Content-Type": "application/json"})
    urllib.request.urlopen(stop_req)

    # 1. Check initial status
    res = urllib.request.urlopen(f"{base_url}/status")
    init_status = json.loads(res.read().decode())
    print("1. Initial Attack Status:", init_status)
    assert init_status["active"] is False

    # 2. Start Attack Campaign with Custom Target IP (10.0.1.77) and Protocol (UDP_DNS)
    payload = json.dumps({
        "target_ip": "10.0.1.77",
        "protocol": "UDP_DNS",
        "target_port": 53,
        "intensity": "high"
    }).encode("utf-8")
    req = urllib.request.Request(f"{base_url}/start", data=payload, headers={"Content-Type": "application/json"})
    res = urllib.request.urlopen(req)
    start_resp = json.loads(res.read().decode())
    print("\n2. Start Attack Response:", start_resp["message"])
    assert start_resp["campaign"]["active"] is True
    assert start_resp["campaign"]["target_ip"] == "10.0.1.77"
    assert start_resp["campaign"]["protocol"] == "UDP_DNS"

    # 3. Wait 5 seconds for background worker to inject and commit flow batches
    print("\n3. Waiting 5 seconds while attack campaign runs in background...")
    time.sleep(5.0)

    # 4. Check status during attack
    res = urllib.request.urlopen(f"{base_url}/status")
    running_status = json.loads(res.read().decode())
    print("4. Live Attack Status:")
    print(f"   Target IP: {running_status['target_ip']}")
    print(f"   Protocol:  {running_status['protocol']} (Port {running_status['target_port']})")
    print(f"   Throughput: {running_status['current_mbps']} Mbps ({running_status['current_pps']} PPS)")
    print(f"   Total Packets Blasted: {running_status['total_packets']:,}")
    print(f"   Batches Sent: {running_status['batches_sent']}")
    assert running_status["active"] is True
    assert running_status["total_packets"] > 0
    assert running_status["batches_sent"] >= 2

    # 5. Check if DDoS detector flagged this attack on target IP
    ddos_res = urllib.request.urlopen("http://localhost:8080/api/v1/security/ddos?window_minutes=5")
    attacks = json.loads(ddos_res.read().decode())
    matched_attacks = [a for a in attacks if a.get("target_ip") == "10.0.1.77"]
    print(f"\n5. DDoS Detection Radar found {len(matched_attacks)} attack alerts for target 10.0.1.77:")
    for a in matched_attacks:
        print(f"   - Alert ID: {a.get('alert_id', a.get('id', 'N/A'))}, Type: {a['attack_type']}, Severity: {a['severity']}, Value: {a['metric_value']} {a['unit']}")
    assert len(matched_attacks) > 0

    # 6. Stop Attack Campaign
    stop_req = urllib.request.Request(f"{base_url}/stop", data=b"{}", headers={"Content-Type": "application/json"})
    res = urllib.request.urlopen(stop_req)
    stop_resp = json.loads(res.read().decode())
    print("\n6. Stop Attack Response:", stop_resp["message"])
    assert stop_resp["campaign"]["active"] is False

    # 7. Verify status after stop
    res = urllib.request.urlopen(f"{base_url}/status")
    final_status = json.loads(res.read().decode())
    print("7. Final Status:", final_status)
    assert final_status["active"] is False

    print("\n" + "=" * 60)
    print("ALL ATTACK CAMPAIGN TESTS PASSED WITH 100% SUCCESS!")

if __name__ == "__main__":
    test_attack_campaign()
