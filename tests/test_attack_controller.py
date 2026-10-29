"""
Test Attack Simulator Controller
"""
import sys
import os
sys.path.insert(0, os.path.abspath("."))

from simulation.attack_simulator import attack_controller, generate_custom_attack_flows

def test_controller():
    print("Testing Attack Campaign Controller...")
    status = attack_controller.start_attack(
        target_ip="10.0.1.75",
        protocol="TCP_SYN",
        target_port=443,
        intensity="high"
    )
    print("Started attack status:", status)
    assert status["active"] is True
    assert status["target_ip"] == "10.0.1.75"
    assert status["protocol"] == "TCP_SYN"
    assert status["target_port"] == 443

    # Generate a batch
    batch = attack_controller.generate_next_batch()
    print(f"Generated {len(batch)} attack flow records.")
    assert len(batch) > 0
    print("Current status:", attack_controller.get_status())

    # Test Stop
    stop_status = attack_controller.stop_attack()
    print("Stopped attack status:", stop_status)
    assert stop_status["active"] is False

    # Test other protocols
    for proto in ["UDP_DNS", "UDP_NTP", "ICMP", "HTTP", "LATERAL", "COMBINED"]:
        flows = generate_custom_attack_flows(target_ip="192.168.1.50", protocol=proto, target_port=8080)
        print(f"Protocol {proto}: generated {len(flows)} flows.")
        assert len(flows) > 0

    print("ALL ATTACK CONTROLLER TESTS PASSED!")

if __name__ == "__main__":
    test_controller()
