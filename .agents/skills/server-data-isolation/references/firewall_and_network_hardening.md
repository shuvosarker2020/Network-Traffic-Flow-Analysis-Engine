# Host Firewall & Network Egress Hardening Rules

This reference provides ready-to-deploy firewall templates for Linux (`iptables`/`nftables`) and Windows Server to ensure complete network isolation for AegisFlow.

---

## 1. Linux `iptables` Policy (Drop-All Egress to Public Internet)

Below is an enterprise policy allowing:
- Loopback traffic (`lo`).
- Ingress UDP flow telemetry from monitored router subnets (e.g. `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- Ingress HTTP/WebSocket management on port 8080 from authorized NOC jumpboxes.
- Outbound responses to established internal management sessions.
- **Strict DROP** of all outbound initiation to non-private / public internet destinations.

```bash
#!/bin/bash
# Flush existing chains
iptables -F
iptables -X

# Set Default Policies to DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# 1. Allow Loopback interface
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 2. Allow Established & Related internal sessions
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 3. Allow Inbound NetFlow / IPFIX / sFlow from Router subnets (Ingress Only)
# Ports: 2055 (NetFlow v5), 2056 (NetFlow v9), 4739 (IPFIX), 6343 (sFlow)
iptables -A INPUT -p udp -m multiport --dports 2055,2056,4739,6343 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p udp -m multiport --dports 2055,2056,4739,6343 -s 172.16.0.0/12 -j ACCEPT
iptables -A INPUT -p udp -m multiport --dports 2055,2056,4739,6343 -s 192.168.0.0/16 -j ACCEPT

# 4. Allow Inbound Web Dashboard / REST API (:8080) from NOC Jumpboxes only
iptables -A INPUT -p tcp --dport 8080 -s 10.254.0.0/16 -j ACCEPT

# 5. Allow Outbound Alerting strictly to Internal Webhook/SIEM and Internal SMTP Relay
iptables -A OUTPUT -p tcp --dport 8080 -d 10.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 25 -d 10.0.0.0/8 -j ACCEPT

# 6. LOG & DROP all unauthorized outbound attempts (Anti-Exfiltration Trap)
iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "[AEGISFLOW-EGRESS-BLOCKED]: "
iptables -A OUTPUT -j DROP
```

---

## 2. Windows Server (PowerShell Firewall Rules)

For deployments running on Windows Server, execute the following PowerShell commands as Administrator:

```powershell
# 1. Block outbound internet access for the Python runtime
New-NetFirewallRule -DisplayName "AegisFlow-Block-External-Egress" `
    -Direction Outbound `
    -Program "C:\Python310\python.exe" `
    -RemoteAddress @("0.0.0.0-9.255.255.255", "11.0.0.0-172.15.255.255", "172.32.0.0-192.167.255.255", "192.169.0.0-255.255.255.255") `
    -Action Block

# 2. Allow Inbound NetFlow / IPFIX / sFlow from internal subnets
New-NetFirewallRule -DisplayName "AegisFlow-Flow-Collectors" `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort 2055,2056,4739,6343 `
    -RemoteAddress @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16") `
    -Action Allow

# 3. Allow Management Dashboard on Port 8080 from internal management network
New-NetFirewallRule -DisplayName "AegisFlow-Web-Management" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 8080 `
    -RemoteAddress "10.0.0.0/8" `
    -Action Allow
```

---

## 3. Disabling Linux Kernel IP Forwarding

To ensure the server cannot be utilized as a pivot or transit router:

```bash
# In /etc/sysctl.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
sysctl -p
```
