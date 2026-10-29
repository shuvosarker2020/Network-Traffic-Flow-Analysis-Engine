"""
AegisFlow Main Launcher
Starts the Carrier-Grade Network Intelligence & Observability Engine.
"""

import uvicorn
import yaml
import os
import sys

def main():
    print("""
    ======================================================================
       ___              _     ______ _                 
      / _ \\            (_)    |  ___| |                
     / /_\\ \\ ___  __ _  _ ___ | |_  | | _____      __  
     |  _  |/ _ \\/ _` || / __||  _| | |/ _ \\ \\ /\\ / /  
     | | | |  __/ (_| || \\__ \\| |   | | (_) \\ V  V /   
     \\_| |_/\\___|\\__, || |___/\\_|   |_|\\___/ \\_/\\_/    
                  __/ || |                             
                 |___/ |_|                             
      Carrier-Grade Flow Intelligence & DDoS Defense Engine v2.0
      Supporting Cisco, Juniper, Huawei, Nokia, ZTE, MikroTik
    ======================================================================
    """)

    config_path = "config/config.yaml"
    host = "0.0.0.0"
    port = 8080

    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            cfg = yaml.safe_load(f)
            host = cfg.get("server", {}).get("host", host)
            port = cfg.get("server", {}).get("api_port", port)

    print(f"[*] Starting Web Dashboard & REST/WebSocket Engine on http://{host}:{port}")
    print(f"[*] Listening for NetFlow v5 (UDP 2055), NetFlow v9 (UDP 2056), IPFIX (UDP 4739), sFlow (UDP 6343)")
    print(f"[*] Embedded Columnar Storage: DuckDB (Ready for ClickHouse cluster)")
    print(f"======================================================================\n")

    uvicorn.run("api.main:app", host=host, port=port, log_level="info", reload=False)

if __name__ == "__main__":
    main()
