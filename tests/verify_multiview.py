"""
Verify Multi-View Analytics API
"""
import urllib.request
import json

def verify():
    # 1. Test CDN Preset
    req_data = json.dumps({"preset": "CDN_ENTRY_EXIT"}).encode("utf-8")
    req = urllib.request.Request("http://localhost:8080/api/v1/pattern/multiview", data=req_data, headers={"Content-Type": "application/json"})
    res = urllib.request.urlopen(req)
    data = json.loads(res.read().decode("utf-8"))
    print("=== CDN Preset Multi-View ===")
    print("View Name:", data.get("view_name", "").encode("ascii", "replace").decode())
    print("Sankey Nodes Count:", len(data["sankey"]["nodes"]))
    print("Sankey Links Count:", len(data["sankey"]["links"]))
    print("Bar Providers Count:", len(data["bars"]["providers"]["labels"]))
    print("Table Records Count:", len(data["table"]))
    print("Treemap Children Count:", len(data["treemap"]["children"]))
    print("Timeseries Points Count:", len(data["timeseries"]))
    print("Summary:", data["summary"])

    # 2. Test Dynamic Query
    req_data2 = json.dumps({"preset": "DYNAMIC", "time_window_minutes": 60}).encode("utf-8")
    req2 = urllib.request.Request("http://localhost:8080/api/v1/pattern/multiview", data=req_data2, headers={"Content-Type": "application/json"})
    res2 = urllib.request.urlopen(req2)
    data2 = json.loads(res2.read().decode("utf-8"))
    print("\n=== Dynamic Filter Multi-View ===")
    print("Dynamic View Name:", data2.get("view_name", "").encode("ascii", "replace").decode())
    print("Dynamic Sankey Nodes Count:", len(data2["sankey"]["nodes"]))
    print("Dynamic Sankey Links Count:", len(data2["sankey"]["links"]))
    print("Dynamic Bar Providers Count:", len(data2["bars"]["providers"]["labels"]))
    print("Dynamic Table Records Count:", len(data2["table"]))
    print("Dynamic Treemap Children Count:", len(data2["treemap"]["children"]))
    print("Dynamic Timeseries Points Count:", len(data2["timeseries"]))
    print("Summary:", data2["summary"])

if __name__ == "__main__":
    verify()
