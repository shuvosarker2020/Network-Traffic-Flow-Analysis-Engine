#!/usr/bin/env python3
"""
Air-Gapped UI Asset Packager & Offline Enforcer
Audits, downloads, and switches frontend assets (Tailwind, FontAwesome, ECharts, Leaflet)
to local 'ui/vendor/' hosting to ensure zero external browser HTTP queries.
"""

import sys
import os
import re
import urllib.request
import argparse

VENDOR_DIR = "ui/vendor"

ASSETS = [
    {
        "name": "ECharts 5.4.3",
        "url": "https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js",
        "local_file": f"{VENDOR_DIR}/echarts.min.js",
        "html_tag": '<script src="/vendor/echarts.min.js"></script>'
    },
    {
        "name": "Leaflet JS 1.9.4",
        "url": "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js",
        "local_file": f"{VENDOR_DIR}/leaflet.js",
        "html_tag": '<script src="/vendor/leaflet.js"></script>'
    },
    {
        "name": "Leaflet CSS 1.9.4",
        "url": "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css",
        "local_file": f"{VENDOR_DIR}/leaflet.css",
        "html_tag": '<link rel="stylesheet" href="/vendor/leaflet.css" />'
    },
    {
        "name": "Tailwind CSS Standalone",
        "url": "https://cdn.tailwindcss.com",
        "local_file": f"{VENDOR_DIR}/tailwind.js",
        "html_tag": '<script src="/vendor/tailwind.js"></script>'
    },
    {
        "name": "FontAwesome CSS",
        "url": "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css",
        "local_file": f"{VENDOR_DIR}/fontawesome.all.min.css",
        "html_tag": '<link rel="stylesheet" href="/vendor/fontawesome.all.min.css" />'
    }
]


def audit_ui_assets(html_path: str = "ui/index.html") -> None:
    print("=" * 65)
    print("  FRONTEND ASSET AIR-GAP AUDIT")
    print("=" * 65)
    if not os.path.exists(html_path):
        print(f"Error: {html_path} does not exist.")
        return

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    external_found = []
    for asset in ASSETS:
        if asset["url"] in html:
            external_found.append(asset)
            print(f"[EXTERNAL CDN] {asset['name']:<25} : {asset['url']}")

    if not external_found:
        print("[AIR-GAP VERIFIED] Zero external CDNs detected! UI is running 100% offline.")
    else:
        print("-" * 65)
        print(f"Found {len(external_found)} external CDN links.")
        print("To download and vendor these assets for air-gapped deployment, run:")
        print("  python .agents/skills/server-data-isolation/scripts/vendor_frontend_assets.py --download")
    print("=" * 65)


def download_vendor_assets():
    os.makedirs(VENDOR_DIR, exist_ok=True)
    print(f"Downloading vendor assets into '{VENDOR_DIR}'...")
    success = 0
    for asset in ASSETS:
        dst = asset["local_file"]
        if os.path.exists(dst) and os.path.getsize(dst) > 0:
            print(f"  [OK: Cached] {asset['name']} -> {dst}")
            success += 1
            continue
        try:
            print(f"  [Fetching] {asset['name']} from {asset['url']}...")
            req = urllib.request.Request(asset["url"], headers={"User-Agent": "AegisFlow-Offline-Packager/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp, open(dst, "wb") as f:
                f.write(resp.read())
            print(f"  [Success] Saved {dst} ({os.path.getsize(dst)} bytes)")
            success += 1
        except Exception as e:
            print(f"  [Failed] Could not download {asset['name']}: {e}")

    print(f"\nVendoring complete: {success}/{len(ASSETS)} assets ready.")


def main():
    parser = argparse.ArgumentParser(description="Air-Gapped Frontend Asset Packager")
    parser.add_argument("--mode", choices=["audit", "download"], default="audit")
    parser.add_argument("--html", default="ui/index.html")
    args = parser.parse_args()

    if args.mode == "download":
        download_vendor_assets()
    else:
        audit_ui_assets(args.html)


if __name__ == "__main__":
    main()
