"""
Unified Enrichment Pipeline for AegisFlow
Applies contextual GeoIP, SNMP interface metadata, BGP ASN, Application classification,
and East-West flow direction tagging to flow records.
"""

from typing import List, Dict, Any
from enrichment.geoip import geoip_resolver
from enrichment.snmp_cache import snmp_cache
from enrichment.application import classify_application, classify_dscp
from enrichment.rfc1918 import classify_flow_direction
from enrichment.bgp_asn import asn_analyzer

def enrich_flow_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    exporter_ip = rec.get("exporter_ip", "0.0.0.0")
    src_ip = rec.get("src_ip", "0.0.0.0")
    dst_ip = rec.get("dst_ip", "0.0.0.0")
    in_if = rec.get("in_ifindex", 0)
    out_if = rec.get("out_ifindex", 0)
    proto = rec.get("protocol", 0)
    src_port = rec.get("src_port", 0)
    dst_port = rec.get("dst_port", 0)
    dscp_val = rec.get("dscp", 0)

    # 1. Device Metadata
    dev = snmp_cache.get_device(exporter_ip)
    if dev:
        rec["device_id"] = dev["device_id"]
        rec["device_name"] = dev["hostname"]
        rec["vendor"] = dev["vendor"]
        rec["site"] = dev["site"]
        rec["site_city"] = dev["city"]
        rec["site_country"] = dev["country"]
    else:
        rec["device_id"] = "dev-unregistered"
        rec["device_name"] = exporter_ip
        rec["vendor"] = "Generic"
        rec["site"] = "Default Site"
        rec["site_city"] = "Unknown"
        rec["site_country"] = "UN"

    # 2. Interface Metadata (Inbound & Outbound)
    in_meta = snmp_cache.get_interface(exporter_ip, in_if)
    out_meta = snmp_cache.get_interface(exporter_ip, out_if)
    rec["in_if_name"] = in_meta["name"]
    rec["in_if_alias"] = in_meta["alias"]
    rec["in_if_speed_bps"] = in_meta["speed_bps"]
    rec["out_if_name"] = out_meta["name"]
    rec["out_if_alias"] = out_meta["alias"]
    rec["out_if_speed_bps"] = out_meta["speed_bps"]

    # 3. GeoIP & ASN Resolution
    src_geo = geoip_resolver.lookup(src_ip)
    dst_geo = geoip_resolver.lookup(dst_ip)
    rec["src_country"] = src_geo["country"]
    rec["src_city"] = src_geo["city"]
    rec["src_lat"] = src_geo["lat"]
    rec["src_lon"] = src_geo["lon"]
    rec["src_cloud"] = src_geo["cloud"]

    rec["dst_country"] = dst_geo["country"]
    rec["dst_city"] = dst_geo["city"]
    rec["dst_lat"] = dst_geo["lat"]
    rec["dst_lon"] = dst_geo["lon"]
    rec["dst_cloud"] = dst_geo["cloud"]

    # If ASN was not in flow header, fill from GeoIP resolver
    if rec.get("src_as", 0) == 0:
        rec["src_as"] = src_geo["asn"]
    if rec.get("dst_as", 0) == 0:
        rec["dst_as"] = dst_geo["asn"]

    src_asn_info = asn_analyzer.get_asn_info(rec["src_as"])
    dst_asn_info = asn_analyzer.get_asn_info(rec["dst_as"])
    rec["src_as_name"] = src_asn_info["name"]
    rec["dst_as_name"] = dst_asn_info["name"]
    rec["dst_as_category"] = dst_asn_info.get("category", "General")

    # 4. Application & QoS / DSCP
    app_name, app_cat = classify_application(proto, src_port, dst_port)
    rec["application"] = app_name
    rec["app_category"] = app_cat
    dscp_name, qos_class = classify_dscp(dscp_val)
    rec["dscp_name"] = dscp_name
    rec["qos_class"] = qos_class

    # 5. East-West / North-South Traffic Direction
    rec["flow_direction"] = classify_flow_direction(src_ip, dst_ip)

    return rec

def enrich_batch(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [enrich_flow_record(r) for r in records]
