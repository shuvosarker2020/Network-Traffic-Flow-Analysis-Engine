"""
AegisFlow FastAPI Application & Real-Time Telemetry Hub
Serves REST endpoints, WebSocket feeds, and UI static assets.
"""

import asyncio
import os
import yaml
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from storage import get_storage_engine
from collector.listener import FlowListenerManager
from enrichment.pipeline import enrich_batch
from enrichment.snmp_cache import snmp_cache
from analytics.top_talkers import TopTalkersAnalyzer
from analytics.peering_analyzer import PeeringAnalyzer
from analytics.interface_analyzer import InterfaceAnalyzer
from analytics.qos_analyzer import QoSAnalyzer
from analytics.ddos_detector import DDoSDetector
from analytics.anomaly_detector import AnomalyDetector
from analytics.capacity_planner import CapacityPlanner
from analytics.billing_engine import BillingEngine
from analytics.pattern_engine import TrafficPatternEngine
from reports import ReportManager, ReportScheduler, notifier
from simulation.flow_generator import seed_initial_telemetry, generate_random_flow_records
from simulation.attack_simulator import inject_attacks_into_storage, attack_controller

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("AegisFlow.Server")

# Load Configuration
config_path = "config/config.yaml"
if os.path.exists(config_path):
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
else:
    config = {}

storage = get_storage_engine(config)
ingest_queue = asyncio.Queue(maxsize=100000)
listener_mgr = FlowListenerManager(ingest_queue)

top_talkers = TopTalkersAnalyzer(storage)
peering_analyzer = PeeringAnalyzer(storage)
interface_analyzer = InterfaceAnalyzer(storage)
qos_analyzer = QoSAnalyzer(storage)
ddos_detector = DDoSDetector(storage, config)
anomaly_detector = AnomalyDetector(storage, config)
capacity_planner = CapacityPlanner(storage)
billing_engine = BillingEngine(storage)
pattern_engine = TrafficPatternEngine(storage)
report_manager = ReportManager(pattern_engine)
report_scheduler = ReportScheduler(report_manager)

# Active WebSocket connections
connected_websockets = set()

async def broadcast_ws(message: dict):
    for ws in list(connected_websockets):
        try:
            await ws.send_json(message)
        except Exception:
            connected_websockets.discard(ws)

async def ingestion_worker():
    """Background worker continuously pulling from UDP queue and batch inserting into storage."""
    batch = []
    last_flush = asyncio.get_event_loop().time()
    flush_interval = config.get("storage", {}).get("flush_interval_seconds", 1.0)
    batch_size = config.get("storage", {}).get("batch_size", 2000)

    while True:
        try:
            timeout = max(0.1, flush_interval - (asyncio.get_event_loop().time() - last_flush))
            try:
                records = await asyncio.wait_for(ingest_queue.get(), timeout=timeout)
                batch.extend(records)
                ingest_queue.task_done()
            except asyncio.TimeoutError:
                pass

            now = asyncio.get_event_loop().time()
            if len(batch) >= batch_size or (now - last_flush >= flush_interval and batch):
                enriched = enrich_batch(batch)
                storage.insert_flows(enriched)
                batch.clear()
                last_flush = now
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in ingestion worker: {e}")

async def live_traffic_ticker():
    """Generates continuous live ambient traffic so the UI live dashboard pulses realistically."""
    while True:
        try:
            await asyncio.sleep(3.0)
            live_batch = generate_random_flow_records(count=80)
            storage.insert_flows(live_batch)
            
            # Broadcast live KPI tick
            kpi = top_talkers.get_overview_kpis(minutes=15)
            await broadcast_ws({"type": "KPI_TICK", "data": kpi})
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug(f"Ticker error: {e}")

async def attack_campaign_worker():
    """Injects continuous attack flows into storage every 2 seconds while campaign is active."""
    while True:
        try:
            await asyncio.sleep(2.0)
            if attack_controller.is_active:
                attack_batch = attack_controller.generate_next_batch()
                if attack_batch:
                    storage.insert_flows(attack_batch)
                    status = attack_controller.get_status()
                    await broadcast_ws({"type": "ATTACK_TICK", "data": status})
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in attack campaign worker: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing AegisFlow Network Intelligence Engine...")
    
    # Pre-seed historical telemetry if database is empty
    count_check = storage.query("SELECT COUNT(*) AS c FROM raw_flows;")
    if not count_check or count_check[0].get("c", 0) < 500:
        seed_initial_telemetry(storage, hours=2, flows_per_batch=400)
        inject_attacks_into_storage(storage)

    # Start UDP Flow Listeners
    await listener_mgr.start_listeners(config)

    # Start background ingestion, ticker, and report scheduler tasks
    worker_task = asyncio.create_task(ingestion_worker())
    ticker_task = asyncio.create_task(live_traffic_ticker())
    scheduler_task = asyncio.create_task(report_scheduler.start())
    attack_task = asyncio.create_task(attack_campaign_worker())

    yield

    logger.info("Shutting down AegisFlow...")
    report_scheduler.stop()
    listener_mgr.stop_listeners()
    worker_task.cancel()
    ticker_task.cancel()
    scheduler_task.cancel()
    attack_task.cancel()
    storage.close()

app = FastAPI(title="AegisFlow Network Intelligence Engine", version="2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- API ENDPOINTS ----------------

@app.get("/api/v1/overview")
def get_overview(minutes: int = Query(60, ge=1, le=1440)):
    return top_talkers.get_overview_kpis(minutes=minutes)

@app.get("/api/v1/throughput-timeseries")
def get_timeseries(minutes: int = Query(60, ge=5, le=1440)):
    return top_talkers.get_throughput_timeseries(minutes=minutes)

@app.get("/api/v1/top-talkers/sources")
def get_top_sources(limit: int = 10, minutes: int = 60):
    return top_talkers.get_top_source_ips(limit=limit, minutes=minutes)

@app.get("/api/v1/top-talkers/destinations")
def get_top_destinations(limit: int = 10, minutes: int = 60):
    return top_talkers.get_top_destination_ips(limit=limit, minutes=minutes)

@app.get("/api/v1/conversations")
def get_conversations(limit: int = 15, minutes: int = 60):
    return top_talkers.get_top_conversations(limit=limit, minutes=minutes)

@app.get("/api/v1/applications")
def get_applications(limit: int = 10, minutes: int = 60):
    return top_talkers.get_top_applications(limit=limit, minutes=minutes)

@app.get("/api/v1/peering/matrix")
def get_peering_matrix(limit: int = 20, minutes: int = 60):
    return peering_analyzer.get_asn_matrix(limit=limit, minutes=minutes)

@app.get("/api/v1/peering/summary")
def get_peering_summary(minutes: int = 60):
    return peering_analyzer.get_transit_vs_peering_summary(minutes=minutes)

@app.get("/api/v1/interfaces/utilization")
def get_interface_utilization(limit: int = 50, minutes: int = 15):
    return interface_analyzer.get_interface_utilization(limit=limit, minutes=minutes)

@app.get("/api/v1/site-to-site")
def get_site_to_site(minutes: int = 60):
    return interface_analyzer.get_site_to_site_traffic(minutes=minutes)

@app.get("/api/v1/geomap")
def get_geomap(minutes: int = 30):
    return interface_analyzer.get_geographic_flow_map(minutes=minutes)

@app.get("/api/v1/qos/breakdown")
def get_qos_breakdown(minutes: int = 60):
    return qos_analyzer.get_qos_breakdown(minutes=minutes)

@app.get("/api/v1/qos/compliance")
def get_qos_compliance(minutes: int = 60):
    return qos_analyzer.validate_policy_compliance(minutes=minutes)

@app.get("/api/v1/security/ddos")
def get_ddos_attacks(window_minutes: int = 15):
    return ddos_detector.scan_for_attacks(window_minutes=window_minutes)

@app.get("/api/v1/security/anomalies")
def get_anomalies(window_minutes: int = 15):
    return anomaly_detector.scan_for_anomalies(window_minutes=window_minutes)

@app.post("/api/v1/security/mitigate")
def apply_mitigation(alert_id: str = Query(...), action: str = Query("BGP_FLOWSPEC")):
    """Simulates immediate BGP Flowspec or RTBH mitigation deployment to border routers."""
    return {
        "status": "SUCCESS",
        "alert_id": alert_id,
        "action_taken": action,
        "message": f"Successfully signaled BGP Flowspec route to 48 border routers. Attack traffic filtered at edge."
    }

@app.post("/api/v1/alerts/mock-webhook")
async def mock_webhook_receiver(request: Request):
    """Receives webhook notifications for testing and SIEM integration."""
    payload = await request.json()
    logger.info(f"Mock Webhook received notification: {payload.get('title', 'Alert')}")
    return {"status": "DELIVERED", "received_at": int(time.time())}

@app.get("/api/v1/capacity/forecast")
def get_capacity_forecast(device_id: str = Query("dev-0001"), in_ifindex: int = Query(1)):
    return capacity_planner.forecast_interface_capacity(device_id, in_ifindex)

@app.get("/api/v1/billing/p95")
def get_p95_billing(days: int = 30, interface: str = None):
    return billing_engine.calculate_95th_percentile(interface_filter=interface, days=days)

@app.get("/api/v1/billing/chargebacks")
def get_chargebacks(days: int = 30):
    return billing_engine.generate_tenant_chargeback_report(days=days)

@app.get("/api/v1/devices")
def get_devices(limit: int = 100, vendor: str = None, site: str = None):
    devices = list(snmp_cache.devices.values())
    if vendor:
        devices = [d for d in devices if d.get("vendor", "").lower() == vendor.lower()]
    if site:
        devices = [d for d in devices if site.lower() in d.get("site", "").lower()]
    return {
        "total_count": len(snmp_cache.devices),
        "filtered_count": len(devices),
        "devices": devices[:limit]
    }

@app.post("/api/v1/devices")
async def add_or_update_device(request: Request):
    """Allows optional manual registration or metadata override for an exporter router."""
    req = await request.json()
    ip = req.get("ip")
    if not ip:
        return JSONResponse(status_code=400, content={"error": "Device IP is required"})
    dev_id = req.get("device_id") or f"dev-{ip.replace('.', '-')}"
    dev_entry = {
        "device_id": dev_id,
        "hostname": req.get("hostname", f"router-{ip}"),
        "ip": ip,
        "vendor": req.get("vendor", "Cisco"),
        "model": req.get("model", "Core Router"),
        "role": req.get("role", "Edge / Peering"),
        "site": req.get("site", "Central DC"),
        "city": req.get("city", "Unknown"),
        "country": req.get("country", "US"),
        "flow_protocol": req.get("flow_protocol", "IPFIX / NetFlow"),
        "sampling_rate": int(req.get("sampling_rate", 1000)),
        "status": "ONLINE"
    }
    snmp_cache.devices[dev_id] = dev_entry
    snmp_cache.device_by_ip[ip] = dev_entry
    return {"status": "SUCCESS", "device": dev_entry}

@app.get("/api/v1/raw-flows")
def get_raw_flows(limit: int = 50, src_ip: str = None, dst_ip: str = None, protocol: int = None, dscp: int = None):
    conditions = ["1=1"]
    if src_ip:
        conditions.append(f"src_ip LIKE '{src_ip}%'")
    if dst_ip:
        conditions.append(f"dst_ip LIKE '{dst_ip}%'")
    if protocol is not None:
        conditions.append(f"protocol = {protocol}")
    if dscp is not None:
        conditions.append(f"dscp = {dscp}")

    where_sql = " AND ".join(conditions)
    sql = f"""
    SELECT 
        timestamp, device_name, vendor, site,
        in_if_name, out_if_name,
        src_ip, src_country, src_as_name,
        dst_ip, dst_country, dst_as_name,
        protocol, src_port, dst_port,
        application, dscp_name, flow_direction,
        packets, bytes
    FROM raw_flows
    WHERE {where_sql}
    ORDER BY timestamp DESC
    LIMIT {limit};
    """
    rows = storage.query(sql)
    for r in rows:
        if "timestamp" in r and hasattr(r["timestamp"], "isoformat"):
            r["timestamp"] = r["timestamp"].isoformat()
    return rows

# ================= MULTI-CONDITION PATTERN ENGINE =================

from fastapi import Request

@app.post("/api/v1/pattern/query")
async def query_traffic_pattern(request: Request):
    req = await request.json()
    criteria = dict(req)
    minutes = int(criteria.pop("time_window_minutes", 60) or 60)
    return pattern_engine.analyze_pattern(criteria, minutes=minutes)

@app.post("/api/v1/pattern/multiview")
async def get_pattern_multiview(request: Request):
    req = await request.json()
    criteria = dict(req)
    minutes = int(criteria.pop("time_window_minutes", 60) or 60)
    preset = str(criteria.pop("preset", "CDN_ENTRY_EXIT") or "CDN_ENTRY_EXIT")
    return pattern_engine.get_multiview_flow_data(criteria, minutes=minutes, preset=preset)

@app.get("/api/v1/pattern/options")
def get_pattern_filter_options():
    """Provides autocomplete dropdown lists for ASN, devices, interfaces, countries, and apps."""
    asns_res = storage.query("SELECT DISTINCT dst_as, dst_as_name FROM raw_flows WHERE dst_as != 0 ORDER BY dst_as_name LIMIT 30;")
    devs_res = storage.query("SELECT DISTINCT device_id, device_name, vendor, site FROM raw_flows LIMIT 50;")
    ifs_res = storage.query("SELECT DISTINCT in_if_name FROM raw_flows WHERE in_if_name != '' LIMIT 40;")
    countries_res = storage.query("SELECT DISTINCT dst_country FROM raw_flows WHERE dst_country != 'UN' AND dst_country != 'UNKNOWN' LIMIT 30;")
    apps_res = storage.query("SELECT DISTINCT application FROM raw_flows LIMIT 30;")

    return {
        "asns": [{"as": r["dst_as"], "name": r["dst_as_name"]} for r in asns_res],
        "devices": devs_res,
        "interfaces": [r["in_if_name"] for r in ifs_res],
        "countries": [r["dst_country"] for r in countries_res],
        "applications": [r["application"] for r in apps_res]
    }

# ================= AUTOMATED REPORTS & NOTIFICATIONS =================

@app.get("/api/v1/reports")
def list_reports():
    return report_manager.list_reports()

@app.post("/api/v1/reports")
async def create_or_update_report(request: Request):
    req = await request.json()
    saved = report_manager.save_report(req)
    return {"status": "SUCCESS", "report": saved}

@app.get("/api/v1/reports/history/all")
def get_report_runs_history(limit: int = 50):
    return report_manager.get_runs_history(limit=limit)

@app.get("/api/v1/reports/{report_id}")
def get_report(report_id: str):
    rep = report_manager.get_report(report_id)
    if not rep:
        return JSONResponse(status_code=404, content={"error": "Report not found"})
    return rep

@app.delete("/api/v1/reports/{report_id}")
def delete_report(report_id: str):
    success = report_manager.delete_report(report_id)
    return {"status": "SUCCESS" if success else "NOT_FOUND"}

@app.post("/api/v1/reports/{report_id}/run")
def run_report_endpoint(report_id: str, notify: bool = True):
    try:
        run_record = report_manager.execute_report(report_id, send_notifications=notify)
        return {"status": "SUCCESS", "run": run_record}
    except Exception as e:
        logger.error(f"Error running report {report_id}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

from fastapi.responses import HTMLResponse, Response

@app.get("/api/v1/reports/{report_id}/export/html")
def export_report_html(report_id: str):
    runs = [r for r in report_manager.report_runs if r["report_id"] == report_id]
    if runs:
        latest_run = runs[0]
    else:
        latest_run = report_manager.execute_report(report_id, send_notifications=False)
    html = report_manager.generate_html_report(latest_run)
    return HTMLResponse(content=html)

@app.get("/api/v1/reports/{report_id}/export/csv")
def export_report_csv(report_id: str):
    runs = [r for r in report_manager.report_runs if r["report_id"] == report_id]
    if runs:
        latest_run = runs[0]
    else:
        latest_run = report_manager.execute_report(report_id, send_notifications=False)
    csv_text = report_manager.generate_csv_report(latest_run)
    return Response(content=csv_text, media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={report_id}.csv"})

@app.get("/api/v1/notifications")
def get_notifications(limit: int = 50):
    return notifier.get_notifications(limit=limit)

@app.post("/api/v1/notifications/test")
def send_test_notification(email: str = Query(None), webhook: str = Query(None)):
    results = {}
    if email:
        results["email"] = notifier.send_email(
            recipients=[email],
            subject="🔔 [AegisFlow Test] System Notification Dispatch",
            html_content="<h3>AegisFlow Notification Verification</h3><p>Your email notification channel is operating correctly.</p>"
        )
    if webhook:
        results["webhook"] = notifier.send_webhook(
            webhook_url=webhook,
            payload={"title": "AegisFlow Test Webhook", "message": "Notification channel verified."}
        )
    notifier.record_in_app_notification({
        "type": "TEST_NOTIFICATION",
        "summary": f"Test alert dispatched to email={email}, webhook={webhook}",
        "results": results
    })
    return {"status": "SUCCESS", "results": results}

@app.post("/api/v1/simulate/inject-attack")
def trigger_attack():
    inject_attacks_into_storage(storage)
    return {"status": "SUCCESS", "message": "Injected SYN flood, UDP amplification and Lateral Movement into active pipeline."}

@app.post("/api/v1/simulate/attack/start")
async def start_simulated_attack(request: Request):
    """Starts a continuous attack campaign against user-defined target IP and protocol."""
    req = await request.json()
    target_ip = req.get("target_ip", "10.0.1.50")
    protocol = req.get("protocol", "TCP_SYN")
    target_port = req.get("target_port")
    intensity = req.get("intensity", "high")
    
    status = attack_controller.start_attack(
        target_ip=target_ip,
        protocol=protocol,
        target_port=target_port,
        intensity=intensity
    )
    # Inject initial batch immediately
    initial_batch = attack_controller.generate_next_batch()
    if initial_batch:
        storage.insert_flows(initial_batch)
    
    cur_status = attack_controller.get_status()
    await broadcast_ws({"type": "ATTACK_TICK", "data": cur_status})
    return {
        "status": "SUCCESS",
        "message": f"Attack campaign started against {target_ip} ({protocol}) at {intensity.upper()} intensity",
        "campaign": cur_status
    }

@app.post("/api/v1/simulate/attack/stop")
async def stop_simulated_attack():
    """Stops the active attack campaign immediately."""
    status = attack_controller.stop_attack()
    await broadcast_ws({"type": "ATTACK_TICK", "data": status})
    return {
        "status": "SUCCESS",
        "message": "Attack campaign stopped successfully",
        "campaign": status
    }

@app.get("/api/v1/simulate/attack/status")
def get_simulated_attack_status():
    """Returns the current state and metrics of the attack simulation engine."""
    return attack_controller.get_status()

# WebSocket for real-time live events
@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.add(websocket)
    try:
        while True:
            # Keepalive receiver
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        connected_websockets.discard(websocket)

# Serve Frontend static directory
ui_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ui")
if os.path.exists(ui_dir):
    app.mount("/static", StaticFiles(directory=ui_dir), name="static")

@app.get("/")
def serve_index():
    index_file = os.path.join(ui_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return JSONResponse({"status": "AegisFlow Engine Running", "docs": "/docs"})
