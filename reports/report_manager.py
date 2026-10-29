"""
Report Manager for AegisFlow
Manages multi-condition report definitions, executes automated analytical queries,
and formats reports for HTML email dispatch and CSV export.
"""

import json
import os
import time
import uuid
import csv
import io
from typing import List, Dict, Any, Optional

from analytics.pattern_engine import TrafficPatternEngine
from reports.notifier import notifier

REPORTS_FILE = "data/reports.json"
REPORT_RUNS_FILE = "data/report_runs.json"

def format_bytes(bytes_val: int) -> str:
    if not bytes_val or bytes_val == 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if abs(bytes_val) < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} PB"

class ReportManager:
    def __init__(self, pattern_engine: TrafficPatternEngine):
        self.pattern_engine = pattern_engine
        self.reports: Dict[str, Dict[str, Any]] = {}
        self.report_runs: List[Dict[str, Any]] = []
        self._load_data()

    def _load_data(self):
        os.makedirs("data", exist_ok=True)
        if os.path.exists(REPORTS_FILE):
            try:
                with open(REPORTS_FILE, "r") as f:
                    self.reports = json.load(f)
            except Exception:
                self.reports = {}

        if os.path.exists(REPORT_RUNS_FILE):
            try:
                with open(REPORT_RUNS_FILE, "r") as f:
                    self.report_runs = json.load(f)
            except Exception:
                self.report_runs = []

        # If no reports exist yet, create default templates
        if not self.reports:
            self._init_default_reports()

    def _save_data(self):
        try:
            with open(REPORTS_FILE, "w") as f:
                json.dump(self.reports, f, indent=2)
            with open(REPORT_RUNS_FILE, "w") as f:
                json.dump(self.report_runs[:100], f, indent=2)
        except Exception:
            pass

    def _init_default_reports(self):
        r1_id = "rep-transit-peering"
        self.reports[r1_id] = {
            "id": r1_id,
            "name": "Tier-1 Transit to Google Peering Utilization",
            "description": "Monitors traffic flowing between Paid Transit AS3356 (Lumen) and AS15169 (Google) on 100G interfaces.",
            "conditions": {
                "src_as": 3356,
                "dst_as": 15169,
                "time_window_minutes": 60
            },
            "schedule": "DAILY",
            "recipients": ["noc-lead@carrier.internal", "netops@company.com"],
            "webhook_url": "http://localhost:8080/api/v1/alerts/mock-webhook",
            "created_at": int(time.time()),
            "last_run": None,
            "status": "ACTIVE"
        }

        r2_id = "rep-internal-east-west"
        self.reports[r2_id] = {
            "id": r2_id,
            "name": "East-West Core Ring WAN Subnet 10.0.0.0/16",
            "description": "Analyzes internal cross-datacenter traffic originating from 10.0.0.0/16 heading to core routers.",
            "conditions": {
                "src_prefix": "10.0.0.0/16",
                "flow_direction": "East-West",
                "time_window_minutes": 60
            },
            "schedule": "WEEKLY",
            "recipients": ["dc-infra@carrier.internal"],
            "webhook_url": "",
            "created_at": int(time.time()),
            "last_run": None,
            "status": "ACTIVE"
        }
        self._save_data()

    def list_reports(self) -> List[Dict[str, Any]]:
        return list(self.reports.values())

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        return self.reports.get(report_id)

    def save_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        rep_id = data.get("id") or f"rep-{uuid.uuid4().hex[:8]}"
        report = {
            "id": rep_id,
            "name": data.get("name", "Custom Traffic Report"),
            "description": data.get("description", ""),
            "conditions": data.get("conditions", {}),
            "schedule": data.get("schedule", "ON_DEMAND"),
            "recipients": data.get("recipients", []),
            "webhook_url": data.get("webhook_url", ""),
            "created_at": data.get("created_at") or int(time.time()),
            "last_run": data.get("last_run"),
            "status": data.get("status", "ACTIVE")
        }
        self.reports[rep_id] = report
        self._save_data()
        return report

    def delete_report(self, report_id: str) -> bool:
        if report_id in self.reports:
            del self.reports[report_id]
            self._save_data()
            return True
        return False

    def execute_report(self, report_id: str, send_notifications: bool = True) -> Dict[str, Any]:
        report = self.get_report(report_id)
        if not report:
            raise ValueError(f"Report {report_id} not found")

        conditions = report.get("conditions", {})
        window_minutes = int(conditions.get("time_window_minutes", 60))

        # Run pattern analytics
        results = self.pattern_engine.analyze_pattern(conditions, minutes=window_minutes)

        run_id = f"run-{uuid.uuid4().hex[:8]}"
        now_ts = int(time.time())
        summary = results["summary"]

        run_record = {
            "run_id": run_id,
            "report_id": report_id,
            "report_name": report["name"],
            "timestamp": now_ts,
            "window_minutes": window_minutes,
            "conditions": conditions,
            "avg_mbps": summary.get("avg_mbps", 0.0),
            "total_bytes": summary.get("total_bytes", 0),
            "total_data_formatted": format_bytes(summary.get("total_bytes", 0)),
            "flow_count": summary.get("flow_count", 0),
            "unique_sources": summary.get("unique_sources", 0),
            "unique_destinations": summary.get("unique_destinations", 0),
            "results": results,
            "dispatch_status": {}
        }

        # Update report last_run
        report["last_run"] = now_ts
        self._save_data()

        # Send Notifications if requested
        if send_notifications:
            html_content = self.generate_html_report(run_record)
            subject = f"📊 [AegisFlow Report] {report['name']} - {summary.get('avg_mbps', 0.0)} Mbps Wire-Rate"

            # 1. Email Dispatch
            email_res = notifier.send_email(
                recipients=report.get("recipients", []),
                subject=subject,
                html_content=html_content
            )

            # 2. Webhook Dispatch
            webhook_res = notifier.send_webhook(
                webhook_url=report.get("webhook_url", ""),
                payload={
                    "title": subject,
                    "report_name": report["name"],
                    "summary_text": f"Traffic pattern matched {summary.get('flow_count', 0):,} flows. Avg Rate: {summary.get('avg_mbps', 0)} Mbps.",
                    "avg_mbps": summary.get("avg_mbps", 0),
                    "total_data": format_bytes(summary.get("total_bytes", 0)),
                    "flow_count": summary.get("flow_count", 0)
                }
            )

            # 3. In-App Notification
            notifier.record_in_app_notification({
                "type": "REPORT_GENERATED",
                "report_id": report_id,
                "report_name": report["name"],
                "summary": f"Report executed: {summary.get('avg_mbps', 0)} Mbps ({format_bytes(summary.get('total_bytes', 0))})",
                "email_status": email_res.get("status"),
                "webhook_status": webhook_res.get("status")
            })

            run_record["dispatch_status"] = {
                "email": email_res,
                "webhook": webhook_res
            }

        self.report_runs.insert(0, run_record)
        self._save_data()
        return run_record

    def generate_html_report(self, run: Dict[str, Any]) -> str:
        """Renders a responsive, professional HTML executive report."""
        summary = run.get("results", {}).get("summary", {})
        top_asns = run.get("results", {}).get("top_asns", [])
        top_convs = run.get("results", {}).get("top_conversations", [])
        top_ifs = run.get("results", {}).get("top_interfaces", [])
        conds = run.get("conditions", {})

        conds_badges = "".join([
            f"<span style='background:#1e293b; color:#38bdf8; padding:3px 8px; border-radius:4px; font-size:11px; margin-right:6px;'>{k}: <b>{v}</b></span>"
            for k, v in conds.items() if v
        ])

        asn_rows = "".join([
            f"<tr><td style='padding:8px; border-bottom:1px solid #1e293b; color:#94a3b8;'>AS{a.get('src_as')} ({a.get('src_as_name')})</td>"
            f"<td style='padding:8px; border-bottom:1px solid #1e293b; color:#38bdf8; font-weight:bold;'>AS{a.get('dst_as')} ({a.get('dst_as_name')})</td>"
            f"<td style='padding:8px; border-bottom:1px solid #1e293b; text-align:right; color:#10b981; font-weight:bold;'>{a.get('mbps')} Mbps</td></tr>"
            for a in top_asns[:6]
        ]) or "<tr><td colspan='3' style='padding:12px; text-align:center; color:#64748b;'>No ASN traffic in subset</td></tr>"

        conv_rows = "".join([
            f"<tr><td style='padding:8px; border-bottom:1px solid #1e293b; color:#38bdf8; font-family:monospace;'>{c.get('src_ip')} ({c.get('src_country')})</td>"
            f"<td style='padding:8px; border-bottom:1px solid #1e293b; color:#60a5fa; font-family:monospace;'>{c.get('dst_ip')} ({c.get('dst_country')})</td>"
            f"<td style='padding:8px; border-bottom:1px solid #1e293b; color:#cbd5e1;'>{c.get('application')}</td>"
            f"<td style='padding:8px; border-bottom:1px solid #1e293b; text-align:right; color:#10b981; font-weight:bold;'>{c.get('mbps')} Mbps</td></tr>"
            for c in top_convs[:6]
        ]) or "<tr><td colspan='4' style='padding:12px; text-align:center; color:#64748b;'>No IP conversations in subset</td></tr>"

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f8fafc; margin: 0; padding: 24px; }}
            .container {{ max-width: 820px; margin: 0 auto; background: #0f172a; border-radius: 12px; border: 1px solid #1e293b; overflow: hidden; }}
            .header {{ background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%); padding: 24px 32px; }}
            .header h1 {{ margin: 0; font-size: 20px; color: #ffffff; letter-spacing: -0.5px; }}
            .header p {{ margin: 4px 0 0 0; font-size: 13px; color: #e0f2fe; }}
            .content {{ padding: 28px 32px; }}
            .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 24px; }}
            .kpi-box {{ background: #1e293b; padding: 14px 16px; border-radius: 8px; border: 1px solid #334155; }}
            .kpi-title {{ font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 600; }}
            .kpi-val {{ font-size: 20px; font-weight: bold; color: #ffffff; margin-top: 4px; }}
            .card {{ background: #131c31; border: 1px solid #1e293b; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }}
            .card-header {{ padding: 12px 16px; background: #1e293b; font-size: 13px; font-weight: 600; color: #e2e8f0; }}
            table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
            .footer {{ padding: 16px 32px; border-top: 1px solid #1e293b; font-size: 11px; color: #64748b; text-align: center; }}
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>{run.get('report_name')}</h1>
              <p>Generated by AegisFlow Intelligence Engine · Window: Last {run.get('window_minutes')} Minutes</p>
            </div>
            <div class="content">
              <div style="margin-bottom: 20px;">
                <span style="font-size: 12px; color: #94a3b8; margin-right: 8px;">Applied Criteria:</span>
                {conds_badges}
              </div>

              <!-- KPI Metrics -->
              <table style="width: 100%; margin-bottom: 24px;">
                <tr>
                  <td style="padding: 10px; background: #1e293b; border-radius: 8px; width: 25%;">
                    <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase;">Average Rate</div>
                    <div style="font-size: 22px; font-weight: bold; color: #38bdf8; margin-top: 4px;">{summary.get('avg_mbps', 0)} Mbps</div>
                  </td>
                  <td style="width: 10px;"></td>
                  <td style="padding: 10px; background: #1e293b; border-radius: 8px; width: 25%;">
                    <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase;">Total Transferred</div>
                    <div style="font-size: 22px; font-weight: bold; color: #10b981; margin-top: 4px;">{format_bytes(summary.get('total_bytes', 0))}</div>
                  </td>
                  <td style="width: 10px;"></td>
                  <td style="padding: 10px; background: #1e293b; border-radius: 8px; width: 25%;">
                    <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase;">Matching Flows</div>
                    <div style="font-size: 22px; font-weight: bold; color: #f59e0b; margin-top: 4px;">{summary.get('flow_count', 0):,}</div>
                  </td>
                  <td style="width: 10px;"></td>
                  <td style="padding: 10px; background: #1e293b; border-radius: 8px; width: 25%;">
                    <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase;">Active Devices</div>
                    <div style="font-size: 22px; font-weight: bold; color: #c084fc; margin-top: 4px;">{summary.get('matched_devices', 0)}</div>
                  </td>
                </tr>
              </table>

              <!-- Top ASN-to-ASN -->
              <div class="card">
                <div class="card-header">Top Autonomous System (ASN-to-ASN) Flows</div>
                <table>
                  <thead>
                    <tr style="text-align: left; color: #94a3b8; border-bottom: 1px solid #1e293b;">
                      <th style="padding: 8px;">Source ASN</th>
                      <th style="padding: 8px;">Destination ASN</th>
                      <th style="padding: 8px; text-align: right;">Throughput</th>
                    </tr>
                  </thead>
                  <tbody>{asn_rows}</tbody>
                </table>
              </div>

              <!-- Top Conversations -->
              <div class="card">
                <div class="card-header">Top IP Talker Conversations</div>
                <table>
                  <thead>
                    <tr style="text-align: left; color: #94a3b8; border-bottom: 1px solid #1e293b;">
                      <th style="padding: 8px;">Source Host</th>
                      <th style="padding: 8px;">Destination Target</th>
                      <th style="padding: 8px;">Service</th>
                      <th style="padding: 8px; text-align: right;">Rate</th>
                    </tr>
                  </thead>
                  <tbody>{conv_rows}</tbody>
                </table>
              </div>
            </div>
            <div class="footer">
              AegisFlow Network Intelligence & Observability Platform · Generated at {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(run.get('timestamp')))}
            </div>
          </div>
        </body>
        </html>
        """
        return html

    def generate_csv_report(self, run: Dict[str, Any]) -> str:
        """Exports traffic pattern time-series and conversations as CSV."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["=== AegisFlow Traffic Pattern Report ==="])
        writer.writerow(["Report Name", run.get("report_name")])
        writer.writerow(["Generated Time", time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(run.get('timestamp')))])
        writer.writerow(["Average Mbps", run.get("avg_mbps")])
        writer.writerow(["Total Data", run.get("total_data_formatted")])
        writer.writerow(["Flow Count", run.get("flow_count")])
        writer.writerow([])

        # Time-series
        writer.writerow(["Time Point", "Throughput (Mbps)", "Packet Rate (PPS)", "Flow Count"])
        timeseries = run.get("results", {}).get("timeseries", [])
        for t in timeseries:
            writer.writerow([t.get("time_point"), t.get("mbps"), t.get("pps"), t.get("flows")])
        writer.writerow([])

        # Top Conversations
        writer.writerow(["Source IP", "Source Country", "Source ASN", "Destination IP", "Dest Country", "Dest ASN", "Application", "Protocol", "Mbps", "Packets"])
        convs = run.get("results", {}).get("top_conversations", [])
        for c in convs:
            writer.writerow([
                c.get("src_ip"), c.get("src_country"), c.get("src_as_name"),
                c.get("dst_ip"), c.get("dst_country"), c.get("dst_as_name"),
                c.get("application"), c.get("protocol"), c.get("mbps"), c.get("packets")
            ])

        return output.getvalue()

    def get_runs_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.report_runs[:limit]
