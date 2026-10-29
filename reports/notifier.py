"""
Automated Notification & Email Dispatcher for AegisFlow Reports
Supports SMTP Email dispatch, Webhook notifications (Slack, Teams, SIEM), and in-app alert history.
"""

import smtplib
import requests
import json
import os
import time
import logging
import urllib.parse
import ipaddress
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Dict, Any, Optional

logger = logging.getLogger("AegisFlow.Reports.Notifier")

def is_safe_internal_destination(url: str) -> bool:
    """Guarantees report webhooks cannot be dispatched to public external internet addresses."""
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if hostname in ["localhost", "127.0.0.1", "::1"]:
            return True
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_loopback or ip.is_private or ip.is_link_local
        except ValueError:
            if any(hostname.endswith(sfx) for sfx in [".internal", ".local", ".lan", ".corp", ".private"]):
                return True
            return False
    except Exception:
        return False

class ReportNotifier:
    def __init__(self, config_file: str = "config/config.yaml"):
        self.config = {}
        if os.path.exists(config_file):
            import yaml
            try:
                with open(config_file, "r") as f:
                    self.config = yaml.safe_load(f) or {}
            except Exception:
                pass

        self.smtp_cfg = self.config.get("alerting", {}).get("smtp", {})
        self.smtp_host = self.smtp_cfg.get("host", "localhost")
        self.smtp_port = self.smtp_cfg.get("port", 25)
        self.smtp_user = self.smtp_cfg.get("user", "")
        self.smtp_pass = self.smtp_cfg.get("password", "")
        self.smtp_from = self.smtp_cfg.get("from_addr", "aegisflow-reports@carrier.internal")
        self.smtp_use_tls = self.smtp_cfg.get("use_tls", False)

        # In-app notifications store
        self.in_app_notifications: List[Dict[str, Any]] = []

    def send_email(self, recipients: List[str], subject: str, html_content: str, text_content: str = "") -> Dict[str, Any]:
        """Sends an HTML formatted executive report via SMTP email with local spool fallback."""
        if not recipients:
            return {"status": "SKIPPED", "message": "No email recipients specified"}

        clean_recipients = [r.strip() for r in recipients if r and "@" in r]
        if not clean_recipients:
            return {"status": "SKIPPED", "message": "No valid email addresses"}

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.smtp_from
        msg["To"] = ", ".join(clean_recipients)

        if text_content:
            msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        # Try sending via configured SMTP server
        sent_smtp = False
        smtp_err = ""
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=4) as server:
                if self.smtp_use_tls:
                    server.starttls()
                if self.smtp_user and self.smtp_pass:
                    server.login(self.smtp_user, self.smtp_pass)
                server.sendmail(self.smtp_from, clean_recipients, msg.as_string())
                sent_smtp = True
                logger.info(f"Successfully dispatched report email to {clean_recipients}")
        except Exception as e:
            smtp_err = str(e)
            logger.warning(f"SMTP delivery direct connection unavailable ({e}). Spooling report to disk.")

        # Local Spool / Audit Log
        spool_dir = "data/spooled_emails"
        os.makedirs(spool_dir, exist_ok=True)
        spool_file = os.path.join(spool_dir, f"report_{int(time.time())}_{clean_recipients[0].replace('@', '_at_')}.html")
        with open(spool_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        return {
            "status": "SENT" if sent_smtp else "SPOOLED",
            "recipients": clean_recipients,
            "smtp_delivered": sent_smtp,
            "spool_file": spool_file,
            "smtp_message": "Delivered via SMTP" if sent_smtp else f"Spooled to {spool_file} (SMTP note: {smtp_err})"
        }

    def send_webhook(self, webhook_url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches JSON alert or report notification to a webhook endpoint with air-gap checks."""
        if not webhook_url or not webhook_url.startswith("http"):
            return {"status": "SKIPPED", "message": "No valid webhook URL"}

        # Air-gap verification: block any attempt to send network reports outside the server enclave
        strict_isolation = self.config.get("security", {}).get("strict_airgap", True)
        if strict_isolation and not is_safe_internal_destination(webhook_url):
            logger.error(f"AIR-GAP VIOLATION BLOCKED: Refusing to dispatch report to external URL '{webhook_url}'.")
            return {"status": "BLOCKED", "message": f"Air-gap policy blocked external egress to '{webhook_url}'"}

        try:
            # Check if Slack webhook format or generic
            if "hooks.slack.com" in webhook_url or "discord.com" in webhook_url:
                slack_payload = {
                    "text": f"*{payload.get('title', 'AegisFlow Report Generated')}*\n{payload.get('summary_text', '')}",
                    "attachments": [{
                        "color": "#06b6d4",
                        "fields": [
                            {"title": "Report", "value": payload.get("report_name", ""), "short": True},
                            {"title": "Avg Wire-Rate", "value": f"{payload.get('avg_mbps', 0)} Mbps", "short": True},
                            {"title": "Total Volume", "value": f"{payload.get('total_data', '')}", "short": True},
                            {"title": "Matched Flows", "value": f"{payload.get('flow_count', 0):,}", "short": True}
                        ]
                    }]
                }
                res = requests.post(webhook_url, json=slack_payload, timeout=4)
            else:
                res = requests.post(webhook_url, json=payload, timeout=4)

            logger.info(f"Webhook dispatched to {webhook_url}: HTTP {res.status_code}")
            return {"status": "DELIVERED", "status_code": res.status_code}
        except Exception as e:
            logger.warning(f"Webhook dispatch failed to {webhook_url}: {e}")
            return {"status": "FAILED", "error": str(e)}

    def record_in_app_notification(self, notification: Dict[str, Any]):
        notification["id"] = f"notif-{int(time.time() * 1000)}"
        notification["timestamp"] = int(time.time())
        self.in_app_notifications.insert(0, notification)
        if len(self.in_app_notifications) > 200:
            self.in_app_notifications.pop()

    def get_notifications(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.in_app_notifications[:limit]

notifier = ReportNotifier()
