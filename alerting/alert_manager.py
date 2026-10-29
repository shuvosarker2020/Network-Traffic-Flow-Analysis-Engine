"""
Alert Manager for AegisFlow
Deduplicates, suppresses, and dispatches critical security and capacity alerts.
"""

import time
import logging
import requests
import urllib.parse
import ipaddress
from typing import List, Dict, Any, Optional

logger = logging.getLogger("AegisFlow.Alerting")

def is_safe_internal_url(url: str) -> bool:
    """Guarantees webhooks cannot be dispatched to public external internet addresses."""
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = (parsed.hostname or "").lower()
        if hostname in ["localhost", "127.0.0.1", "::1"]:
            return True
        # Check IP address
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_loopback or ip.is_private or ip.is_link_local
        except ValueError:
            # Check internal domain suffixes
            if any(hostname.endswith(sfx) for sfx in [".internal", ".local", ".lan", ".corp", ".private"]):
                return True
            return False
    except Exception:
        return False

class AlertManager:
    def __init__(self, config: dict):
        self.config = config.get("alerting", {})
        self.webhook_url = self.config.get("dispatch_webhook")
        self.active_alerts: Dict[str, Dict[str, Any]] = {}
        self.suppression_window_sec = 300 # 5 minutes

    def process_alerts(self, alerts: List[Dict[str, Any]]):
        now = time.time()
        for alert in alerts:
            alert_key = f"{alert.get('category')}:{alert.get('target_ip')}:{alert.get('title')}"
            
            # Check suppression
            last_alert = self.active_alerts.get(alert_key)
            if last_alert and (now - last_alert.get("last_fired", 0)) < self.suppression_window_sec:
                continue

            alert["last_fired"] = now
            self.active_alerts[alert_key] = alert
            self._dispatch(alert)

    def _dispatch(self, alert: Dict[str, Any]):
        logger.warning(f"DISPATCHING ALERT: [{alert.get('severity')}] {alert.get('title')} - {alert.get('description')}")
        if self.webhook_url and self.webhook_url.startswith("http"):
            if not is_safe_internal_url(self.webhook_url):
                logger.error(f"AIR-GAP VIOLATION PREVENTED: Blocked attempt to dispatch alert webhook to external destination '{self.webhook_url}'")
                return
            try:
                # Asynchronous or non-blocking fire-and-forget in production
                requests.post(self.webhook_url, json=alert, timeout=2.0)
            except Exception as e:
                logger.debug(f"Webhook dispatch failed: {e}")

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        return list(self.active_alerts.values())

alert_manager = AlertManager({})
