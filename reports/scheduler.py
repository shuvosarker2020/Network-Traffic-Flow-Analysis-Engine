"""
Automated Report Scheduler for AegisFlow
Runs periodically in the background to execute scheduled reports and dispatch notifications.
"""

import asyncio
import time
import logging
from typing import Optional

logger = logging.getLogger("AegisFlow.Reports.Scheduler")

class ReportScheduler:
    def __init__(self, report_manager):
        self.report_manager = report_manager
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        self._running = True
        logger.info("Starting AegisFlow Automated Report Scheduler...")
        while self._running:
            try:
                await self._check_and_run_schedules()
            except Exception as e:
                logger.error(f"Error in scheduler check: {e}")
            await asyncio.sleep(60) # Check every 60 seconds

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()

    async def _check_and_run_schedules(self):
        now = time.time()
        reports = self.report_manager.list_reports()

        for rep in reports:
            schedule = rep.get("schedule", "ON_DEMAND").upper()
            if schedule == "ON_DEMAND" or rep.get("status") != "ACTIVE":
                continue

            last_run = rep.get("last_run") or 0
            interval_sec = 3600 # default hourly
            if schedule == "HOURLY":
                interval_sec = 3600
            elif schedule == "DAILY":
                interval_sec = 86400
            elif schedule == "WEEKLY":
                interval_sec = 604800
            elif schedule == "MONTHLY":
                interval_sec = 2592000

            if now - last_run >= interval_sec:
                logger.info(f"Triggering scheduled report execution: {rep['name']} ({schedule})")
                try:
                    # Run report and dispatch notification
                    self.report_manager.execute_report(rep["id"], send_notifications=True)
                except Exception as e:
                    logger.error(f"Failed executing scheduled report {rep['id']}: {e}")
