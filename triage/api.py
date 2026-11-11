"""HTTP API. Run with: uvicorn triage.api:app --reload"""

from __future__ import annotations

import hmac
import logging

from fastapi import Depends, FastAPI, Header, HTTPException

from . import config
from .models import ReportIn, ReportRecord, Status
from .notify import Notifier
from .pipeline import Pipeline
from .store import ReportStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def create_app(pipeline: Pipeline | None = None, webhook_secret: str | None = None) -> FastAPI:
    pipeline = pipeline or Pipeline(
        store=ReportStore(config.DB_PATH),
        triager=config.make_triager(),
        notifier=Notifier(config.SLACK_WEBHOOK_URL),
    )
    secret = webhook_secret if webhook_secret is not None else config.WEBHOOK_SECRET

    app = FastAPI(title="Security Report Triage Agent", version="1.0.0")

    def check_secret(x_webhook_secret: str | None = Header(default=None)) -> None:
        # Shared-secret check for the intake webhook. Constant-time comparison.
        if secret and not hmac.compare_digest(x_webhook_secret or "", secret):
            raise HTTPException(status_code=401, detail="invalid webhook secret")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "triager": pipeline.triager.name}

    @app.post("/reports", response_model=ReportRecord, status_code=201, dependencies=[Depends(check_secret)])
    def submit(report: ReportIn) -> ReportRecord:
        return pipeline.process(report)

    @app.get("/reports", response_model=list[ReportRecord])
    def list_reports(status: Status | None = None, limit: int = 100) -> list[ReportRecord]:
        return pipeline.store.list(status=status, limit=min(limit, 500))

    @app.get("/reports/{report_id}", response_model=ReportRecord)
    def get_report(report_id: int) -> ReportRecord:
        record = pipeline.store.get(report_id)
        if record is None:
            raise HTTPException(status_code=404, detail="not found")
        return record

    @app.post("/reports/{report_id}/approve", response_model=ReportRecord, dependencies=[Depends(check_secret)])
    def approve(report_id: int) -> ReportRecord:
        record = pipeline.approve(report_id)
        if record is None:
            raise HTTPException(status_code=409, detail="report is not awaiting approval")
        return record

    return app


app = create_app()
