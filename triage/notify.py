"""Slack notifications via an incoming webhook. Optional: logs instead when unset."""

from __future__ import annotations

import logging

import httpx

from .models import ReportRecord

log = logging.getLogger(__name__)

_EMOJI = {"critical": ":rotating_light:", "high": ":red_circle:", "medium": ":large_orange_circle:",
          "low": ":large_yellow_circle:", "informational": ":white_circle:"}


class Notifier:
    def __init__(self, slack_webhook_url: str | None = None):
        self.url = slack_webhook_url

    def send(self, record: ReportRecord, headline: str) -> None:
        text = format_message(record, headline)
        if not self.url:
            log.info("notification (Slack not configured):\n%s", text)
            return
        try:
            httpx.post(self.url, json={"text": text}, timeout=10).raise_for_status()
        except httpx.HTTPError as e:
            # A failed notification must never lose the report: it is already stored.
            log.warning("Slack notification failed for report %s: %s", record.id, e)


def format_message(record: ReportRecord, headline: str) -> str:
    t = record.triage
    if t is None:
        return f"*{headline}* — report #{record.id}: {record.title}\nError: {record.error}"
    lines = [
        f"{_EMOJI.get(t.severity.value, '')} *{headline}* — report #{record.id}",
        f"*{t.severity.value.upper()}* · {t.vuln_class.value} · `{t.affected_component}`",
        t.summary,
        f"Confidence: {t.confidence:.0%}",
    ]
    lines += [f"Note: {n}" for n in record.notes]
    return "\n".join(lines)
