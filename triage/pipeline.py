"""The triage pipeline: store -> triage -> guardrails -> route -> notify."""

from __future__ import annotations

import logging

from .llm import Triager
from .models import ReportIn, ReportRecord, Severity, Status, TriageResult
from .notify import Notifier
from .store import ReportStore

log = logging.getLogger(__name__)

MIN_CONFIDENCE = 0.6
NEEDS_HUMAN_APPROVAL = {Severity.critical, Severity.high}


def apply_guardrails(result: TriageResult, candidate_ids: set[int]) -> tuple[TriageResult, list[str]]:
    """Never trust model output blindly. Fix what can be fixed, record what was changed."""
    notes: list[str] = []
    result = result.model_copy()

    if result.duplicate_of is not None and result.duplicate_of not in candidate_ids:
        notes.append(f"Model pointed to unknown report #{result.duplicate_of}; duplicate link removed.")
        result.duplicate_of = None

    if not 0.0 <= result.confidence <= 1.0:
        notes.append(f"Confidence {result.confidence} out of range; clamped.")
        result.confidence = min(max(result.confidence, 0.0), 1.0)

    if result.suspected_prompt_injection:
        notes.append("Report appears to contain instructions aimed at the triage system.")

    return result, notes


def route(result: TriageResult) -> Status:
    if result.suspected_prompt_injection or result.confidence < MIN_CONFIDENCE:
        return Status.needs_review
    if result.duplicate_of is not None:
        return Status.duplicate
    if result.severity in NEEDS_HUMAN_APPROVAL:
        return Status.pending_approval
    return Status.triaged


class Pipeline:
    def __init__(self, store: ReportStore, triager: Triager, notifier: Notifier):
        self.store = store
        self.triager = triager
        self.notifier = notifier

    def process(self, report: ReportIn) -> ReportRecord:
        # 1. Persist first, so nothing is lost if a later step fails.
        report_id = self.store.add(report)
        log.info("report %s received: %r", report_id, report.title)

        # 2. Triage with the model.
        candidates = self.store.candidates_for_dedupe(exclude_id=report_id)
        try:
            raw = self.triager.triage(report, candidates)
        except Exception as e:  # noqa: BLE001 - any failure goes to a human, never dropped
            log.exception("triage failed for report %s", report_id)
            self.store.mark_failed(report_id, f"{type(e).__name__}: {e}")
            record = self.store.get(report_id)
            self.notifier.send(record, "Triage failed, needs manual review")
            return record

        # 3. Validate the output, then decide where it goes.
        result, notes = apply_guardrails(raw, {c.id for c in candidates})
        status = route(result)
        self.store.save_triage(report_id, result, status, notes)
        record = self.store.get(report_id)
        log.info("report %s -> %s (%s, confidence %.2f)", report_id, status.value,
                 result.severity.value, result.confidence)

        # 4. Tell people only when they need to act.
        if status is Status.pending_approval:
            self.notifier.send(record, "New high-severity report awaiting approval")
        elif status is Status.needs_review:
            self.notifier.send(record, "Report needs manual review")
        return record

    def approve(self, report_id: int) -> ReportRecord | None:
        record = self.store.get(report_id)
        if record is None or record.status is not Status.pending_approval:
            return None
        self.store.set_status(report_id, Status.escalated)
        record = self.store.get(report_id)
        self.notifier.send(record, "Escalated to the security team")
        return record
