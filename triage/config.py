"""Settings from environment variables."""

from __future__ import annotations

import logging
import os

from .llm import ClaudeTriager, MockTriager, Triager

log = logging.getLogger(__name__)


def make_triager(mode: str | None = None) -> Triager:
    """TRIAGE_MODE=auto (default) uses Claude when ANTHROPIC_API_KEY is set, else the mock."""
    mode = (mode or os.getenv("TRIAGE_MODE", "auto")).lower()
    if mode == "auto":
        mode = "claude" if os.getenv("ANTHROPIC_API_KEY") else "mock"
    if mode == "claude":
        return ClaudeTriager(
            model=os.getenv("TRIAGE_MODEL", "claude-opus-5-5"),
            effort=os.getenv("TRIAGE_EFFORT", "medium"),
        )
    if mode == "mock":
        log.warning("Using the MOCK triager (keyword heuristics). Set ANTHROPIC_API_KEY to use Claude.")
        return MockTriager()
    raise ValueError(f"Unknown TRIAGE_MODE: {mode}")


DB_PATH = os.getenv("TRIAGE_DB", "triage.db")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL") or None
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET") or None
