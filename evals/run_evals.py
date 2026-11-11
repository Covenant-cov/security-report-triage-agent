"""Run the labeled dataset through the full pipeline and score the results.

Usage:
    python -m evals.run_evals              # Claude if ANTHROPIC_API_KEY is set, else mock
    python -m evals.run_evals --mode mock
    python -m evals.run_evals --mode claude

Cases run in order through a fresh in-memory database, so later cases can be
detected as duplicates of earlier ones, just like in production.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from triage.config import make_triager
from triage.models import SEVERITY_ORDER, ReportIn, Severity
from triage.notify import Notifier
from triage.pipeline import Pipeline
from triage.store import ReportStore

HERE = Path(__file__).parent


def load_cases() -> list[dict]:
    lines = (HERE / "dataset.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(ln) for ln in lines if ln.strip()]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["auto", "claude", "mock"], default="auto")
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING)

    triager = make_triager(args.mode)
    pipeline = Pipeline(ReportStore(":memory:"), triager, Notifier(None))

    cases = load_cases()
    case_to_id: dict[str, int] = {}
    rows = []
    for c in cases:
        record = pipeline.process(ReportIn(title=c["title"], body=c["body"]))
        case_to_id[c["case"]] = record.id
        exp = c["expect"]
        t = record.triage
        exp_dup = case_to_id.get(exp["duplicate_of"]) if exp["duplicate_of"] else None
        if t is None:
            rows.append({"case": c["case"], "error": record.error})
            continue
        got_rank = SEVERITY_ORDER.index(t.severity)
        exp_rank = SEVERITY_ORDER.index(Severity(exp["severity"]))
        rows.append({
            "case": c["case"],
            "status": record.status.value,
            "class_ok": t.vuln_class.value == exp["vuln_class"],
            "sev_exact": got_rank == exp_rank,
            "sev_within_1": abs(got_rank - exp_rank) <= 1,
            "dup_ok": t.duplicate_of == exp_dup,
            "inj_ok": t.suspected_prompt_injection == exp["injection"],
            "got": f"{t.vuln_class.value}/{t.severity.value}",
            "expected": f"{exp['vuln_class']}/{exp['severity']}",
            "confidence": round(t.confidence, 2),
        })

    scored = [r for r in rows if "error" not in r]
    metrics = ["class_ok", "sev_exact", "sev_within_1", "dup_ok", "inj_ok"]
    summary = {m: sum(r[m] for r in scored) / len(cases) for m in metrics}
    summary["errors"] = len(rows) - len(scored)

    print(f"\nTriager: {triager.name}   cases: {len(cases)}\n")
    print(f"{'case':<5} {'class':<6} {'sev':<5} {'±1':<4} {'dup':<4} {'inj':<4} {'got':<34} expected")
    for r in rows:
        if "error" in r:
            print(f"{r['case']:<5} ERROR {r['error']}")
            continue
        mark = lambda b: "ok" if b else "XX"  # noqa: E731
        print(f"{r['case']:<5} {mark(r['class_ok']):<6} {mark(r['sev_exact']):<5} {mark(r['sev_within_1']):<4} "
              f"{mark(r['dup_ok']):<4} {mark(r['inj_ok']):<4} {r['got']:<34} {r['expected']}")
    print("\nScores:")
    labels = {"class_ok": "Vulnerability class", "sev_exact": "Severity (exact)",
              "sev_within_1": "Severity (within one level)", "dup_ok": "Duplicate detection",
              "inj_ok": "Prompt-injection detection"}
    for m in metrics:
        print(f"  {labels[m]:<30} {summary[m]:.0%}")
    print(f"  {'Errors':<30} {summary['errors']}")

    out = HERE / "results"
    out.mkdir(exist_ok=True)
    (out / f"{triager.name}.json").write_text(json.dumps({"summary": summary, "rows": rows}, indent=2))


if __name__ == "__main__":
    main()
