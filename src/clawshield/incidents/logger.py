from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from clawshield.core.decision import Decision
from clawshield.event_schema.models import Event
from clawshield.retrieval.engine import RetrievedPolicy
from clawshield.utils import ensure_jsonable, utc_now

LOGGER = logging.getLogger(__name__)


class IncidentLogger:
    def __init__(self, incident_path: Path) -> None:
        self.incident_path = incident_path
        self.incident_path.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        event: Event,
        decision: Decision,
        retrieved: list[RetrievedPolicy],
        judge_output: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        evolution = self._evolution_suggestion(event, decision, retrieved, judge_output)
        record = {
            "timestamp": utc_now(),
            "event": event.to_dict(),
            "event_summary": event.summary,
            "policies_retrieved": [
                {"id": item.policy.id, "score": item.score, "reasons": item.reasons}
                for item in retrieved
            ],
            "judge_output": judge_output,
            "final_decision": decision.to_dict(),
            "why": decision.rationale,
            "deterministic": decision.deterministic,
            "llm_assisted": decision.judge_used,
            "evolution": evolution,
        }
        with self.incident_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(ensure_jsonable(record), ensure_ascii=True) + "\n")
        return record

    def _evolution_suggestion(
        self,
        event: Event,
        decision: Decision,
        retrieved: list[RetrievedPolicy],
        judge_output: dict[str, Any] | None,
    ) -> dict[str, Any]:
        policy_hits = [item.policy.id for item in retrieved]
        should_review = (
            decision.action in {"block", "require_confirm", "sanitize_then_allow"}
            or bool(decision.risk_types)
            or judge_output is not None
        )
        mode = "revise_existing" if policy_hits else "new_candidate"
        reasons: list[str] = []
        if decision.action in {"block", "require_confirm", "sanitize_then_allow"}:
            reasons.append("restrictive_decision")
        if judge_output is not None:
            reasons.append("llm_assisted_decision")
        if len(policy_hits) > 0:
            reasons.append("existing_policy_context_present")
        if event.event_type in {"memory_update", "prompt_build_context"}:
            reasons.append("cross_turn_context_risk")
        return {
            "should_review": should_review,
            "mode": mode,
            "policy_hits": policy_hits,
            "reasons": reasons,
        }

    def read_all(self) -> list[dict[str, Any]]:
        if not self.incident_path.exists():
            return []
        records: list[dict[str, Any]] = []
        for lineno, line in enumerate(self.incident_path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                LOGGER.warning("Skipping invalid incident line %s in %s", lineno, self.incident_path)
        return records
