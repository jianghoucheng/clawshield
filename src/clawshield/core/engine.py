from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from clawshield.core.decision import Decision
from clawshield.core.deterministic import inspect_fallback_heuristics, inspect_hard_barrier
from clawshield.core.session_state import SessionStateStore
from clawshield.event_schema.models import Event
from clawshield.incidents.logger import IncidentLogger
from clawshield.judge.client import GuardJudgeClient
from clawshield.policy.loader import PolicyLoader
from clawshield.retrieval.engine import PolicyRetriever


@dataclass(slots=True)
class EvaluationResult:
    event: Event
    decision: Decision
    incident: dict[str, Any]


class SafetyCore:
    def __init__(
        self,
        policy_loader: PolicyLoader,
        incident_logger: IncidentLogger,
        judge_client: GuardJudgeClient,
        runtime_dir,
    ) -> None:
        self.policy_loader = policy_loader
        self.incident_logger = incident_logger
        self.judge_client = judge_client
        self.runtime_dir = runtime_dir
        self._policies = self.policy_loader.load()
        self.retriever = PolicyRetriever(self._policies)
        self.session_state = SessionStateStore(self.runtime_dir)

    def refresh_policies(self) -> None:
        self._policies = self.policy_loader.load()
        self.retriever = PolicyRetriever(self._policies)

    def evaluate(self, event: Event, recent_memory_diff: str | None = None) -> EvaluationResult:
        session_id = event.session_id or "default"
        current_state = self.session_state.load(session_id)
        retrieved = self.retriever.retrieve(
            event,
            tool_type=event.tool_name,
            source_type=event.provenance.source_type,
            risk_stage=event.risk_stage,
            recent_memory_diff=recent_memory_diff,
        )
        hard_barrier = inspect_hard_barrier(event, retrieved, self.runtime_dir)
        if hard_barrier is not None:
            incident = self.incident_logger.log(event, hard_barrier, retrieved)
            self.session_state.update(session_id, event.to_dict(), hard_barrier.to_dict())
            return EvaluationResult(event=event, decision=hard_barrier, incident=incident)

        judge_output = self.judge_client.judge(
            {
                "event": event.to_dict(),
                "retrieved_policies": [
                    {
                        "id": item.policy.id,
                        "title": item.policy.title,
                        "scope": item.policy.scope,
                        "risk_type": item.policy.risk_type,
                        "required_evidence": item.policy.required_evidence,
                        "default_action": item.policy.default_action,
                        "severity": item.policy.severity,
                        "rationale": item.policy.rationale,
                        "tags": item.policy.tags,
                        "retrieval_reasons": item.reasons,
                        "retrieval_score": item.score,
                    }
                    for item in retrieved
                ],
                "recent_memory_diff": recent_memory_diff,
                "session_state": current_state.to_dict(),
                "judge_instruction": {
                    "mode": "online_guard",
                    "policy_role": "Policies are structured context and consistency guidance, not the sole judge.",
                    "hard_barrier_role": "If a deterministic hard barrier already fired, the caller would have blocked before you.",
                },
            }
        )
        if judge_output is not None:
            decision = judge_output.to_decision("Decision from external guard judge.")
            incident = self.incident_logger.log(event, decision, retrieved, judge_output=judge_output.__dict__)
            self.session_state.update(session_id, event.to_dict(), decision.to_dict())
            return EvaluationResult(event=event, decision=decision, incident=incident)

        fallback = inspect_fallback_heuristics(event, retrieved)
        if fallback is not None:
            incident = self.incident_logger.log(event, fallback, retrieved)
            self.session_state.update(session_id, event.to_dict(), fallback.to_dict())
            return EvaluationResult(event=event, decision=fallback, incident=incident)

        decision = Decision(
            action="allow",
            risk_score=0.15,
            confidence=0.55,
            rationale="No hard barrier fired and no guard judge override.",
            risk_types=[],
            evidence=[],
            policy_hits=[item.policy.id for item in retrieved],
            judge_used=False,
            deterministic=True,
        )
        incident = self.incident_logger.log(event, decision, retrieved)
        self.session_state.update(session_id, event.to_dict(), decision.to_dict())
        return EvaluationResult(event=event, decision=decision, incident=incident)
