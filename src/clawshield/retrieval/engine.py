from __future__ import annotations

from dataclasses import dataclass

from clawshield.event_schema.models import Event
from clawshield.policy.schema import Policy


@dataclass(slots=True)
class RetrievedPolicy:
    policy: Policy
    score: int
    reasons: list[str]


class PolicyRetriever:
    def __init__(self, policies: list[Policy]) -> None:
        self.policies = policies

    def retrieve(
        self,
        event: Event,
        tool_type: str | None = None,
        source_type: str | None = None,
        risk_stage: str | None = None,
        recent_memory_diff: str | None = None,
        limit: int = 5,
    ) -> list[RetrievedPolicy]:
        ranked: list[RetrievedPolicy] = []
        haystack = " ".join(
            [
                event.summary.lower(),
                event.event_type.lower(),
                (tool_type or "").lower(),
                (source_type or event.provenance.source_type).lower(),
                (risk_stage or event.risk_stage).lower(),
                recent_memory_diff.lower() if recent_memory_diff else "",
                " ".join(event.tags).lower(),
            ]
        )
        for policy in self.policies:
            if policy.status not in {"active", "shadow", "candidate"}:
                continue
            score = 0
            reasons: list[str] = []
            keywords = [str(v).lower() for v in policy.trigger.get("keywords", [])]
            if any(keyword in haystack for keyword in keywords):
                score += 4
                reasons.append("keyword")
            if tool_type and tool_type in policy.scope:
                score += 3
                reasons.append("tool-scope")
            if event.event_type in policy.scope:
                score += 2
                reasons.append("event-scope")
            if policy.risk_type.lower() in haystack:
                score += 2
                reasons.append("risk-type")
            if source_type and source_type in policy.scope:
                score += 1
                reasons.append("source-scope")
            if risk_stage and risk_stage == event.risk_stage:
                score += 1
                reasons.append("risk-stage")
            if score > 0:
                ranked.append(RetrievedPolicy(policy=policy, score=score, reasons=reasons))
        ranked.sort(key=lambda item: item.score, reverse=True)
        return ranked[:limit]
