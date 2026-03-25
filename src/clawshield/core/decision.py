from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Decision:
    action: str
    risk_score: float
    confidence: float
    rationale: str
    risk_types: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    policy_hits: list[str] = field(default_factory=list)
    sanitized_payload: dict[str, Any] | None = None
    judge_used: bool = False
    deterministic: bool = True
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
