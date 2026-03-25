from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Policy:
    id: str
    title: str
    scope: list[str]
    trigger: dict[str, Any]
    risk_type: str
    required_evidence: list[str]
    default_action: str
    severity: str
    rationale: str
    examples: list[dict[str, str]]
    status: str
    version: str
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        required = {
            "id",
            "title",
            "scope",
            "trigger",
            "risk_type",
            "required_evidence",
            "default_action",
            "severity",
            "rationale",
            "examples",
            "status",
            "version",
        }
        missing = sorted(required - set(data))
        if missing:
            raise ValueError(f"Policy missing required fields: {', '.join(missing)}")
        return cls(
            id=data["id"],
            title=data["title"],
            scope=list(data["scope"]),
            trigger=dict(data["trigger"]),
            risk_type=data["risk_type"],
            required_evidence=list(data["required_evidence"]),
            default_action=data["default_action"],
            severity=data["severity"],
            rationale=data["rationale"],
            examples=list(data["examples"]),
            status=data["status"],
            version=data["version"],
            tags=list(data.get("tags", [])),
        )


def validate_policy_document(data: dict[str, Any]) -> None:
    if data.get("candidate_type") == "policy_revision":
        required = {"candidate_type", "target_policy_id", "proposed_changes", "why", "status", "version", "tags"}
        missing = sorted(required - set(data))
        if missing:
            raise ValueError(f"Policy revision candidate missing required fields: {', '.join(missing)}")
        if data["candidate_type"] != "policy_revision":
            raise ValueError("candidate_type must be policy_revision")
        return
    Policy.from_dict(data)
