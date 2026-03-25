from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from clawshield.utils import gen_id, utc_now


@dataclass(slots=True)
class Provenance:
    source_type: str
    source_name: str
    trust_level: str = "unknown"
    raw_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EventPayload:
    content: dict[str, Any] = field(default_factory=dict)
    raw_payload: dict[str, Any] | None = None


@dataclass(slots=True)
class Event:
    event_type: str
    risk_stage: str
    summary: str
    provenance: Provenance
    payload: EventPayload = field(default_factory=EventPayload)
    session_id: str | None = None
    run_id: str | None = None
    tool_name: str | None = None
    event_id: str = field(default_factory=lambda: gen_id("evt"))
    timestamp: str = field(default_factory=utc_now)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
