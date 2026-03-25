from __future__ import annotations

from typing import Any

from clawshield.core.engine import SafetyCore
from clawshield.event_schema.models import Event, EventPayload, Provenance


class OpenClawAdapter:
    """Thin adapter scaffold for local OpenClaw hook integration."""

    def __init__(self, core: SafetyCore) -> None:
        self.core = core

    def before_tool_call(self, tool_name: str, payload: dict[str, Any], session_id: str | None = None) -> dict[str, Any]:
        event = Event(
            event_type="tool_call_attempt",
            risk_stage="pre_tool",
            summary=f"OpenClaw before_tool_call for {tool_name}",
            provenance=Provenance(source_type="openclaw_hook", source_name="before_tool_call", trust_level="medium"),
            payload=EventPayload(content=payload, raw_payload=payload),
            tool_name=tool_name,
            session_id=session_id,
        )
        return self.core.evaluate(event).decision.to_dict()

    def after_tool_call(self, tool_name: str, payload: dict[str, Any], session_id: str | None = None) -> dict[str, Any]:
        event = Event(
            event_type="tool_result",
            risk_stage="post_tool",
            summary=f"OpenClaw after_tool_call for {tool_name}",
            provenance=Provenance(source_type="openclaw_hook", source_name="after_tool_call", trust_level="medium"),
            payload=EventPayload(content=payload, raw_payload=payload),
            tool_name=tool_name,
            session_id=session_id,
        )
        return self.core.evaluate(event).decision.to_dict()

    def tool_result_persist(self, payload: dict[str, Any], session_id: str | None = None) -> dict[str, Any]:
        event = Event(
            event_type="memory_update",
            risk_stage="persist",
            summary="OpenClaw tool_result_persist event",
            provenance=Provenance(source_type="openclaw_hook", source_name="tool_result_persist", trust_level="medium"),
            payload=EventPayload(content=payload, raw_payload=payload),
            session_id=session_id,
        )
        return self.core.evaluate(event, recent_memory_diff=str(payload)).decision.to_dict()

    def before_prompt_build(self, payload: dict[str, Any], session_id: str | None = None) -> dict[str, Any]:
        event = Event(
            event_type="prompt_build_context",
            risk_stage="pre_prompt",
            summary="OpenClaw before_prompt_build event",
            provenance=Provenance(source_type="openclaw_hook", source_name="before_prompt_build", trust_level="medium"),
            payload=EventPayload(content=payload, raw_payload=payload),
            session_id=session_id,
        )
        return self.core.evaluate(event, recent_memory_diff=str(payload)).decision.to_dict()
