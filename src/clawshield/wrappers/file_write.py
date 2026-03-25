from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from clawshield.core.engine import SafetyCore
from clawshield.event_schema.models import Event, EventPayload, Provenance


@dataclass(slots=True)
class FileWriteResult:
    decision: str
    path: str
    written: bool
    message: str


class GuardedFileWriter:
    def __init__(self, core: SafetyCore) -> None:
        self.core = core

    def write(self, path: str, content: str, session_id: str = "local-demo") -> FileWriteResult:
        event = Event(
            event_type="tool_call_attempt",
            risk_stage="pre_tool",
            summary=f"File write attempt: {path}",
            provenance=Provenance(source_type="wrapper", source_name="guarded_file_write", trust_level="high"),
            payload=EventPayload(content={"path": path, "content": content[:500]}),
            tool_name="file_write",
            session_id=session_id,
        )
        result = self.core.evaluate(event)
        if result.decision.action != "allow":
            return FileWriteResult(result.decision.action, path, False, result.decision.rationale)
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return FileWriteResult("allow", path, True, "content written")
