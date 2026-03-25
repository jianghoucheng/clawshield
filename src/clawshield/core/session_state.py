from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class SessionState:
    session_id: str
    recent_events: list[dict[str, Any]] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SessionStateStore:
    def __init__(self, runtime_dir: Path) -> None:
        self.base_dir = runtime_dir / "session_state"
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, session_id: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in session_id)
        return self.base_dir / f"{safe}.json"

    def load(self, session_id: str) -> SessionState:
        path = self._path(session_id)
        if not path.exists():
            return SessionState(session_id=session_id)
        data = json.loads(path.read_text(encoding="utf-8"))
        return SessionState(
            session_id=data.get("session_id", session_id),
            recent_events=list(data.get("recent_events", [])),
            risk_flags=list(data.get("risk_flags", [])),
            counters=dict(data.get("counters", {})),
        )

    def save(self, state: SessionState) -> None:
        self._path(state.session_id).write_text(json.dumps(state.to_dict(), ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

    def update(self, session_id: str, event: dict[str, Any], decision: dict[str, Any]) -> SessionState:
        state = self.load(session_id)
        state.recent_events.append(
            {
                "event_type": event.get("event_type"),
                "risk_stage": event.get("risk_stage"),
                "summary": event.get("summary"),
                "tool_name": event.get("tool_name"),
                "decision": decision.get("action"),
                "risk_types": decision.get("risk_types", []),
            }
        )
        state.recent_events = state.recent_events[-8:]
        for risk_type in decision.get("risk_types", []):
            if risk_type not in state.risk_flags:
                state.risk_flags.append(risk_type)
            state.counters[risk_type] = state.counters.get(risk_type, 0) + 1
        state.risk_flags = state.risk_flags[-12:]
        self.save(state)
        return state
