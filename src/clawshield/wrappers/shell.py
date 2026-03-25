from __future__ import annotations

import subprocess
from dataclasses import dataclass

from clawshield.core.engine import SafetyCore
from clawshield.event_schema.models import Event, EventPayload, Provenance


@dataclass(slots=True)
class ShellResult:
    decision: str
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None


class GuardedShell:
    def __init__(self, core: SafetyCore) -> None:
        self.core = core

    def run(self, command: str, session_id: str = "local-demo", execute: bool = False) -> ShellResult:
        event = Event(
            event_type="tool_call_attempt",
            risk_stage="pre_tool",
            summary=f"Shell execution attempt: {command[:80]}",
            provenance=Provenance(source_type="wrapper", source_name="guarded_shell", trust_level="high"),
            payload=EventPayload(content={"command": command}),
            tool_name="shell",
            session_id=session_id,
        )
        result = self.core.evaluate(event)
        if result.decision.action != "allow" or not execute:
            return ShellResult(decision=result.decision.action, stderr=result.decision.rationale)
        completed = subprocess.run(command, capture_output=True, text=True, shell=True, check=False)
        return ShellResult(
            decision="allow",
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
        )
