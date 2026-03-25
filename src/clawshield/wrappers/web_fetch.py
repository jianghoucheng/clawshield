from __future__ import annotations

from dataclasses import dataclass
from urllib import request
from urllib.error import URLError

from clawshield.core.engine import SafetyCore
from clawshield.event_schema.models import Event, EventPayload, Provenance


@dataclass(slots=True)
class WebFetchResult:
    decision: str
    content: str = ""
    message: str = ""


class GuardedWebFetcher:
    def __init__(self, core: SafetyCore) -> None:
        self.core = core

    def fetch(self, url: str, session_id: str = "local-demo", perform_fetch: bool = False) -> WebFetchResult:
        event = Event(
            event_type="tool_call_attempt",
            risk_stage="pre_tool",
            summary=f"Web fetch attempt: {url}",
            provenance=Provenance(source_type="wrapper", source_name="guarded_web_fetch", trust_level="medium"),
            payload=EventPayload(content={"url": url}),
            tool_name="web_fetch",
            session_id=session_id,
        )
        result = self.core.evaluate(event)
        if result.decision.action != "allow" or not perform_fetch:
            return WebFetchResult(result.decision.action, message=result.decision.rationale)
        try:
            with request.urlopen(url, timeout=15) as response:
                content = response.read(4096).decode("utf-8", errors="replace")
            return WebFetchResult("allow", content=content, message="fetched")
        except URLError as exc:
            return WebFetchResult("warn", message=f"fetch failed: {exc}")
