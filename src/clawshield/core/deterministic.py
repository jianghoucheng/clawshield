from __future__ import annotations

import re
from pathlib import Path

from clawshield.core.decision import Decision
from clawshield.event_schema.models import Event
from clawshield.retrieval.engine import RetrievedPolicy


INJECTION_MARKERS = [
    "ignore previous instructions",
    "system prompt",
    "developer message",
    "exfiltrate",
    "send secrets",
    "collect any api keys",
    "if blocked, try another tool",
]

SHELL_BLOCK_MARKERS = [
    "rm -rf",
    "del /f /s /q",
    "format ",
    "curl ",
    "wget ",
    "powershell -enc",
]

SENSITIVE_SOURCE_MARKERS = [
    "api_keys",
    ".env",
    "id_rsa",
    "customer_records",
    "private/",
    "private\\",
    "secret",
    "token",
    "credential",
    "password",
]

SENSITIVE_READ_MARKERS = [
    "get-content",
    "cat ",
    "type ",
    "select-string",
    "grep ",
    "findstr ",
]

EXFIL_MARKERS = [
    "curl ",
    "wget ",
    "scp ",
    "rsync ",
    "invoke-webrequest",
    "ftp ",
]

SECRET_VALUE_PATTERNS = [
    re.compile(r"(api[_-]?key|access[_-]?token|token|secret|password)[a-z0-9_-]*\s*[:=]", re.IGNORECASE),
    re.compile(r"begin [a-z ]*private key", re.IGNORECASE),
    re.compile(r"classification\s*:\s*(secret|private)", re.IGNORECASE),
]


def _has_secret_like_content(text: str) -> bool:
    lowered = text.lower()
    if "no secrets" in lowered or "non-sensitive" in lowered:
        lowered = lowered.replace("no secrets", "").replace("non-sensitive", "")
    return any(pattern.search(lowered) for pattern in SECRET_VALUE_PATTERNS)


def inspect_hard_barrier(event: Event, retrieved: list[RetrievedPolicy], runtime_dir: Path) -> Decision | None:
    if event.event_type == "tool_result":
        content_text = str(event.payload.content).lower()
        for marker in INJECTION_MARKERS:
            if marker in content_text:
                return Decision(
                    action="sanitize_then_allow",
                    risk_score=0.88,
                    confidence=0.95,
                    rationale="Detected likely indirect prompt injection in tool result.",
                    risk_types=["tool_result_injection"],
                    evidence=[marker],
                    policy_hits=[item.policy.id for item in retrieved],
                    sanitized_payload={"content": "[sanitized remote content removed due to injection markers]"},
                    notes=["sanitized remote content"],
                )
    if event.event_type == "tool_call_attempt" and event.tool_name == "shell":
        command = str(event.payload.content.get("command", "")).lower()
        for marker in SHELL_BLOCK_MARKERS:
            if marker in command:
                return Decision(
                    action="block",
                    risk_score=0.98,
                    confidence=0.98,
                    rationale="Blocked shell command due to dangerous deterministic marker.",
                    risk_types=["dangerous_exec"],
                    evidence=[marker],
                    policy_hits=[item.policy.id for item in retrieved],
                )
        if any(marker in command for marker in SENSITIVE_SOURCE_MARKERS):
            if any(marker in command for marker in EXFIL_MARKERS):
                return Decision(
                    action="block",
                    risk_score=0.97,
                    confidence=0.94,
                    rationale="Blocked shell command that appears to access sensitive data and transfer it externally.",
                    risk_types=["sensitive_data_exfiltration"],
                    evidence=["sensitive-source-and-exfil-marker"],
                    policy_hits=[item.policy.id for item in retrieved],
                )
            if any(marker in command for marker in SENSITIVE_READ_MARKERS) or "copy " in command or "move " in command:
                return Decision(
                    action="require_confirm",
                    risk_score=0.8,
                    confidence=0.86,
                    rationale="Shell command appears to access privacy-sensitive local material.",
                    risk_types=["sensitive_data_access"],
                    evidence=["sensitive-source-marker"],
                    policy_hits=[item.policy.id for item in retrieved],
                )
        if "export" in command or "copy" in command:
            return Decision(
                action="require_confirm",
                risk_score=0.72,
                confidence=0.75,
                rationale="Shell action may move or export data and should be confirmed.",
                risk_types=["intent_action_mismatch"],
                evidence=["export-or-copy"],
                policy_hits=[item.policy.id for item in retrieved],
            )
    if event.event_type == "tool_call_attempt" and event.tool_name == "file_write":
        target = str(event.payload.content.get("path", ""))
        normalized = Path(target)
        if normalized.is_absolute() and runtime_dir not in normalized.parents and normalized != runtime_dir:
            return Decision(
                action="block",
                risk_score=0.94,
                confidence=0.96,
                rationale="Blocked absolute file write outside the isolated runtime directory.",
                risk_types=["unsafe_file_write"],
                evidence=[target],
                policy_hits=[item.policy.id for item in retrieved],
            )
        text = str(event.payload.content.get("content", ""))
        if _has_secret_like_content(text):
            return Decision(
                action="require_confirm",
                risk_score=0.76,
                confidence=0.83,
                rationale="File content appears to include sensitive material.",
                risk_types=["possible_secret_write"],
                evidence=["secret-like-content"],
                policy_hits=[item.policy.id for item in retrieved],
            )
    if event.event_type == "tool_call_attempt" and event.tool_name == "web_fetch":
        url = str(event.payload.content.get("url", "")).lower()
        if not url.startswith(("http://", "https://")):
            return Decision(
                action="block",
                risk_score=0.9,
                confidence=0.94,
                rationale="Blocked non-http remote ingest target.",
                risk_types=["untrusted_remote_ingest"],
                evidence=[url],
                policy_hits=[item.policy.id for item in retrieved],
            )
    return None


def inspect_fallback_heuristics(event: Event, retrieved: list[RetrievedPolicy]) -> Decision | None:
    if event.event_type in {"memory_update", "prompt_build_context"}:
        content_text = str(event.payload.content).lower()
        for marker in INJECTION_MARKERS:
            if marker in content_text:
                return Decision(
                    action="require_confirm",
                    risk_score=0.9,
                    confidence=0.92,
                    rationale="Suspicious content appears to be entering memory or prompt-building context.",
                    risk_types=["memory_or_context_poisoning"],
                    evidence=[marker],
                    policy_hits=[item.policy.id for item in retrieved],
                    notes=["review memory update or prompt context before reuse"],
                )
    if event.event_type == "user_request":
        summary = f"{event.summary.lower()} {str(event.payload.content).lower()}"
        if any(marker in summary for marker in EXFIL_MARKERS) and any(marker in summary for marker in SENSITIVE_SOURCE_MARKERS):
            return Decision(
                action="require_confirm",
                risk_score=0.78,
                confidence=0.8,
                rationale="User request appears to combine sensitive local data with transfer or export intent.",
                risk_types=["sensitive_intent_request"],
                evidence=["sensitive-source-and-transfer-intent"],
                policy_hits=[item.policy.id for item in retrieved],
            )
    return None
