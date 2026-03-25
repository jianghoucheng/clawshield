from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib import request
from urllib.error import URLError

from clawshield.core.decision import Decision

LOGGER = logging.getLogger(__name__)


def _coerce_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return [str(value)]


def _normalize_api_type(value: str | None) -> str:
    normalized = (value or "openai").strip().lower().replace("-", "_")
    aliases = {
        "openai_compatible": "openai",
        "compatible": "openai",
        "anthropic_messages": "anthropic",
        "claude": "anthropic",
    }
    return aliases.get(normalized, normalized)


def _build_endpoint(api_base: str, api_type: str, path: str) -> str:
    base = api_base.rstrip("/")
    if base.endswith(path):
        return base
    return f"{base}{path}"


@dataclass(slots=True)
class JudgeResult:
    risk_score: float
    risk_types: list[str]
    evidence: list[str]
    decision: str
    confidence: float
    policy_hits: list[str]
    notes: list[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "JudgeResult":
        required = {
            "risk_score",
            "risk_types",
            "evidence",
            "decision",
            "confidence",
            "policy_hits",
            "notes",
        }
        missing = sorted(required - set(data))
        if missing:
            raise ValueError(f"Judge response missing required fields: {', '.join(missing)}")
        return cls(
            risk_score=float(data["risk_score"]),
            risk_types=_coerce_list(data["risk_types"]),
            evidence=_coerce_list(data["evidence"]),
            decision=str(data["decision"]),
            confidence=float(data["confidence"]),
            policy_hits=_coerce_list(data["policy_hits"]),
            notes=_coerce_list(data["notes"]),
        )

    def to_decision(self, rationale: str) -> Decision:
        return Decision(
            action=self.decision,
            risk_score=self.risk_score,
            confidence=self.confidence,
            rationale=rationale,
            risk_types=self.risk_types,
            evidence=self.evidence,
            policy_hits=self.policy_hits,
            judge_used=True,
            deterministic=False,
            notes=self.notes,
        )


class GuardJudgeClient:
    def __init__(
        self,
        api_base: str | None,
        api_key: str | None,
        model: str | None,
        api_type: str | None = "openai",
        api_version: str | None = None,
        max_tokens: int = 1000,
    ) -> None:
        self.api_base = api_base
        self.api_key = api_key
        self.model = model
        self.api_type = _normalize_api_type(api_type)
        self.api_version = api_version or "2023-06-01"
        self.max_tokens = max_tokens

    def configured(self) -> bool:
        return bool(self.api_base and self.api_key and self.model)

    def judge(self, context: dict[str, Any]) -> JudgeResult | None:
        if not self.configured():
            return None
        system_prompt = (
            "You are an OpenClaw runtime safety judge. "
            "Deterministic hard barriers are handled outside you. "
            "Use policies as structured context, evidence guidance, and response preference, not as rigid keyword rules. "
            "Consider event content, session history, recent memory diffs, and policy context together. "
            "Return JSON only with fields: risk_score, risk_types, evidence, decision, confidence, policy_hits, notes."
        )
        try:
            data = self._request_json(system_prompt, context)
            return JudgeResult.from_dict(data)
        except (URLError, TimeoutError, KeyError, ValueError, json.JSONDecodeError) as exc:
            LOGGER.warning("Guard judge unavailable or invalid response: %s", exc)
            return None

    def generate_policy_candidates(self, context: dict[str, Any]) -> list[dict[str, Any]] | None:
        if not self.configured():
            return None
        system_prompt = (
            "Generate JSON only with a top-level field named policies. "
            "Each policy must include: id, title, scope, trigger, risk_type, "
            "required_evidence, default_action, severity, rationale, examples, "
            "status, version, tags. Use status candidate."
        )
        try:
            data = self._request_json(system_prompt, context)
            policies = data["policies"]
            if not isinstance(policies, list):
                raise ValueError("policies must be a list")
            return policies
        except (URLError, TimeoutError, KeyError, ValueError, json.JSONDecodeError) as exc:
            LOGGER.warning("Policy generation unavailable or invalid response: %s", exc)
            return None

    def _request_json(self, system_prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        if self.api_type == "anthropic":
            return self._request_anthropic(system_prompt, context)
        return self._request_openai_compatible(system_prompt, context)

    def _request_openai_compatible(self, system_prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(context, ensure_ascii=True)},
            ],
        }
        req = request.Request(
            url=_build_endpoint(str(self.api_base), self.api_type, "/chat/completions"),
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with request.urlopen(req, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8"))
        message = body["choices"][0]["message"]["content"]
        return json.loads(message)

    def _request_anthropic(self, system_prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "system": system_prompt,
            "max_tokens": self.max_tokens,
            "temperature": 0,
            "messages": [
                {
                    "role": "user",
                    "content": json.dumps(context, ensure_ascii=True),
                }
            ],
        }
        req = request.Request(
            url=_build_endpoint(str(self.api_base), self.api_type, "/messages"),
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": str(self.api_key),
                "anthropic-version": self.api_version,
            },
            method="POST",
        )
        with request.urlopen(req, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8"))
        content = body["content"]
        if not isinstance(content, list) or not content:
            raise ValueError("Anthropic response missing content")
        text_blocks = [block.get("text", "") for block in content if isinstance(block, dict) and block.get("type") == "text"]
        if not text_blocks:
            raise ValueError("Anthropic response missing text block")
        return json.loads("\n".join(text_blocks))
