from __future__ import annotations

import json
from pathlib import Path

from clawshield.policy.schema import Policy, validate_policy_document


class PolicyLoader:
    def __init__(self, policy_dir: Path) -> None:
        self.policy_dir = policy_dir

    def load(self) -> list[Policy]:
        policies: list[Policy] = []
        for path in sorted(self.policy_dir.rglob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("candidate_type") == "policy_revision":
                continue
            policies.append(Policy.from_dict(data))
        return policies

    def validate(self) -> list[str]:
        errors: list[str] = []
        for path in sorted(self.policy_dir.rglob("*.json")):
            try:
                validate_policy_document(json.loads(path.read_text(encoding="utf-8")))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{path.name}: {exc}")
        return errors
