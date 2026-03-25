from __future__ import annotations

import os
import json
from dataclasses import dataclass
from pathlib import Path


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


@dataclass(slots=True)
class Settings:
    project_root: Path
    policy_dir: Path
    incident_path: Path
    runtime_dir: Path
    guard_api_type: str | None
    guard_api_base: str | None
    guard_api_key: str | None
    guard_model: str | None
    guard_api_version: str | None
    guard_max_tokens: int

    @classmethod
    def load(cls, project_root: Path | None = None) -> "Settings":
        root = project_root or Path(__file__).resolve().parents[2]
        load_dotenv(root / ".env")
        policy_dir = root / os.environ.get("CLAWSHIELD_POLICY_DIR", "policies/base")
        incident_path = root / os.environ.get("CLAWSHIELD_INCIDENT_PATH", "data/incidents/incidents.jsonl")
        runtime_dir = root / os.environ.get("CLAWSHIELD_RUNTIME_DIR", "data/runtime")
        runtime_dir.mkdir(parents=True, exist_ok=True)
        incident_path.parent.mkdir(parents=True, exist_ok=True)
        return cls(
            project_root=root,
            policy_dir=policy_dir,
            incident_path=incident_path,
            runtime_dir=runtime_dir,
            guard_api_type=os.environ.get("GUARD_API_TYPE", "openai"),
            guard_api_base=os.environ.get("GUARD_API_BASE"),
            guard_api_key=os.environ.get("GUARD_API_KEY"),
            guard_model=os.environ.get("GUARD_MODEL"),
            guard_api_version=os.environ.get("GUARD_API_VERSION", "2023-06-01"),
            guard_max_tokens=int(os.environ.get("GUARD_MAX_TOKENS", "1000")),
        )


def resolve_openclaw_config_path(profile: str | None = None) -> Path:
    home = Path.home()
    if profile and profile not in {"default", "main"}:
        return home / f".openclaw-{profile}" / "openclaw.json"
    return home / ".openclaw" / "openclaw.json"


def resolve_openclaw_workspace(profile: str | None = None) -> Path:
    config_path = resolve_openclaw_config_path(profile)
    if not config_path.exists():
        raise FileNotFoundError(f"OpenClaw config not found: {config_path}")
    data = json.loads(config_path.read_text(encoding="utf-8"))
    workspace = data.get("agents", {}).get("defaults", {}).get("workspace")
    if not workspace:
        raise ValueError(f"OpenClaw workspace not configured in: {config_path}")
    return Path(workspace).expanduser().resolve()
