from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def gen_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def ensure_jsonable(data: Any) -> Any:
    if isinstance(data, Path):
        return str(data)
    if isinstance(data, dict):
        return {str(k): ensure_jsonable(v) for k, v in data.items()}
    if isinstance(data, list):
        return [ensure_jsonable(v) for v in data]
    return data


def dumps(data: Any) -> str:
    return json.dumps(ensure_jsonable(data), ensure_ascii=True, sort_keys=True)


def configure_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
