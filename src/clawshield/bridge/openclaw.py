from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import sys
from pathlib import Path

from clawshield.cli.main import build_core
from clawshield.config import Settings
from clawshield.core.engine import SafetyCore
from clawshield.event_schema.models import Event, EventPayload, Provenance
from clawshield.wrappers.file_write import GuardedFileWriter
from clawshield.wrappers.shell import GuardedShell
from clawshield.wrappers.web_fetch import GuardedWebFetcher


def _core() -> SafetyCore:
    root = Path(__file__).resolve().parents[3]
    return build_core(Settings.load(root))


def shell_cmd(args: argparse.Namespace) -> int:
    result = GuardedShell(_core()).run(args.command, session_id=args.session_id, execute=args.execute)
    print(json.dumps(asdict(result), ensure_ascii=True))
    return 0 if result.decision == "allow" else 2


def file_write_cmd(args: argparse.Namespace) -> int:
    content = Path(args.content_file).read_text(encoding="utf-8") if args.content_file else args.content
    result = GuardedFileWriter(_core()).write(args.path, content, session_id=args.session_id)
    print(json.dumps(asdict(result), ensure_ascii=True))
    return 0 if result.decision == "allow" else 2


def web_fetch_cmd(args: argparse.Namespace) -> int:
    result = GuardedWebFetcher(_core()).fetch(args.url, session_id=args.session_id, perform_fetch=args.perform_fetch)
    print(json.dumps(asdict(result), ensure_ascii=True))
    return 0 if result.decision == "allow" else 2


def tool_result_cmd(args: argparse.Namespace) -> int:
    if not args.content and not args.content_file:
        raise SystemExit("Provide --content or --content-file")
    content = Path(args.content_file).read_text(encoding="utf-8") if args.content_file else args.content
    event = Event(
        event_type="tool_result",
        risk_stage="post_tool",
        summary=args.summary or f"Tool result from {args.source_name}",
        provenance=Provenance(source_type=args.source_type, source_name=args.source_name, trust_level=args.trust_level),
        payload=EventPayload(content={"content": content}),
        tool_name=args.tool_name,
        session_id=args.session_id,
    )
    result = _core().evaluate(event)
    print(json.dumps(result.decision.to_dict(), ensure_ascii=True))
    return 0 if result.decision.action == "allow" else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="clawshield-openclaw-bridge")
    sub = parser.add_subparsers(dest="command_name", required=True)

    shell = sub.add_parser("shell")
    shell.add_argument("--command", required=True)
    shell.add_argument("--session-id", default="openclaw-bridge")
    shell.add_argument("--execute", action="store_true")
    shell.set_defaults(func=shell_cmd)

    file_write = sub.add_parser("file-write")
    file_write.add_argument("--path", required=True)
    file_write.add_argument("--content", default="")
    file_write.add_argument("--content-file")
    file_write.add_argument("--session-id", default="openclaw-bridge")
    file_write.set_defaults(func=file_write_cmd)

    web = sub.add_parser("web-fetch")
    web.add_argument("--url", required=True)
    web.add_argument("--session-id", default="openclaw-bridge")
    web.add_argument("--perform-fetch", action="store_true")
    web.set_defaults(func=web_fetch_cmd)

    tool_result = sub.add_parser("tool-result")
    tool_result.add_argument("--content")
    tool_result.add_argument("--content-file")
    tool_result.add_argument("--tool-name", default="web_fetch")
    tool_result.add_argument("--source-type", default="web")
    tool_result.add_argument("--source-name", default="openclaw")
    tool_result.add_argument("--trust-level", default="low")
    tool_result.add_argument("--summary")
    tool_result.add_argument("--session-id", default="openclaw-bridge")
    tool_result.set_defaults(func=tool_result_cmd)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
