from __future__ import annotations

import argparse
import json
from pathlib import Path

from clawshield.adapter_openclaw import install_workspace_bootstrap
from clawshield.config import Settings, resolve_openclaw_workspace
from clawshield.core.engine import SafetyCore
from clawshield.incidents.logger import IncidentLogger
from clawshield.judge.client import GuardJudgeClient
from clawshield.policy.loader import PolicyLoader
from clawshield.utils import configure_logging, dumps


def build_core(settings: Settings) -> SafetyCore:
    return SafetyCore(
        policy_loader=PolicyLoader(settings.policy_dir),
        incident_logger=IncidentLogger(settings.incident_path),
        judge_client=GuardJudgeClient(
            settings.guard_api_base,
            settings.guard_api_key,
            settings.guard_model,
            api_type=settings.guard_api_type,
            api_version=settings.guard_api_version,
            max_tokens=settings.guard_max_tokens,
        ),
        runtime_dir=settings.runtime_dir.resolve(),
    )


def cmd_install_openclaw(settings: Settings, workspace: str | None) -> int:
    target = Path(workspace).resolve() if workspace else settings.project_root
    result = install_workspace_bootstrap(target)
    print(f"workspace={target}")
    for name, status in result.items():
        print(f"{name}={status}")
    print("bridge=clawshield-openclaw-bridge")
    return 0


def cmd_attach_openclaw(profile: str | None) -> int:
    workspace = resolve_openclaw_workspace(profile)
    result = install_workspace_bootstrap(workspace)
    print(f"profile={profile or 'default'}")
    print(f"workspace={workspace}")
    for name, status in result.items():
        print(f"{name}={status}")
    print("bridge=clawshield-openclaw-bridge")
    return 0


def cmd_incidents(settings: Settings) -> int:
    logger = IncidentLogger(settings.incident_path)
    incidents = logger.read_all()
    print(f"incidents={len(incidents)}")
    for item in incidents[-10:]:
        print(
            dumps(
                {
                    "timestamp": item["timestamp"],
                    "summary": item["event_summary"],
                    "decision": item["final_decision"]["action"],
                    "why": item["why"],
                }
            )
        )
    return 0


def _local_policy_candidate(incident: dict, idx: int) -> dict:
    event = incident["event"]
    tool_name = event.get("tool_name") or "general"
    risk_types = incident["final_decision"].get("risk_types") or ["review_needed"]
    return {
        "id": f"cand-{idx:03d}-{tool_name}",
        "title": f"Candidate policy from incident {idx}",
        "scope": [event["event_type"], tool_name],
        "trigger": {"keywords": risk_types + [tool_name]},
        "risk_type": risk_types[0],
        "required_evidence": ["event.summary", "event.payload", "decision.evidence"],
        "default_action": incident["final_decision"]["action"],
        "severity": "medium",
        "rationale": "Candidate synthesized from incident review.",
        "examples": [{"input": event["summary"], "expected": incident["final_decision"]["action"]}],
        "status": "candidate",
        "version": "0.1.0",
        "tags": ["generated", "incident-derived"],
    }


def _local_policy_revision_candidate(incident: dict, idx: int) -> dict | None:
    evolution = incident.get("evolution", {})
    policy_hits = evolution.get("policy_hits") or []
    if not policy_hits:
        return None
    target_policy_id = policy_hits[0]
    decision = incident["final_decision"]
    risk_types = decision.get("risk_types") or ["review_needed"]
    summary = incident["event_summary"]
    return {
        "id": f"rev-{idx:03d}-{target_policy_id}",
        "candidate_type": "policy_revision",
        "target_policy_id": target_policy_id,
        "proposed_changes": {
            "trigger": {
                "keywords_add": [risk_types[0], incident["event"].get("tool_name") or incident["event"]["event_type"]],
            },
            "required_evidence_add": ["session_state.recent_events", "incident.final_decision", "incident.why"],
            "examples_add": [{"input": summary, "expected": decision["action"]}],
            "default_action": decision["action"],
        },
        "why": f"Incident suggests the existing policy {target_policy_id} may need adjustment or broader retrieval coverage.",
        "status": "candidate",
        "version": "0.1.0",
        "tags": ["generated", "revision", "incident-derived"],
    }


def cmd_policy_generate(settings: Settings) -> int:
    logger = IncidentLogger(settings.incident_path)
    incidents = logger.read_all()
    suspicious = [item for item in incidents if item.get("evolution", {}).get("should_review")]
    output_dir = settings.project_root / "policies" / "local"
    output_dir.mkdir(parents=True, exist_ok=True)
    if not suspicious:
        print("No suspicious incidents found.")
        return 0
    judge = GuardJudgeClient(
        settings.guard_api_base,
        settings.guard_api_key,
        settings.guard_model,
        api_type=settings.guard_api_type,
        api_version=settings.guard_api_version,
        max_tokens=settings.guard_max_tokens,
    )
    generated = judge.generate_policy_candidates({"incidents": suspicious}) if judge.configured() else None
    if generated:
        candidates = generated
    else:
        candidates = []
        for idx, incident in enumerate(suspicious, start=1):
            if incident.get("evolution", {}).get("mode") == "revise_existing":
                revision = _local_policy_revision_candidate(incident, idx)
                if revision is not None:
                    candidates.append(revision)
            candidates.append(_local_policy_candidate(incident, idx))
    for idx, candidate in enumerate(candidates, start=1):
        candidate["status"] = "candidate"
        candidate.setdefault("version", "0.1.0")
        candidate.setdefault("tags", ["generated"])
        if "id" not in candidate:
            candidate["id"] = f"cand-{idx:03d}-generated"
        path = output_dir / f"{candidate['id']}.json"
        path.write_text(json.dumps(candidate, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        print(f"wrote={path}")
    return 0


def cmd_policy_validate(settings: Settings) -> int:
    errors = PolicyLoader(settings.project_root / "policies").validate()
    if errors:
        for error in errors:
            print(error)
        return 1
    print("all policies valid")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="clawshield")
    sub = parser.add_subparsers(dest="command", required=True)
    install = sub.add_parser("install-openclaw")
    install.add_argument("--workspace")
    attach = sub.add_parser("attach-openclaw")
    attach.add_argument("--profile")
    sub.add_parser("incidents")
    sub.add_parser("policy-generate")
    sub.add_parser("policy-validate")
    return parser


def main() -> int:
    configure_logging()
    parser = build_parser()
    args = parser.parse_args()
    settings = Settings.load()
    if args.command == "install-openclaw":
        return cmd_install_openclaw(settings, args.workspace)
    if args.command == "attach-openclaw":
        return cmd_attach_openclaw(args.profile)
    commands = {"incidents": cmd_incidents, "policy-generate": cmd_policy_generate, "policy-validate": cmd_policy_validate}
    return commands[args.command](settings)


if __name__ == "__main__":
    raise SystemExit(main())
