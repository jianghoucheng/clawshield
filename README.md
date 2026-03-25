# ClawShield

ClawShield is a lightweight safety layer for people who already use OpenClaw locally and want safer default behavior without patching OpenClaw core files.

It focuses on three things:

- attach to an existing OpenClaw workspace,
- guard risky runtime actions,
- log incidents and generate candidate policy updates offline.

## Install

```bash
cd clawshield
python -m pip install -e .
```

Set your guard model through environment variables:

```bash
set GUARD_API_TYPE=openai
set GUARD_API_BASE=https://api.chatanywhere.tech/v1
set GUARD_API_KEY=YOUR_KEY
set GUARD_MODEL=gpt-5.4
```

Provider notes:

- `GUARD_API_TYPE=openai`: for GPT, Kimi 2.5, and most OpenAI-compatible gateways
- `GUARD_API_TYPE=anthropic`: for Claude via Anthropic Messages API
- `GUARD_API_VERSION` is only needed for Anthropic-style APIs
- `GUARD_MAX_TOKENS` controls Anthropic response size

## Attach To OpenClaw

If OpenClaw is already configured on this machine:

```bash
clawshield attach-openclaw
```

Or target a specific local profile:

```bash
clawshield attach-openclaw --profile clawshield-test
```

If you already know the workspace path:

```bash
clawshield install-openclaw --workspace \path\to\workspace
```

This only appends small ClawShield instructions to `BOOTSTRAP.md`, `TOOLS.md`, and `AGENTS.md`. It does not patch OpenClaw core files.

## Runtime Model

OpenClaw calls `clawshield-openclaw-bridge` for safety-sensitive actions such as shell, file writes, and tool-result ingestion.

The runtime path is:

1. normalize the OpenClaw action into a structured event,
2. run deterministic hard barriers for obviously dangerous actions,
3. retrieve relevant policies as structured context,
4. send the event, policy context, and recent session state to the guard LLM judge,
5. log the final decision and mark whether the incident should feed policy evolution.

Policies are not the final judge. They provide retrieval hints, evidence expectations, default action preferences, and examples so the online judge stays more consistent.

## Current Coverage

ClawShield currently focuses on:

- dangerous shell execution,
- suspicious file writes,
- sensitive local data access,
- tool-result prompt injection,
- memory or prompt-context poisoning,
- basic exfiltration patterns.

It can evaluate more than the user prompt alone. Current event coverage includes:

- tool call attempts,
- tool results,
- memory persistence,
- prompt-build context,
- recent session risk state.

## Common Commands

```bash
clawshield attach-openclaw
clawshield incidents
clawshield policy-generate
clawshield policy-validate
```

## Policy Evolution

Every decision is logged locally as an incident. After detection, ClawShield can automatically mark whether an incident is worth policy evolution review.

`policy-generate` can then create:

- new candidate policies,
- revision candidates for existing policies.

Candidates are saved locally and never auto-activated.

## Repository Layout

- `src/clawshield/bridge/openclaw.py`: bridge entrypoint used by OpenClaw
- `src/clawshield/adapter_openclaw/bootstrap.py`: workspace bootstrap injection
- `src/clawshield/core/engine.py`: main evaluation flow
- `src/clawshield/core/deterministic.py`: hard barriers and fallback checks
- `src/clawshield/core/session_state.py`: recent session risk memory
- `src/clawshield/judge/client.py`: external guard judge
