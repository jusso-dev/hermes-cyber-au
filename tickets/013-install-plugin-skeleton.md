---
key: "install-plugin-skeleton"
title: "Native plugin skeleton `plugins/cyber-au` (plugin.yaml, register(ctx), tools, hooks)"
labels: ["type:feature", "area:install", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-install"
---
## Outcome
A native Hermes plugin that hosts the in-process pieces: intel store tools, audit hooks, untrusted-content middleware, evidence import and the `cyber-au` CLI and slash commands.

## Context
Native plugin = `plugin.yaml` plus `__init__.py` with `register(ctx)` ([`website/docs/developer-guide/plugins/index.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/developer-guide/plugins/index.md)). Hooks available: `pre_tool_call` (can block), `post_tool_call`, `pre_llm_call`, `on_session_start`, `on_session_end`. Middleware kinds: `tool_request`, `llm_request`, `tool_execution`, `llm_execution` (`hermes_cli/middleware.py`). Durable state belongs in `<hermes home>/plugin-data/<name>/`. General plugins are disabled until enabled.

## Files
```
plugins/cyber-au/
  plugin.yaml
  __init__.py          # register(ctx)
  tools/store.py       # intel_* tools (intel store epic)
  tools/evidence.py    # evidence_import
  hooks/audit.py       # post_tool_call, pre_tool_call (security epic)
  middleware/untrusted.py
  cli.py               # cyber-au doctor|bootstrap|store|export
  skills/              # none at first; skills live in profile skills/
tests/plugin/
```

## plugin.yaml
```yaml
name: cyber-au
version: 0.1.0
manifest_version: 2
api_version: 1
description: "In-process tools, audit logging and untrusted-content guards for the cyber-au distribution."
author: "Justin Middler"
license: Apache-2.0
homepage: https://github.com/jusso-dev/hermes-cyber-au
provides_tools: [intel_search, intel_get, intel_add_observation, intel_export_stix, evidence_import]
provides_hooks: [pre_tool_call, post_tool_call, on_session_start, on_session_end]
python_dependencies:
  - "stix2>=3,<4"
config_schema:
  audit_log_path: {type: str, default: "", description: "Override audit log path"}
  untrusted_banner: {type: bool, default: true, description: "Wrap feed content in an untrusted banner"}
```
Check every key against the manifest v2 table at implementation time and drop any the pinned Hermes does not know.

## Acceptance criteria
- [ ] `hermes plugins doctor plugins/cyber-au --ci` passes in CI against Hermes v0.22.2.
- [ ] `hermes plugins validate` shows declared tools equal registered tools.
- [ ] Hook callbacks accept `**kwargs` and never raise (failures are logged and swallowed except the audit `pre_tool_call` fail-closed path, see security epic).
- [ ] Plugin load time under 300 ms (plugins have a default 10 s load timeout; stay far below it).

## Constraints
- Public repository. Never commit secrets, tokens, real customer data or internal hostnames. Fixtures are scrubbed before commit.
- Every credential is read from the profile `.env` through a `${VAR}` placeholder. No literal keys in `config.yaml`, `mcp.json`, skills or tests.
- Read-only by default. Nothing in this ticket submits, blocks, deletes or posts anywhere.
- Content fetched from feeds is untrusted data. It is returned inside the result envelope and never treated as instructions.
- Australian English in prose and docs. No em dashes. No emojis.
- Pin dependencies with upper bounds (see `mcp/pyproject.toml`).

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
