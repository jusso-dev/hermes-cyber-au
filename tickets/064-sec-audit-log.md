---
key: "sec-audit-log"
title: "Tamper-evident audit log of tool calls, approvals and exports"
labels: ["type:feature", "area:security", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-security"
---
## Outcome
Every tool call, approval, block, export and delivery is recorded in an append-only, hash-chained log that an assessor can verify.

## Context
`post_tool_call` gives `tool_name`, `args`, `result`, `task_id`, `duration_ms`; `pre_tool_call` can block; `on_session_start` and `on_session_end` mark sessions ([`website/docs/developer-guide/plugins/index.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/developer-guide/plugins/index.md), "Hook reference").

## Format
`plugin-data/cyber-au/audit/YYYY-MM-DD.jsonl`, one JSON object per line:
```json
{
  "type": "object",
  "required": [
    "ts",
    "seq",
    "event",
    "prev_hash",
    "hash"
  ],
  "properties": {
    "ts": {
      "type": "string",
      "format": "date-time"
    },
    "seq": {
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    },
    "task_id": {
      "type": "string"
    },
    "event": {
      "enum": [
        "session_start",
        "session_end",
        "tool_call",
        "tool_blocked",
        "approval",
        "export",
        "delivery",
        "config_change"
      ]
    },
    "tool": {
      "type": "string"
    },
    "args_redacted": {
      "type": "object"
    },
    "args_sha256": {
      "type": "string"
    },
    "result_sha256": {
      "type": "string"
    },
    "result_bytes": {
      "type": "integer"
    },
    "duration_ms": {
      "type": "integer"
    },
    "flags": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "prev_hash": {
      "type": "string"
    },
    "hash": {
      "type": "string",
      "description": "sha256(prev_hash + canonical JSON of this record without hash)"
    }
  }
}
```

Results are hashed, not stored, so TLP:AMBER data does not spread into logs.

## Interfaces
- `hermes -p cyber-au cyber-au audit verify [--from DATE]` checks the chain.
- `hermes -p cyber-au cyber-au audit export --since DATE --format jsonl|csv`.
- Optional forwarding to syslog or a Sentinel Logs Ingestion endpoint (v0.2, separate config, off by default).

## Acceptance criteria
- [ ] Deleting or editing any line makes `audit verify` fail with the line number.
- [ ] Hook overhead under 5 ms per call (benchmark).
- [ ] Log writing failure: write tools are blocked (fail closed), read tools continue with a warning.
- [ ] Daily file rotation; 90 day default retention, configurable.

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
