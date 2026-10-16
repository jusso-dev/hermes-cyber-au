---
key: "install-doctor"
title: "`hermes cyber-au doctor`: health check for profile, plugin, connectors, store and routines"
labels: ["type:feature", "area:install", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-install"
---
## Outcome
One command tells an analyst exactly what works, what is missing and how to fix it.

## Context
Plugins can register CLI commands and slash commands ([`website/docs/developer-guide/plugins/index.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/developer-guide/plugins/index.md), "Register CLI commands"). Hermes's own `hermes plugins doctor` checks plugin loading; ours checks the distribution.

## Interface
`hermes -p cyber-au cyber-au doctor [--offline] [--json] [--fix]` and `/cyber-au doctor` in chat.

Checks, each `ok | warn | fail` with a fix hint:
1. Hermes version satisfies `hermes_requires`.
2. Plugin `cyber-au` enabled and registered tools match `provides_tools`.
3. `mcp/.venv` present, lockfile hash matches.
4. Each `mcp_servers` entry: enabled state, env var presence (never print values), `cyberau-mcp health <server> --offline` passes, and with network the live probe passes.
5. Intel store: schema version, row counts, last ingest per source, WAL size.
6. Snapshots: ISM release, E8 data date, ATT&CK version, KEV `catalogVersion`, age warnings over 7 days.
7. Cron: shipped jobs present, paused or enabled, last run status.
8. Security: `security.allow_private_urls` is false, audit log writable, egress allowlist loaded, `.env` mode is 600.

JSON output schema:
```json
{
  "type": "object",
  "properties": {
    "version": {
      "type": "string"
    },
    "checks": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": {
            "type": "string"
          },
          "status": {
            "enum": [
              "ok",
              "warn",
              "fail"
            ]
          },
          "detail": {
            "type": "string"
          },
          "fix": {
            "type": "string"
          }
        },
        "required": [
          "id",
          "status"
        ]
      }
    }
  },
  "required": [
    "version",
    "checks"
  ]
}
```

## Acceptance criteria
- [ ] Exit code 0 when no `fail`, 1 otherwise.
- [ ] Never prints a secret value; tests assert the output contains no value from a seeded fake `.env`.
- [ ] `--fix` only performs safe local actions (create dirs, chmod 600 `.env`, re-run bootstrap) and lists each one.
- [ ] Unit tests for every check with fakes; one integration test in the Hermes container.

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
