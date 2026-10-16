---
key: "install-update-path"
title: "Update and pinning path: hermes profile update, MCP venv refresh, migrations, rollback"
labels: ["type:task", "area:install", "area:release", "priority:p1"]
milestone: "v0.2"
parent: "epic-install"
---
## Outcome
Analysts update with one command and never lose their `.env`, memories, intel store or local config edits.

## Context
`hermes profile update <name>` replaces distribution-owned files, merges `cron/jobs.json` by id (new jobs arrive paused) and preserves `config.yaml` unless `--force-config` ([`website/docs/user-guide/profile-distributions.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/profile-distributions.md)). `hermes update` updates Hermes itself on the stable or main channel ([`website/docs/getting-started/updating.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/getting-started/updating.md)).

## In scope
- `hermes -p cyber-au cyber-au update`: runs `hermes profile update cyber-au`, then `bootstrap.sh` (venv sync, `mcp_servers` patch, store migrations), then doctor.
- Store migrations: numbered SQL files `plugins/cyber-au/store/migrations/NNNN_*.sql`, applied in a transaction, backed up first to `plugin-data/cyber-au/backups/`. Note `backups` is a user-owned name at the profile root, so it is never overwritten by an update.
- Rollback: `cyber-au update --to <tag>` reinstalls an earlier tag; store downgrades are refused with a message.
- Document Hermes version policy: `hermes_requires` floor moves only in the weekly bump PR.

## Acceptance criteria
- [ ] Update from v0.1.0 to a test v0.1.1 keeps a user `.env`, an edited `config.yaml` model setting and 1,000 store rows.
- [ ] A new cron job in v0.1.1 arrives paused; an enabled job stays enabled.
- [ ] A failing migration leaves the store untouched and prints the backup path.
- [ ] Docs page `docs/operations/updating.md`.

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
