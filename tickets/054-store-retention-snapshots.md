---
key: "store-retention-snapshots"
title: "Store retention, backups and shareable snapshots"
labels: ["type:feature", "area:intel-store", "priority:p2"]
milestone: "v0.2"
parent: "epic-intel-store"
---
## Outcome
The store stays small and recoverable, and a TLP:CLEAR snapshot of public data can be shipped in releases so a fresh install is useful offline.

## In scope
- Retention policy in config: observations older than N days (default 365) are compacted into indicator counters; advisories kept forever (they are small and feeds are rolling).
- `cyberau-mcp store backup` using SQLite online backup API into `plugin-data/cyber-au/backups/` with 7 daily copies.
- `cyberau-mcp store snapshot --public` writes `intel/snapshots/public-<date>.sqlite.zst` containing only public-source TLP:CLEAR data, used by the nightly refresh and release packaging.
- `cyberau-mcp store vacuum` scheduled weekly by a no-agent cron job.

## Acceptance criteria
- [ ] Snapshot contains no analyst observations and no keyed-source raw data (test).
- [ ] Restore from backup tested in CI.
- [ ] Snapshot under 50 MB compressed.

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
