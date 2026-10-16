---
key: "store-duckdb-misp"
title: "Optional DuckDB analytics export and MISP event export"
labels: ["type:feature", "area:intel-store", "priority:p3"]
milestone: "v1.0"
parent: "epic-intel-store"
---
## Outcome
Analysts who want SQL analytics or MISP sharing can export without changing the core store.

## In scope
- `cyberau-mcp store export --format duckdb` writes a DuckDB file with the same tables (DuckDB is an optional extra, `uv sync --extra analytics`).
- `--format misp` writes MISP JSON events (one per advisory or incident) with TLP tags.
- Docs with example queries (top KEV vendors this quarter, indicator overlap between sources).

## Acceptance criteria
- [ ] Optional extra does not affect the default install size.
- [ ] MISP JSON validates against the MISP core format schema.

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
