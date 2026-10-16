---
key: "routine-watchlists"
title: "Watchlists: brand lookalikes, own IP ranges and domains, vendor products"
labels: ["type:feature", "area:routines", "area:intel-store", "priority:p2"]
milestone: "v0.2"
parent: "epic-routines"
---
## Outcome
Teams register what they care about once, and routines alert on new matches.

## In scope
- `plugin-data/cyber-au/watchlists.yaml` with `domains`, `brands`, `ip_ranges`, `asns`, `vendors`.
- Hourly no-agent job checks new store rows against watchlists and writes matches to `routine_state` for the briefing.
- Daily crt.sh check for lookalikes of watched domains (when the connector is enabled).
- Radar BGP hijack and leak events involving watched ASNs.

## Acceptance criteria
- [ ] Match logic unit-tested (CIDR containment, homoglyph lookalikes, vendor alias table).
- [ ] No outbound call contains watched values except to the connector designed for it (crt.sh for domains, Radar for ASNs), checked against the audit log.

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
