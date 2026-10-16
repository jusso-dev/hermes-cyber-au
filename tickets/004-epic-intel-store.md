---
key: "epic-intel-store"
title: "Epic: Local threat intel store with dedupe and STIX 2.1 export"
labels: ["type:epic", "area:intel-store", "priority:p0"]
milestone: "v0.1 MVP"
parent: "roadmap"
---
## Outcome
SQLite store shared by connectors, skills and routines, with canonical dedupe, STIX 2.1 export, retention and snapshots.

## Sub-issues
Linked as GitHub sub-issues. Checklist mirrors them by milestone.

### v0.1 MVP
- [ ] {{ref:store-schema-ingest}} Local threat intel store: SQLite schema, ingest API and canonical dedupe (p0)
- [ ] {{ref:store-stix-export}} STIX 2.1 export (and import) for the intel store (p1)

### v0.2
- [ ] {{ref:store-retention-snapshots}} Store retention, backups and shareable snapshots (p2)

### v1.0
- [ ] {{ref:store-duckdb-misp}} Optional DuckDB analytics export and MISP event export (p3)

## Definition of done
- [ ] Every sub-issue closed or moved to a later milestone with a reason.
- [ ] Docs updated for anything user-visible.
- [ ] Security review against `docs/security/threat-model.md`.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
