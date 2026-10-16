---
key: "epic-routines"
title: "Epic: Daily briefing and scheduled routines"
labels: ["type:epic", "area:routines", "priority:p1"]
milestone: "v0.1 MVP"
parent: "roadmap"
---
## Outcome
Paused-by-default cron jobs: hourly ingest, 07:30 Sydney briefing, KEV watch, weekly executive summary, watchlists.

## Sub-issues
Linked as GitHub sub-issues. Checklist mirrors them by milestone.

### v0.1 MVP
- [ ] {{ref:routine-cron-jobs}} Shipped cron jobs (cron/jobs.json): hourly ingest, 07:30 briefing, KEV watch, weekly summary (p0)
- [ ] {{ref:routine-daily-briefing}} Daily Australian cyber briefing: content, format and delivery (p0)

### v0.2
- [ ] {{ref:routine-watchlists}} Watchlists: brand lookalikes, own IP ranges and domains, vendor products (p2)
- [ ] {{ref:routine-delivery-docs}} Routine operations guide: resume, pause, deliver, quiet hours, failures (p2)

## Definition of done
- [ ] Every sub-issue closed or moved to a later milestone with a reason.
- [ ] Docs updated for anything user-visible.
- [ ] Security review against `docs/security/threat-model.md`.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
