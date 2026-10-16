---
key: "routine-delivery-docs"
title: "Routine operations guide: resume, pause, deliver, quiet hours, failures"
labels: ["type:docs", "area:routines", "area:docs", "priority:p2"]
milestone: "v0.2"
parent: "epic-routines"
---
## Outcome
An operator can turn routines on, route them to the right channel and handle failures without reading Hermes source.

## In scope
`docs/operations/routines.md` covering `hermes cron list|resume|pause|run`, `hermes pause` and `hermes resume` as the global stop ([`website/docs/user-guide/features/cron.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/features/cron.md)), delivery targets, `failure_deliver`, failure streak behaviour, and how to change times (they follow `timezone:`).

## Acceptance criteria
- [ ] Every command in the guide is run once against Hermes v0.22.2 and its output pasted.
- [ ] Australian English, no em dashes.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
