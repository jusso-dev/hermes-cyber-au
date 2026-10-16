---
key: "routine-daily-briefing"
title: "Daily Australian cyber briefing: content, format and delivery"
labels: ["type:feature", "area:routines", "area:skills", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-routines"
---
## Outcome
Every working morning at 07:30 Sydney time the team gets one briefing that covers what changed in the last 24 hours (72 on Mondays), what affects them, and what to do today.

## Sections
1. Headline (one sentence).
2. Act today: ASD's ACSC alerts, new KEV entries matching the asset inventory, Tier 1 vulnerabilities from `vuln-prioritisation`.
3. This week: advisories, AusCERT bulletins, EPSS movers, ATT&CK techniques trending in sources.
4. Australian internet picture: Cloudflare Radar outages and attack summaries for AU (when the token is set), attributed.
5. Watchlist hits from the intel store.
6. Sources with retrieval times.

## Asset inventory input
`plugin-data/cyber-au/assets.yaml` (user-owned, never shipped):
```yaml
assets:
  - name: Citrix gateway
    vendor: citrix
    product: netscaler
    exposure: internet
    owner: infra-team
  - name: Staff laptops
    vendor: microsoft
    product: windows
    exposure: internal
```
Matching uses KEV `vendorProject`/`product` and NVD CPEs with a fuzzy match documented in `skills/vuln-prioritisation/references/matching.md`.

## Delivery
`deliver: origin` by default. Docs show Slack, Teams, email and Telegram targets using Hermes gateway delivery targets (see [`website/docs/user-guide/features/cron.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/features/cron.md), delivery targets section). No webhook URL is stored in this repo.

## Acceptance criteria
- [ ] Golden-file test: fixed fixtures produce a stable briefing structure (sections present, sources listed).
- [ ] Briefing under 600 words by default; `detail: full` option for analysts.
- [ ] Missing connectors are listed in one line at the end, not as errors.
- [ ] Monday window is 72 hours.

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
