---
key: "sec-threat-model"
title: "Threat model for the agent itself"
labels: ["type:docs", "area:security", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-security"
---
## Outcome
A written threat model that every security ticket traces to.

## Assets
Provider keys and connector keys in the profile `.env`; the intel store (may hold TLP:AMBER analyst data); delivery channels (Slack, Teams, email); the analyst's trust in outputs; the host running Hermes.

## Main threats
| Id | Threat | Entry point | Control ticket |
|---|---|---|---|
| T1 | Indirect prompt injection in feed content (RSS, OTX pulses, advisory pages, email bodies under analysis) | MCP tool results | prompt injection defences |
| T2 | Secret leakage via tool args, logs, cassettes, exports or briefing delivery | any | secrets handling |
| T3 | Exfiltration to an attacker host via a URL tool or a connector | web tools, MCP | egress allowlist |
| T4 | Malicious or tampered update of this distribution or a dependency | `hermes profile update`, uv | supply chain |
| T5 | Unreviewed action (blocking, emailing, ticketing) triggered by the agent | write tools | approvals, `trust: untrusted` |
| T6 | Loss of accountability | none | audit log |
| T7 | Over-trust in wrong answers (hallucinated control ids, wrong deadlines) | skills | citations, "I don't know", evals |

## Existing Hermes controls we rely on
Dangerous command approval, `approvals.deny`, SSRF protection, `security.website_blocklist`, context file injection scanning, MCP env filtering and error redaction, `trust: untrusted`, iron-proxy egress for sandboxes ([`website/docs/user-guide/security.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/security.md), [`website/docs/user-guide/egress/iron-proxy.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/egress/iron-proxy.md)).

## Acceptance criteria
- [ ] `docs/security/threat-model.md` merged, reviewed against STRIDE and OWASP Top 10 for LLM Applications.
- [ ] Each threat links to at least one ticket and one test.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
