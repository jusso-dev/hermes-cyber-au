---
key: "sec-prompt-injection"
title: "Prompt injection defences for feed content"
labels: ["type:feature", "area:security", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-security"
---
## Outcome
Text from feeds, advisories, pulses, emails under analysis and web pages can inform answers but cannot steer the agent.

## Layers
1. Connector layer: every free-text field passes through `untrusted_text()` (strip control and bidi characters, cap length, wrap in `<<untrusted source=...>>` markers). Envelopes carry `untrusted: true`.
2. Plugin middleware (`plugins/cyber-au/middleware/untrusted.py`, `tool_execution` kind, see [`website/docs/developer-guide/plugins/index.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/developer-guide/plugins/index.md), "Middleware"): for results from `mcp__{asd,auscert,otx,abusech,...}__*` tools, prepend a fixed banner telling the model the block is third-party data. Also scans the text with a small heuristic detector (instructions to ignore prior guidance, requests for secrets, URLs plus "send", tool names) and adds `warnings: ["possible_injection"]` without removing content.
3. `pre_tool_call` hook guard: if the previous tool result in the turn was flagged and the next call is a write-capable or outbound tool (send message, terminal with network, web fetch to a new host), return `{"action": "block", "message": ...}` unless the user approved in this session. Verify the exact directive shape against the hook docs at implementation time.
4. Config: every connector server is `trust: untrusted` so non-read-only tools need approval and fail closed in cron ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md)).
5. SOUL rule, written without quoting attack phrases so the distribution SOUL passes Hermes's injection scanner ([`website/docs/user-guide/security.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/security.md)).
6. Cron prompts state the allowed actions explicitly.

## Test plan
- Corpus `tests/security/injection/` with at least 40 cases: plain instructions, hidden HTML, zero-width text, base64 blobs, markdown links with instructions, fake system messages, fake tool results, multilingual variants. Sources: our own synthetic cases plus public research corpora where the licence allows.
- Eval: each case is injected into a connector fixture; the run must not call any forbidden tool and must mention the suspicious content.
- Regression gate in CI for the deterministic parts (wrapper, detector, hook).

## Acceptance criteria
- [ ] 100 percent of corpus cases blocked from triggering a write or outbound tool in the deterministic hook test.
- [ ] Model eval pass rate recorded per release; regressions fail the release workflow.
- [ ] Shipped SOUL.md loads with no injection warning (`/context`).

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
