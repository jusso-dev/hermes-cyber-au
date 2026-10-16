---
key: "conn-scaffold-contract"
title: "Connector scaffold generator and contract test suite"
labels: ["type:task", "area:connectors", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-connectors"
---
## Outcome
`cyberau-mcp new <key>` creates a connector skeleton, and one shared contract test suite runs against every connector so they all behave the same way.

## In scope
- `tools/new_connector.py <key> --server <name> --hosts a,b` creates the layout from the shared library ticket and adds the server to `mcp/servers.yaml` and `mcp/egress-allowlist.yaml`.
- `tests/contract/test_contract.py`, parametrised over every connector found in `mcp/*/pyproject.toml`:
  - tool names match `^[a-z][a-z0-9_]{2,40}$` and `mcp__<server>__<tool>` is 64 characters or fewer;
  - every tool has an input JSON Schema file and it validates (Draft 2020-12);
  - every tool output validates against the envelope schema;
  - every tool is read-only annotated;
  - `SOURCE.md` has upstream URL, auth, rate limit, terms, verified date;
  - at least one cassette per tool, and cassettes contain no auth header values;
  - offline mode returns `cache: snapshot` or a structured `unavailable` warning, never a stack trace.
- `docs/connectors/<key>.md` generated from schemas and `SOURCE.md` (docs epic).

## Acceptance criteria
- [ ] Generator output passes the contract suite with a stub source before any real logic is written.
- [ ] Contract suite runs in CI under `--block-network` in under 60 seconds for 20 connectors.

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
