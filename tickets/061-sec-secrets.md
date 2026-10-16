---
key: "sec-secrets"
title: "Secrets handling: env placeholders only, redaction everywhere, secret scanning in CI"
labels: ["type:feature", "area:security", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-security"
---
## Outcome
No secret is ever committed, logged, cached, exported, put in a prompt or delivered.

## Context
`${VAR}` placeholders resolve from the profile `.env` or secret source; unset variables in remote `url`/`headers` fail closed ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md)). Distributions never ship `.env` or credential stores ([`website/docs/user-guide/profile-distributions.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/profile-distributions.md)). Portable plugin `mcp.json` values are visible data, not secret storage ([`website/docs/developer-guide/plugins/index.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/developer-guide/plugins/index.md)).

## In scope
- Only `${VAR}` in `mcp/servers.yaml` and rendered `config.yaml`. A CI check fails on anything that looks like a literal key.
- `cyberau_common.secrets.redact()` applied to logs, envelopes, exceptions and the audit log, covering `Auth-Key`, `apiKey`, `Authorization`, `X-OTX-API-KEY`, `key`, and any value of an env var named in `distribution.yaml`.
- pytest-recording `filter_headers` and a post-record scrubber; a CI test greps cassettes for header names with non-placeholder values.
- gitleaks in `ci.yml` (proposed YAML addition):
```yaml
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ github.token }}
```
- Doctor warns if `.env` is not mode 600.
- Docs: recommend a Hermes secret source plugin or OS keychain over plain `.env` where available ([`website/docs/developer-guide/secret-source-plugin.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/developer-guide/secret-source-plugin.md)).

## Acceptance criteria
- [ ] Seeded fake keys never appear in any test output, cassette, log or export (automated).
- [ ] gitleaks clean on full history.
- [ ] Rendered `config.yaml` contains no secret values, only placeholders.

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
