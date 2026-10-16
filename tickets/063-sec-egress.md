---
key: "sec-egress"
title: "Egress allowlist: connectors, web tools and sandbox"
labels: ["type:feature", "area:security", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-security"
---
## Outcome
The agent and its connectors can only reach the hosts this distribution needs, and anything else is refused and logged.

## Layers
1. Connector egress policy in the shared library: per-connector host list in `mcp/egress-allowlist.yaml`, https only, DNS checked against private ranges, redirects re-checked.
2. Hermes web and browser tools: Hermes ships a blocklist (`security.website_blocklist`) and SSRF protection, not an allowlist ([`website/docs/user-guide/security.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/security.md)). Options to evaluate and document: disable the web toolset in this profile by default (`agent.disabled_toolsets` or `platform_toolsets`, verify key names in [`website/docs/user-guide/configuration.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/configuration.md)), or write a `pre_tool_call` hook that refuses URL tools for hosts outside the allowlist.
3. Terminal sandbox: recommend Docker backend with `terminal.docker_network: false`, or `hermes egress` (iron-proxy) with `proxy.extra_allowed_hosts` listing exactly the catalogue hosts ([`website/docs/user-guide/egress/iron-proxy.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/egress/iron-proxy.md)).
4. Container deployments: compose file with an egress proxy (Squid or iron-proxy) as the only route out.

## Interface: `mcp/egress-allowlist.yaml`
```yaml
version: 1
connectors:
  kev: [www.cisa.gov]
  epss: [api.first.org, www.first.org, epss.empiricalsecurity.com]
  nvd: [services.nvd.nist.gov]
  asd: [www.cyber.gov.au]
  # generated from the inventory, reviewed in PRs
global_deny_cidrs: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10, "::1/128", "fc00::/7", "fe80::/10"]
```

## Acceptance criteria
- [ ] A connector test proves calls outside its list are refused before a socket opens.
- [ ] `tools/ci/check_allowlist.py` fails CI if the allowlist and the inventory hosts drift.
- [ ] Hook (if chosen) tested with allowed, denied and redirecting URLs.
- [ ] Docs page `docs/security/egress.md` with the iron-proxy setup steps run once and recorded.

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
