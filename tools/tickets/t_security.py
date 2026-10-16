from common import *

E = "epic-security"


def tickets():
    out = []
    out.append(dict(key="sec-threat-model", parent=E, milestone=M_V01,
        labels=["type:docs", "area:security", "priority:p0"],
        title="Threat model for the agent itself",
        body=dedent(f"""
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
Dangerous command approval, `approvals.deny`, SSRF protection, `security.website_blocklist`, context file injection scanning, MCP env filtering and error redaction, `trust: untrusted`, iron-proxy egress for sandboxes ({hsrc('website/docs/user-guide/security.md')}, {hsrc('website/docs/user-guide/egress/iron-proxy.md')}).

## Acceptance criteria
- [ ] `docs/security/threat-model.md` merged, reviewed against STRIDE and OWASP Top 10 for LLM Applications.
- [ ] Each threat links to at least one ticket and one test.
""")))

    out.append(dict(key="sec-secrets", parent=E, milestone=M_V01,
        labels=["type:feature", "area:security", "priority:p0"],
        title="Secrets handling: env placeholders only, redaction everywhere, secret scanning in CI",
        body=dedent(f"""
## Outcome
No secret is ever committed, logged, cached, exported, put in a prompt or delivered.

## Context
`${{VAR}}` placeholders resolve from the profile `.env` or secret source; unset variables in remote `url`/`headers` fail closed ({hsrc('website/docs/reference/mcp-config-reference.md')}). Distributions never ship `.env` or credential stores ({hsrc('website/docs/user-guide/profile-distributions.md')}). Portable plugin `mcp.json` values are visible data, not secret storage ({hsrc('website/docs/developer-guide/plugins/index.md')}).

## In scope
- Only `${{VAR}}` in `mcp/servers.yaml` and rendered `config.yaml`. A CI check fails on anything that looks like a literal key.
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
          GITHUB_TOKEN: ${{{{ github.token }}}}
```
- Doctor warns if `.env` is not mode 600.
- Docs: recommend a Hermes secret source plugin or OS keychain over plain `.env` where available ({hsrc('website/docs/developer-guide/secret-source-plugin.md')}).

## Acceptance criteria
- [ ] Seeded fake keys never appear in any test output, cassette, log or export (automated).
- [ ] gitleaks clean on full history.
- [ ] Rendered `config.yaml` contains no secret values, only placeholders.

## Constraints
{COMMON_CONSTRAINTS}
""")))

    out.append(dict(key="sec-prompt-injection", parent=E, milestone=M_V01,
        labels=["type:feature", "area:security", "priority:p0"],
        title="Prompt injection defences for feed content",
        body=dedent(f"""
## Outcome
Text from feeds, advisories, pulses, emails under analysis and web pages can inform answers but cannot steer the agent.

## Layers
1. Connector layer: every free-text field passes through `untrusted_text()` (strip control and bidi characters, cap length, wrap in `<<untrusted source=...>>` markers). Envelopes carry `untrusted: true`.
2. Plugin middleware (`plugins/cyber-au/middleware/untrusted.py`, `tool_execution` kind, see {hsrc('website/docs/developer-guide/plugins/index.md')}, "Middleware"): for results from `mcp__{{asd,auscert,otx,abusech,...}}__*` tools, prepend a fixed banner telling the model the block is third-party data. Also scans the text with a small heuristic detector (instructions to ignore prior guidance, requests for secrets, URLs plus "send", tool names) and adds `warnings: ["possible_injection"]` without removing content.
3. `pre_tool_call` hook guard: if the previous tool result in the turn was flagged and the next call is a write-capable or outbound tool (send message, terminal with network, web fetch to a new host), return `{{"action": "block", "message": ...}}` unless the user approved in this session. Verify the exact directive shape against the hook docs at implementation time.
4. Config: every connector server is `trust: untrusted` so non-read-only tools need approval and fail closed in cron ({hsrc('website/docs/reference/mcp-config-reference.md')}).
5. SOUL rule, written without quoting attack phrases so the distribution SOUL passes Hermes's injection scanner ({hsrc('website/docs/user-guide/security.md')}).
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
{COMMON_CONSTRAINTS}
""")))

    out.append(dict(key="sec-egress", parent=E, milestone=M_V01,
        labels=["type:feature", "area:security", "priority:p0"],
        title="Egress allowlist: connectors, web tools and sandbox",
        body=dedent(f"""
## Outcome
The agent and its connectors can only reach the hosts this distribution needs, and anything else is refused and logged.

## Layers
1. Connector egress policy in the shared library: per-connector host list in `mcp/egress-allowlist.yaml`, https only, DNS checked against private ranges, redirects re-checked.
2. Hermes web and browser tools: Hermes ships a blocklist (`security.website_blocklist`) and SSRF protection, not an allowlist ({hsrc('website/docs/user-guide/security.md')}). Options to evaluate and document: disable the web toolset in this profile by default (`agent.disabled_toolsets` or `platform_toolsets`, verify key names in {hsrc('website/docs/user-guide/configuration.md')}), or write a `pre_tool_call` hook that refuses URL tools for hosts outside the allowlist.
3. Terminal sandbox: recommend Docker backend with `terminal.docker_network: false`, or `hermes egress` (iron-proxy) with `proxy.extra_allowed_hosts` listing exactly the catalogue hosts ({hsrc('website/docs/user-guide/egress/iron-proxy.md')}).
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
{COMMON_CONSTRAINTS}
""")))

    out.append(dict(key="sec-audit-log", parent=E, milestone=M_V01,
        labels=["type:feature", "area:security", "priority:p0"],
        title="Tamper-evident audit log of tool calls, approvals and exports",
        body=dedent(f"""
## Outcome
Every tool call, approval, block, export and delivery is recorded in an append-only, hash-chained log that an assessor can verify.

## Context
`post_tool_call` gives `tool_name`, `args`, `result`, `task_id`, `duration_ms`; `pre_tool_call` can block; `on_session_start` and `on_session_end` mark sessions ({hsrc('website/docs/developer-guide/plugins/index.md')}, "Hook reference").

## Format
`plugin-data/cyber-au/audit/YYYY-MM-DD.jsonl`, one JSON object per line:
{schema_block({"type": "object", "required": ["ts", "seq", "event", "prev_hash", "hash"], "properties": {"ts": {"type": "string", "format": "date-time"}, "seq": {"type": "integer"}, "session_id": {"type": "string"}, "task_id": {"type": "string"}, "event": {"enum": ["session_start", "session_end", "tool_call", "tool_blocked", "approval", "export", "delivery", "config_change"]}, "tool": {"type": "string"}, "args_redacted": {"type": "object"}, "args_sha256": {"type": "string"}, "result_sha256": {"type": "string"}, "result_bytes": {"type": "integer"}, "duration_ms": {"type": "integer"}, "flags": {"type": "array", "items": {"type": "string"}}, "prev_hash": {"type": "string"}, "hash": {"type": "string", "description": "sha256(prev_hash + canonical JSON of this record without hash)"}}})}

Results are hashed, not stored, so TLP:AMBER data does not spread into logs.

## Interfaces
- `hermes -p {PROFILE} cyber-au audit verify [--from DATE]` checks the chain.
- `hermes -p {PROFILE} cyber-au audit export --since DATE --format jsonl|csv`.
- Optional forwarding to syslog or a Sentinel Logs Ingestion endpoint (v0.2, separate config, off by default).

## Acceptance criteria
- [ ] Deleting or editing any line makes `audit verify` fail with the line number.
- [ ] Hook overhead under 5 ms per call (benchmark).
- [ ] Log writing failure: write tools are blocked (fail closed), read tools continue with a warning.
- [ ] Daily file rotation; 90 day default retention, configurable.

## Constraints
{COMMON_CONSTRAINTS}
""")))

    out.append(dict(key="sec-supply-chain", parent=E, milestone=M_V02,
        labels=["type:task", "area:security", "area:release", "priority:p1"],
        title="Supply chain: pinned deps, SBOM, provenance, signed releases, update review",
        body=dedent(f"""
## Outcome
Installers can check what they are running and where it came from.

## Context
Hermes distributions are unsigned and installed from git ({hsrc('website/docs/user-guide/profile-distributions.md')}, "Security and trust"). Cron jobs arrive paused, but SOUL and skills are live on first chat.

## In scope
- `uv.lock` committed, hashes enforced (`--frozen`).
- CycloneDX SBOM per release (`cyclonedx-py` against the lock), attached to the release.
- GitHub artifact attestations (`actions/attest-build-provenance`) for the tarball and image.
- Release notes list every changed skill, SOUL line and cron job, so updaters can review before `hermes profile update`.
- `install.sh --ref <tag>` recommended in docs over `main`.
- Dependabot config `.github/dependabot.yml` for pip (uv) and GitHub Actions, weekly. The file already exists from the earlier skill pack (GitHub Actions only, weekly); extend it rather than adding a second one:
```yaml
version: 2
updates:
  - package-ecosystem: "uv"
    directory: "/mcp"
    schedule: {{interval: "weekly", day: "monday", time: "09:00", timezone: "Australia/Sydney"}}
    open-pull-requests-limit: 5
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule: {{interval: "weekly", day: "monday", time: "09:00", timezone: "Australia/Sydney"}}
```
(Check that Dependabot supports the `uv` ecosystem name at implementation time; fall back to `pip`.)

## Acceptance criteria
- [ ] `gh attestation verify` succeeds for a release asset.
- [ ] SBOM lists every runtime dependency in the lock.
- [ ] Release notes generator test covers SOUL, skills and cron diffs.

## Constraints
{COMMON_CONSTRAINTS}
""")))
    return out
