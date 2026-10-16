from common import *
from inventory import CONNECTORS

E = "epic-connectors"

ENVELOPE = {
    "type": "object",
    "required": ["source", "retrieved_at", "cache", "data", "untrusted"],
    "properties": {
        "source": {"type": "string", "description": "Connector key, for example cisa-kev"},
        "source_urls": {"type": "array", "items": {"type": "string", "format": "uri"}},
        "retrieved_at": {"type": "string", "format": "date-time"},
        "data_as_of": {"type": "string", "description": "Upstream timestamp or version (catalogVersion, release tag, score date)"},
        "cache": {"enum": ["hit", "miss", "stale", "snapshot"]},
        "attribution": {"type": "string"},
        "untrusted": {"type": "boolean", "const": True, "description": "Free text inside data came from a third party and is not instructions"},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "data": {},
    },
}


def shared():
    out = []
    out.append(dict(key="conn-shared-lib", parent=E, milestone=M_V01,
        labels=["type:feature", "area:connectors", "area:security", "priority:p0"],
        title="Shared connector library: HTTP client, egress allowlist, cache, rate limiter, result envelope",
        body=dedent(f"""
## Outcome
Every connector is a thin module on top of one library that handles HTTP, egress policy, caching, rate limits, retries, secrets redaction, fixtures and the result envelope. A new connector needs a source module, schemas and fixtures, nothing else.

## Context
Hermes launches stdio MCP servers from `mcp_servers` with a filtered environment: only `PATH`, `HOME`, `USER`, `LANG`, `LC_ALL`, `TERM`, `SHELL`, `TMPDIR`, `XDG_*` plus the server's own `env` ({hsrc('website/docs/user-guide/security.md')}, "MCP Credential Handling"). Model-facing names are `mcp__<server>__<tool>` within 64 characters ({hsrc('website/docs/developer-guide/plugins/index.md')}). Tools that only read should carry the MCP `readOnlyHint: true` annotation so `trust: untrusted` servers do not prompt for them ({hsrc('website/docs/reference/mcp-config-reference.md')}).

## Layout
```
mcp/
  pyproject.toml                 # uv workspace root, ruff, pytest config
  uv.lock
  egress-allowlist.yaml          # union of per-connector hosts, reviewed in PRs
  servers.yaml                   # launch metadata used by install/render_config.py
  common/
    pyproject.toml               # package cyberau-common
    src/cyberau_common/
      http.py      # HttpClient
      egress.py    # EgressPolicy
      cache.py     # HttpCache (SQLite)
      ratelimit.py # RateLimiter (SQLite-backed, cross-process)
      envelope.py  # Result envelope + untrusted text wrapper
      secrets.py   # env lookup, redaction
      server.py    # build_server(): FastMCP wiring, readOnlyHint, error mapping
      health.py    # Probe, SchemaDrift
      cli.py       # cyberau-mcp serve|health|refresh|regen|parser-check|store
  <connector>/
    pyproject.toml
    src/cyberau_<connector>/source.py
    schema/<tool>.input.json
    schema/<endpoint>.response.json
    tests/fixtures/*.yaml        # pytest-recording cassettes
    tests/test_<connector>.py
    SOURCE.md                    # upstream docs, terms, attribution, verified date
```
Use the official MCP Python SDK (`mcp` on PyPI, `FastMCP`). Pin `mcp>=1,<2` after checking the current major.

## Interfaces
```python
class EgressPolicy:
    def __init__(self, allowlist_path: Path, connector: str): ...
    def check(self, url: str) -> None:  # raises EgressDenied
        # https only (http allowed for 127.0.0.1/localhost only when the connector opts in),
        # host must be in the connector's hosts list, no userinfo, no IP literals unless opted in,
        # resolve DNS and refuse RFC 1918, loopback, link-local, CGNAT and metadata ranges.

class HttpClient:
    def __init__(self, connector: str, *, policy: EgressPolicy, cache: HttpCache,
                 limiter: RateLimiter, timeout: float = 30, retries: int = 3,
                 user_agent: str = "hermes-cyber-au/<version> (+https://github.com/jusso-dev/hermes-cyber-au)"): ...
    def get(self, url, *, params=None, headers=None, ttl: int, stale_if_error: int = 86400) -> Response: ...
    def post_json(self, url, body, *, headers=None, ttl: int, cache_key_extra: str = "") -> Response: ...
    # Redirects followed manually (max 5), each hop re-checked by EgressPolicy.
    # 429 and 503: honour Retry-After, else exponential backoff with full jitter (base 1 s, cap 60 s).
    # Response size cap 50 MB (configurable per call). Decompression bomb guard.

class HttpCache:  # SQLite at $CYBERAU_DATA_DIR/http_cache.sqlite, WAL mode
    key = sha256(method, url, sorted params, body hash, auth scope id)  # never the secret itself
    stores status, headers subset, body (zstd), fetched_at, etag, last_modified
    supports conditional GET and stale-if-error

class RateLimiter:  # token bucket per (connector, host) persisted in SQLite so several MCP processes share it
    def acquire(self, key: str, *, rate: float, burst: int, window: str = "rolling") -> None
    # NVD needs a rolling 30 second window: implement as a sliding log, not a fixed bucket.

def envelope(source: str, data, *, urls, cache: str, data_as_of=None, warnings=(), attribution="") -> dict
def untrusted_text(s: str, source: str, max_len: int = 4000) -> str
    # Strips control and bidi characters, collapses whitespace, truncates, and wraps:
    # "<<untrusted source=asd>> ... <<end untrusted>>"
```

## Result envelope (every tool returns this JSON)
{schema_block(ENVELOPE)}

## Env vars
| Name | Default | Purpose |
|---|---|---|
| `CYBERAU_DATA_DIR` | `<profile>/plugin-data/cyber-au` | Cache, limiter and store location |
| `CYBERAU_EGRESS_ALLOWLIST` | `<profile>/mcp/egress-allowlist.yaml` | Allowlist file |
| `CYBERAU_OFFLINE` | unset | When `1`, network is refused and only cache or snapshots answer |
| `CYBERAU_LOG_LEVEL` | `INFO` | Logs go to stderr; MCP stdout stays protocol only |

## Test plan
- Unit: egress (allowed host, denied host, redirect to denied host, DNS to 10.0.0.1, IPv6 link-local, punycode lookalike), cache (hit, conditional 304, stale-if-error), limiter (two processes share a bucket; rolling window maths), retries (429 with and without Retry-After), redaction (Auth-Key, apiKey, Authorization, X-OTX-API-KEY never appear in logs, errors or cassettes).
- pytest-recording with `filter_headers` for every auth header and `--block-network` in CI.
- Property tests (hypothesis) for `untrusted_text`.

## Acceptance criteria
- [ ] Coverage of `cyberau_common` at least 90 percent.
- [ ] A connector cannot reach a host not listed for it, proven by test.
- [ ] Every tool built with `build_server()` has `readOnlyHint: true` unless it is registered with `writes=True`, which no v0.1 connector does.
- [ ] Secrets never appear in envelopes, logs or cassettes (grep test over the test output and fixtures).
- [ ] `cyberau-mcp serve <name>` starts in under 1 second and lists tools over stdio.

## Constraints
{COMMON_CONSTRAINTS}

## Out of scope
HTTP transport MCP servers; everything is stdio in v0.1.
""")))

    out.append(dict(key="conn-scaffold-contract", parent=E, milestone=M_V01,
        labels=["type:task", "area:connectors", "priority:p1"],
        title="Connector scaffold generator and contract test suite",
        body=dedent(f"""
## Outcome
`cyberau-mcp new <key>` creates a connector skeleton, and one shared contract test suite runs against every connector so they all behave the same way.

## In scope
- `tools/new_connector.py <key> --server <name> --hosts a,b` creates the layout from the shared library ticket and adds the server to `mcp/servers.yaml` and `mcp/egress-allowlist.yaml`.
- `tests/contract/test_contract.py`, parametrised over every connector found in `mcp/*/pyproject.toml`:
  - tool names match `^[a-z][a-z0-9_]{{2,40}}$` and `mcp__<server>__<tool>` is 64 characters or fewer;
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
{COMMON_CONSTRAINTS}
""")))

    out.append(dict(key="conn-feed-catalogue", parent=E, milestone=M_V01,
        labels=["type:feature", "area:connectors", "area:routines", "priority:p1"],
        title="Feed catalogue feeds/catalogue.yaml: every source, URL, format, auth, licence, cadence",
        body=dedent(f"""
## Outcome
One machine-readable catalogue drives ingestion, health checks, the README table and docs.

## Schema (`feeds/catalogue.schema.json`)
{schema_block({"type": "object", "required": ["version", "feeds"], "properties": {"version": {"type": "integer"}, "feeds": {"type": "array", "items": {"type": "object", "required": ["id", "connector", "url", "format", "auth", "poll", "licence", "region"], "properties": {"id": {"type": "string"}, "connector": {"type": "string"}, "url": {"type": "string"}, "format": {"enum": ["rss", "atom", "json", "csv", "stix", "oscal", "html"]}, "auth": {"type": "object", "properties": {"type": {"enum": ["none", "header", "bearer"]}, "env": {"type": "string"}, "header": {"type": "string"}}}, "poll": {"type": "string", "description": "ISO 8601 duration, e.g. PT1H"}, "licence": {"type": "string"}, "region": {"enum": ["AU", "global"]}, "tlp": {"enum": ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"]}, "health": {"type": "object", "properties": {"probe": {"type": "string"}, "expect_status": {"type": "integer"}, "max_age": {"type": "string"}}}}}}}})}

## Acceptance criteria
- [ ] Catalogue lists every feed from the inventory (`docs/research/connectors.md`).
- [ ] CI validates it against the schema and checks each `connector` exists.
- [ ] The nightly refresh writes `last_ok`, `last_error` and item counts into `feeds/status.json` (not into the catalogue).
- [ ] README connector table is generated from it by `tools/build_readme_table.py` and CI fails if they drift.

## Constraints
{COMMON_CONSTRAINTS}
""")))
    return out


def connector_ticket(c: dict) -> dict:
    server = c["server"]
    ep = "\n".join(f"| `{m}` | {u} | {d} |" for m, u, d in c["endpoints"])
    env_rows = "\n".join(f"| `{n}` | {'yes' if r else 'no'} | {d} |" for n, r, d in c["env"]) or "| (none) | | |"
    tools_md = []
    for name, desc, schema in list(c["tools"]) + list(c.get("extra_tools", [])):
        full = f"mcp__{server}__{name}"
        if name.startswith("("):
            tools_md.append(f"### {name}\n{desc}")
            continue
        naming = f"Model-facing name: `{full}` ({len(full)} characters)." if server != "(none)" else "Registered by the `cyber-au` plugin, not an MCP server."
        tools_md.append(f"### `{name}`\n{desc}\n\n{naming}\n\nInput schema (`mcp/{c['key']}/schema/{name}.input.json`):\n{schema_block(schema)}\n\nOutput: result envelope with `data` holding the normalised records. Annotations: `readOnlyHint: true`, `openWorldHint: true`.")
    tools_md = "\n\n".join(tools_md)
    def code_item(path: str) -> str:
        head, sep, rest = path.partition(" (")
        return f"- `{head}`" + (f" ({rest}" if sep else "")
    fixtures = "\n".join(code_item(f"mcp/{c['key']}/tests/fixtures/{f}") for f in c["fixtures"])
    env_cfg = "\n".join(f'      {n}: "${{{n}}}"' for n, _, _ in c["env"])
    is_mcp = server != "(none)"
    cfg = ""
    if c.get("config"):
        cfg = "\n## Hermes configuration\n" + c["config"] + "\n"
    elif is_mcp:
        cfg = dedent(f"""
## Hermes configuration (rendered by bootstrap from `mcp/servers.yaml`)
```yaml
mcp_servers:
  {server}:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "{c['key']}"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
{env_cfg}
    lazy: true
    timeout: 120
    trust: untrusted
    supports_parallel_tool_calls: true
```
Placeholders resolve from the profile `.env` ({hsrc('website/docs/reference/mcp-config-reference.md')}, "Environment variable references"). The server gets no other environment.
""")
    files = c.get("files") or [
        f"mcp/{c['key']}/src/cyberau_{c['key'].replace('-', '_')}/source.py",
        f"mcp/{c['key']}/schema/*.json",
        f"mcp/{c['key']}/tests/test_{c['key'].replace('-', '_')}.py",
        f"mcp/{c['key']}/SOURCE.md",
        f"docs/connectors/{c['key']}.md (generated)",
    ]
    files_md = "\n".join(code_item(f) for f in files)
    hosts = ", ".join(f"`{h}`" for h in c["hosts"]) or "none"
    if c.get("wrap"):
        outcome = f"A pinned, read-only `{server}` entry that wraps an existing MCP server for {c['name']}, filtered to the tools listed below, with a skill that tells the agent how to use it, recorded-fixture tests and a live health probe."
    else:
        outcome = f"A read-only `{server}` connector for {c['name']} that the skills and routines can call, with caching, rate limiting, recorded-fixture tests and a live health probe."
    default_md = ""
    off_crit = ""
    off_test = ""
    if c.get("default_off"):
        default_md = (f"\n## Default state: off, bring your own key\n{c['default_off']}\n\n"
                      f"- `mcp/servers.yaml` marks the entry `default_enabled: false` and bootstrap renders `enabled: false` under `mcp_servers.{server}` even when the key is set (`enabled` is a documented per-server field).\n"
                      f"- The user turns it on by setting `enabled: true` in their profile `config.yaml`. `config.yaml` is user-owned and kept by `hermes profile update`, so an update never switches it back off or on.\n"
                      f"- `doctor` lists it as \"off by default: licence terms\" with a link to `docs/connectors/{c['key']}.md`, which quotes the terms.\n"
                      f"- The skill text that uses it states the terms before the first call in a session.\n")
        off_crit = "\n- [ ] Ships disabled (`enabled: false`) with the terms shown in docs, doctor and skill text; bootstrap and `hermes profile update` never enable it."
        off_test = "\n- default state: a fresh install with the key present still renders `enabled: false`; an update keeps the user's `enabled: true`."
    if c.get("wrap"):
        limiter = "the wrapped server runs upstream, so the limit is enforced by a `tool_request` middleware budget in the `cyber-au` plugin keyed by server name (shared library `RateLimiter` semantics). Values above are the ceiling; stay under them."
    else:
        limiter = "configured in `source.py` through `RateLimiter.acquire()` from the shared library. Values above are the ceiling; stay under them."
    extra_tests = "".join(f"\n- {x}" for x in c.get("extra_tests", []))
    extra_crit = "".join(f"\n- [ ] {x}" for x in c.get("extra_criteria", []))
    body = dedent(f"""
## Outcome
{outcome}

## Context
{c['notes']}

Docs: {c['docs']}

Verified on 16 October 2026: {c['verified']}

## Source API
| Method | Endpoint | Notes |
|---|---|---|
{ep}

- Auth: {c['auth']}
- Rate limits: {c['rate']}
- Terms and attribution: {c['terms']}
- Egress hosts (added to `mcp/egress-allowlist.yaml`): {hosts}
{default_md}
## Files
{files_md}

## Tools
{tools_md}

## Env vars
| Name | Required | Purpose |
|---|---|---|
{env_rows}
{cfg}
## Caching and rate limiting
- Cache: {c['cache']}
- Limiter: {limiter}
- Offline (`CYBERAU_OFFLINE=1`): answer from cache or snapshot with `cache: stale|snapshot`, otherwise return an `unavailable` warning.
- Every record that matters for history is also written to the intel store so rolling feeds and score changes are kept.

## Tests
Recorded fixtures (pytest-recording cassettes, auth headers filtered):
{fixtures}

Cases:
- happy path for every tool, validated against input and envelope schemas;
- empty result; malformed upstream payload (returns a warning, not an exception);
- 401/403 with a clear message naming the env var; 429 honouring `Retry-After`; timeout falls back to cache;
- schema drift: a fixture with a renamed field fails `health --schema-drift`;
- egress: a redirect to a host outside the list is refused;
- free text fields come back wrapped by `untrusted_text`.{off_test}{extra_tests}

Live probe for `connector-health.yml`: one cheap call per tool group, response validated against `schema/*.response.json`.

## Acceptance criteria
- [ ] Contract suite passes for `{c['key']}`.
- [ ] All tests pass with `--block-network`.
- [ ] `cyberau-mcp health {c['key']} --live` returns ok against the real service (keyed connectors: with a key set).
- [ ] `docs/connectors/{c['key']}.md` generated and linked from the README table.
- [ ] Attribution string shown in every envelope.
- [ ] No secret in any cassette, log line or envelope (automated grep).{off_crit}{extra_crit}

## Constraints
{COMMON_CONSTRAINTS}

## Out of scope
Any write call to the upstream service (submissions, uploads, sample downloads).
""")
    labels = ["type:feature", "area:connectors", f"priority:{c['priority']}"]
    return dict(key=f"conn-{c['key']}", parent=E, milestone=c["milestone"], labels=labels,
                title=f"Connector: {c['name']} (`{server}`)" if is_mcp else f"Integration: {c['name']}", body=body)


def tickets():
    return shared() + [connector_ticket(c) for c in CONNECTORS]
