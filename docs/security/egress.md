# Egress

Connectors in this distribution may open connections only to hosts listed for them in [`mcp/egress-allowlist.yaml`](https://github.com/jusso-dev/hermes-cyber-au/blob/main/mcp/egress-allowlist.yaml). Anything else is refused and written to the `cyberau.egress` log. The refusal names the connector and the reason. It does not include the query string.

Hermes facts below were checked against NousResearch/hermes-agent at `43faacf` (v0.22.2). The iron-proxy commands were then run once on this machine. That run is recorded at the end of this page.

## Connector policy

`EgressPolicy` in the shared library loads the allowlist for one connector.

- The scheme must be `https`. `http` is refused.
- The host must be in that connector's list. Names are compared after IDNA normalisation. A lookalike character that encodes to a different name is a different host.
- Userinfo in the URL is refused.
- IP literals are refused unless that connector sets `allow_ip_literals`. The shipped file does not set it.
- A connector may set `allow_http_loopback` to permit `http` to `localhost` or a loopback address. The shipped file does not set it. The opt-in covers only `http` to a loopback name or address. An `https` request, or a listed public name that resolves to loopback, is still refused.
- Hosts that are not in the list are refused before DNS resolution and before a socket to that host is opened.

Redirects are not followed by the HTTP library. The client follows at most five hops itself. Each hop is checked with the same policy before the next request is sent. A redirect to a host outside the list, or to a private or scoped address, is refused. Secret headers are dropped before the next hop.

## Private and scoped addresses

When a direct connection is opened, every resolved address is refused when it is private, loopback, link-local, site-local, unique-local, multicast, reserved, or unspecified, or when it is an IPv4-mapped IPv6 address. Shared address space `100.64.0.0/10` is refused as well. The code applies that floor even when `global_deny_cidrs` in the allowlist file is shorter. CI fails if the file drops a floor network.

An address on the connector's host list is still refused when it is private or scoped. Listing a name does not waive the address check.

## One lookup per connection

The per-hop check before each request uses only the URL and the host list. It does no DNS lookup. An IP literal is checked against the address rules at that point.

For a direct connection, the HTTP client's transport resolves the name once, refuses the whole answer if any address is private or scoped, and then connects to one of those addresses by number. TLS still uses the name from the URL for SNI and certificate checks. Because the check and the connection share one lookup, a name that answers with a public address first and a private address later cannot reach the private address.

A name that does not resolve is refused, and the request fails closed. The client then serves a stale cache entry if one is within its stale window, or reports an upstream error. In offline mode a cache answer sends nothing, so it needs no lookup.

## Proxies, fake-IP DNS and TLS inspection

- `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and `NO_PROXY` are read the same way httpx reads them. A proxied request is checked against the host list only. It is not resolved locally, because the proxy resolves the name. The proxy is trusted to enforce its own rules. Hosts matched by `NO_PROXY` connect directly and get the address checks above.
- Some TUN proxies and secure web gateways answer every public name from `198.18.0.0/15` (fake-IP DNS). That range is blocked by default. Set `CYBERAU_EGRESS_FAKE_IP=1` to accept answers in that range for listed names. It does not cover IP literals or any other range. Prefer an explicit `HTTPS_PROXY` where one is available.
- For a gateway that inspects TLS, point `SSL_CERT_FILE` (or `SSL_CERT_DIR`) at a bundle that includes its CA. Do not turn certificate checks off.

## Web and browser tools

Hermes does not allowlist web and browser tools. It ships `security.website_blocklist` (a deny list) and SSRF protection that refuses private addresses and checks redirects again. Key names checked in `website/docs/user-guide/configuration.md` and `website/docs/user-guide/security.md` at the commit above:

- `agent.disabled_toolsets` removes a toolset everywhere, including after `platform_toolsets`. The value `web` removes `web_search` and `web_extract`.
- `security.allow_private_urls` defaults to false. This profile sets it to false.
- `security.website_blocklist` blocks named domains. It does not limit tools to the catalogue.

This profile turns the web toolset off:

```yaml
agent:
  disabled_toolsets:
    - web
```

A `pre_tool_call` hook that would filter URL tools against the allowlist was not added. Hermes already refuses private addresses for those tools, and the hook would be a second list to keep aligned with the inventory. With the web toolset off, catalogue hosts are reached through connectors.

## Terminal sandbox

Two options, checked in the Hermes configuration and iron-proxy guides at the same commit:

- Docker backend with no network: `terminal.backend: docker` and `terminal.docker_network: false` (`--network=none` for the terminal, code execution, and file-tool container).
- `hermes egress` (iron-proxy), with `proxy.extra_allowed_hosts` set to the catalogue hosts. That setting adds hosts. It does not replace the inference hosts Hermes allows by default. Use `terminal.docker_network: false` when the sandbox should have no network at all.

Catalogue hosts, one per line, excluding loopback names and the in-library stub:

```bash
uv run --project mcp python tools/ci/check_allowlist.py --print-hosts
```

## Iron-proxy setup

Run these from a Hermes install. This distribution asks for Hermes `>=0.22.2`.

1. Leave `security.allow_private_urls` false.
2. Choose one sandbox posture. Either set `terminal.docker_network: false`, or follow the steps below and add the catalogue hosts under `proxy.extra_allowed_hosts`.
3. Confirm the current state: `hermes egress status`.
4. Write the config without starting the daemon: `hermes egress setup --no-restart`. Add `--tunnel-port <port>` when 9090 is already in use. Do not pass `--rotate-tokens` unless you intend to replace tokens that running sandboxes already hold.
5. Read `hermes egress status` again. Check that Enabled is yes, the binary version is the one you expect, and Credential src matches how you store provider credentials (`env` unless you use Bitwarden).
6. Start the daemon only when you want it listening: `hermes egress start`.
7. Stop or turn the integration off with `hermes egress stop` or `hermes egress disable`.

`hermes egress setup` downloads the pinned iron-proxy binary into the active `HERMES_HOME`, creates a CA, and writes `proxy/proxy.yaml`. It reads provider credential names in order to mint proxy tokens. Run it only in a home whose credentials you mean to use.

## Recorded run

Recorded on 17 October 2026.

The Hermes on this machine was Agent v0.20.5. That build already provides `hermes egress`. The documentation keys above were taken from v0.22.2 at `43faacf`, not from this older binary.

The setup was run in a temporary `HERMES_HOME`. The operator's Hermes profile was not changed, and the daemon was not started.

Command:

```bash
hermes egress setup --no-restart --tunnel-port 19090
```

Result: exit 0. iron-proxy 0.39.0 was installed into that temporary home. A CA and `proxy/proxy.yaml` were written. `proxy.extra_allowed_hosts` in the temporary config listed `www.cyber.gov.au`, `www.cisa.gov`, `services.nvd.nist.gov`, and `api.first.org`. Those four names were present in the generated proxy config, together with a default inference host (`openrouter.ai`).

`hermes egress status` after setup:

| Field | Value |
|---|---|
| Enabled | yes |
| Binary version | 0.39.0 |
| Tunnel port | 19090 |
| Process | stopped |
| Listening | no |
| Credential src | env |
| Docker enforce | yes |

## Containers

For a container deployment, give the agent no direct route to the network. The only egress path should be a proxy (iron-proxy, or another forward proxy with the same host list). Do not publish a second interface that can reach the internet or private ranges.

## CI

`tools/ci/check_allowlist.py` compares `mcp/egress-allowlist.yaml` with the connector inventory (`tools/tickets/inventory.py`, `inventory_added.py`, and `inventory_premium.py`). It fails when a host is added or removed on only one side. Connectors whose inventory host is supplied by the operator must have an empty host list until a real host is reviewed in. The in-library `stub` connector is the only extra key, and its only host is `example.com`.

The same script fails when `global_deny_cidrs` no longer contains every floor network. Adding a network is allowed. Removing one is not.
