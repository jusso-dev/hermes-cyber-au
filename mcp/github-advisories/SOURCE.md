# github-advisories

- Upstream: https://github.com/github/github-mcp-server (pinned v2.0.2, MIT), serving https://api.github.com/advisories
- Auth: a fine-grained token with no repository permissions in `GITHUB_ADVISORY_TOKEN`. The pinned server starts without a token but answers every tool call with an OAuth sign-in link and tries to open a browser, so a headless profile gets no data. The token is needed to use the server, not only to raise limits
- Rate limit: 60 requests an hour unauthenticated, 5,000 with a token (GitHub REST)
- Terms: GitHub Advisory Database, CC BY 4.0. Attribute the GitHub Advisory Database
- Verified: 2026-10-17
- Egress hosts: api.github.com

## Wrap

`ghsa` in `mcp/servers.yaml` runs the vendor binary pinned by `mcp/vendor/github-mcp-server.lock`
with `stdio --toolsets security_advisories --read-only`. That toolset also holds
`list_repository_security_advisories` and `list_org_repository_security_advisories`, so
`tools.include` keeps only `get_global_security_advisory` and `list_global_security_advisories`,
and `--exclude-tools` stops the server registering the repository and organisation advisory tools,
so the process refuses them and the client filter is not the only barrier. No repository, issue or pull request tool is enabled.
`check_entry` rejects `--tools`, `--dynamic-toolsets`, a wider `--toolsets` and a changed exclude list.

The `api.github.com` entry in `mcp/egress-allowlist.yaml` binds the shared Python HTTP client only.
The pinned binary makes its own requests and is not under that policy, so it is not enforced for `ghsa`.

## Fixtures

- `tools_list.json`: `tools/list` recorded from the pinned darwin-arm64 binary on 2026-10-17
  with a placeholder token. Icons are removed. It lists four tools, which is why the filter exists.
- `advisories_page.json`, `advisory_withdrawn.json`: public advisories fetched unauthenticated
  from `/advisories` on 2026-10-17 and mapped to the tool output shape in `schema/*.response.json`
  (the pinned server needs a token, so its own output was not captured). Descriptions are cut to 600 characters.
- `schema/*.response.json` come from the `outputSchema` in the upstream tool snapshots at v2.0.2.

## Differences from the ticket

- Input names follow the pinned server (`cveId`, `ghsaId`, `isWithdrawn`), not `cve_id`. The server
  ignores unknown arguments, so a snake_case filter would be dropped and return an unfiltered list.
- The token is required in practice. The ticket assumed it was optional. The pinned v2.0.2 server
  does start without one (checked on darwin-arm64), but it then replies to each call with an OAuth
  authorisation link, so `required_env` lists `GITHUB_ADVISORY_TOKEN`.
- `args` adds `--exclude-tools list_repository_security_advisories,list_org_repository_security_advisories`
  beyond the ticket, so the process refuses them (`unknown tool`) if a client ignores `tools.include`.
- `list_global_security_advisories` returns `null` for an empty result, as its upstream `outputSchema` allows.
  The response schema accepts `null` and the wrap reports it as "no advisories matched".
- The 6 hour cache, the request budget and the doctor check for repository access belong to the
  `cyber-au` plugin (ticket 17) and the doctor (ticket 16). They are not in this package.
