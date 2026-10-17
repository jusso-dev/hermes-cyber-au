# github-advisories

- Upstream: https://github.com/github/github-mcp-server (pinned v2.0.2, MIT), serving https://api.github.com/advisories
- Auth: a fine-grained token with no repository permissions in `GITHUB_ADVISORY_TOKEN`. The pinned server exits with "authentication required" when no token is set, so the token is needed to start it, not only to raise limits
- Rate limit: 60 requests an hour unauthenticated, 5,000 with a token (GitHub REST)
- Terms: GitHub Advisory Database, CC BY 4.0. Attribute the GitHub Advisory Database
- Verified: 2026-10-17
- Egress hosts: api.github.com

## Wrap

`ghsa` in `mcp/servers.yaml` runs the vendor binary pinned by `mcp/vendor/github-mcp-server.lock`
with `stdio --toolsets security_advisories --read-only`. That toolset also holds
`list_repository_security_advisories` and `list_org_repository_security_advisories`, so
`tools.include` keeps only `get_global_security_advisory` and `list_global_security_advisories`.
No repository, issue or pull request tool is enabled.

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
- The token is required to start the pinned server. The ticket assumed it was optional.
- The 6 hour cache, the request budget and the doctor check for repository access belong to the
  `cyber-au` plugin (ticket 17) and the doctor (ticket 16). They are not in this package.
