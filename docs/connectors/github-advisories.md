# GitHub Advisory Database

Read-only global security advisories from the GitHub Advisory Database, through the official GitHub MCP server.

`ghsa` runs the GitHub MCP server release pinned in `mcp/vendor/github-mcp-server.lock` (v2.0.2) with `--toolsets security_advisories --read-only`. Only two of the toolset's four tools are kept. No repository, issue or pull request tool is enabled.

| Tool | What it returns |
|---|---|
| `get_global_security_advisory` | One advisory by GHSA id: summary, description, severity, CVE and CWE ids, affected packages with version ranges and patched versions, and withdrawal time |
| `list_global_security_advisories` | Advisories filtered by ecosystem, affected package, severity, CVE or GHSA id, CWE, type, or date |

Model-facing names are `mcp__ghsa__get_global_security_advisory` and `mcp__ghsa__list_global_security_advisories`. Filter names follow the pinned server (`cveId`, `ghsaId`, `isWithdrawn`).

`GITHUB_ADVISORY_TOKEN` is passed to the server as `GITHUB_PERSONAL_ACCESS_TOKEN`. The pinned server will not start without a token. Use a fine-grained token with no repository permissions. It reads public advisories only and lifts the limit from 60 to 5,000 requests an hour. Advisory summaries and descriptions are untrusted text.

Check the wrap with `cyberau-mcp health github-advisories` (offline: entry, lock and schema drift) or with `--live` (starts the pinned binary and makes one call per tool).

Advisory data comes from the GitHub Advisory Database under CC BY 4.0. This connector is not endorsed by GitHub.
