# virustotal

- Upstream: https://github.com/VirusTotal/virustotal-mcp (official server, release v0.9.9, wrapped unchanged and run over stdio). Reports come from VTAI at https://ai.virustotal.com/api/v3.
- Auth: the user's own VTAI token in `VTAI_TOKEN`, passed through the server `env` block. Never logged, never shipped. Get one at https://ai.virustotal.com/connect/mcp.
- Rate limit: ceiling of 4 requests a minute and 500 a day, enforced by the `cyber-au` plugin budget keyed by server name, below the VirusTotal Public API limits. Premium quotas are the user's own. Reports are cached for 24 hours by indicator.
- Terms: The VirusTotal Public API must not be used in commercial products or services, or in business workflows that do not contribute new files. Premium API is paid. The server ships off. The user switches it on in their own `config.yaml` after reading https://docs.virustotal.com/reference/overview and the VTAI terms at https://ai.virustotal.com.
- Verified: 2026-10-17
- Egress hosts: ai.virustotal.com, www.virustotal.com

Pin: `mcp/vendor/virustotal-mcp.lock` (tag, commit, sdist and wheel SHA-256).

Tool names were read from the running v0.9.9 stdio server (`tools/list`, 11 tools) and recorded in `tests/fixtures/tools_list.json`. Four report tools are included and frozen in `expected_tools.txt`. The other seven stay excluded by `tools.include`: `submit_local_file`, `submit_file`, `submit_url`, `reanalyze_domain`, `reanalyze_ip` (upload and rescan, write to VirusTotal), and `get_analysis` and `get_submission` (read-only, but only useful after a submission).

Where the release differs from the ticket: v0.9.9 authenticates with `VTAI_TOKEN` (or `VTAI_TOKEN_FILE`), not a `VIRUSTOTAL_API_KEY` sent as `x-apikey`, and calls `ai.virustotal.com` rather than `www.virustotal.com`. `www.virustotal.com` stays on the allowlist because report permalinks point at it. Report fixtures are hand-built to the release's output shape (`reports.py`, `_result`) because no token was available at build time; `tools_list.json` is a real recording. The live probe needs a token.
