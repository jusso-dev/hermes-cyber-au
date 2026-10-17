# VirusTotal via the official VirusTotal MCP server

Read-only file, URL, domain and IP reports from VirusTotal. This connector wraps the official [VirusTotal MCP server](https://github.com/VirusTotal/virustotal-mcp), pinned to release v0.9.9 in `mcp/vendor/virustotal-mcp.lock`. It is not a client written for this project.

## Off by default: licence terms

The VirusTotal Public API must not be used in commercial products or services, or in business workflows that do not contribute new files. The Premium API is paid. For that reason the `virustotal` server ships with `enabled: false`, even when a token is set. `doctor` lists it as "off by default: licence terms".

To turn it on, read the terms at <https://docs.virustotal.com/reference/overview>, then set this in your profile `config.yaml`:

```yaml
mcp_servers:
  virustotal:
    enabled: true
```

`config.yaml` is yours. Bootstrap and `hermes profile update` never switch the server on or off after you set it.

## Tools

| Tool | What it returns |
|---|---|
| `get_file_report` | Existing report for an MD5, SHA-1 or SHA-256 hash |
| `get_url_report` | Existing report for a URL |
| `get_domain_report` | Existing report for a domain |
| `get_ip_report` | Existing report for an IPv4 or IPv6 address |

Each answer carries detection counts, the analysis date and a permalink. A missing report means unknown, not safe. The tool names are frozen in `mcp/virustotal/expected_tools.txt` and checked against the recorded `tools/list` of the pinned release.

These upstream tools are excluded by `tools.include` and never registered: `submit_local_file`, `submit_file`, `submit_url`, `reanalyze_domain`, `reanalyze_ip` (upload and rescan), `get_analysis` and `get_submission` (only meaningful after a submission). The upstream server has no comment or vote tools; if a later release adds one, the include list keeps it out.

## Setup

1. Get your own VTAI Agent Token at <https://ai.virustotal.com/connect/mcp>. The pinned server asks for that token, not a key from the VirusTotal Public API page.
2. Put it in the profile `.env` as `VTAI_TOKEN`. It reaches the server through a `${VTAI_TOKEN}` placeholder and is never written to `config.yaml`.
3. Set `enabled: true` as above.

The pinned release authenticates with `VTAI_TOKEN` against `ai.virustotal.com`. The connector ticket named `VIRUSTOTAL_API_KEY` and `www.virustotal.com`; the release does not use them. `www.virustotal.com` stays on the egress allowlist for report permalinks.

## Limits and caching

Stay under 4 requests a minute and 500 a day. The `cyber-au` plugin budget refuses a fifth call inside a minute before the upstream 429. Reports are cached for 24 hours by indicator so repeat questions do not spend quota. Report text, including detection names, is untrusted.

Reports are provided by VirusTotal. This connector is not endorsed by VirusTotal.
