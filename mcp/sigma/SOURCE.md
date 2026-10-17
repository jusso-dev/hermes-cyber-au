# sigma

- Upstream: https://github.com/SigmaHQ/sigma
- Auth: none. Optional GITHUB_TOKEN for the GitHub API.
- Rate limit: at most 10 GitHub requests an hour. The release document is cached for 12 hours. Each rule package is downloaded once per release tag. Only requests that reach the network count against that limit. GITHUB_TOKEN is sent to api.github.com only, never to the download hosts.
- Terms: Sigma rules are published under the Detection Rule License (DRL) 1.1. Keep the rule id and author on every rule shown. https://github.com/SigmaHQ/Detection-Rule-License
- Verified: 2026-10-17
- Egress hosts: api.github.com, github.com, objects.githubusercontent.com, release-assets.githubusercontent.com

Release `r2026-07-01` (published 2026-07-09) exposes `sigma_core.zip`, `sigma_core+.zip` and `sigma_emerging_threats_addon.zip`. Those downloads redirect from github.com to release-assets.githubusercontent.com, so that host is allowlisted with the GitHub hosts.

Checked on PyPI the same day: pySigma 2.0.1 is current, but pySigma-backend-kusto 1.0.1, pySigma-backend-splunk 2.1.0 and pySigma-backend-elasticsearch 2.1.1 all require pySigma below 2. pySigma-backend-microsoft365defender is only a rename notice for the Kusto backend. This connector pins pySigma 1.5.1 and converts with KustoBackend (Microsoft Sentinel and Defender KQL), SplunkBackend and LuceneBackend.

The shipped `rules_subset.zip` is a 10-rule offline fixture, not the upstream package. Rule text is untrusted.

## Operator guide

Read-only Sigma detection rules from SigmaHQ releases.

| Tool | What it returns |
|---|---|
| `sigma_search` | Rules matching a keyword, ATT&CK technique, log source or level |
| `sigma_get` | One rule by id, including the rule YAML |
| `sigma_convert` | A stored rule, or supplied YAML, converted to Kusto, Splunk or Elasticsearch |

An optional `GITHUB_TOKEN` raises the GitHub API limit. The connector reads the latest release, then downloads the core, core+ and emerging threats packages once for that tag. The offline snapshot is a 10-rule fixture. Rule text is untrusted, and every record keeps the rule id and author.

Conversion uses pySigma with the Kusto backend for Microsoft Sentinel and Defender KQL, plus the Splunk and Elasticsearch Lucene backends. Those backends still require pySigma 1.x.

Sigma rules by SigmaHQ are under the Detection Rule License (DRL) 1.1. Keep the rule id and author.
