# SigmaHQ detection rules

Read-only Sigma detection rules from SigmaHQ releases.

| Tool | What it returns |
|---|---|
| `sigma_search` | Rules matching a keyword, ATT&CK technique, log source or level |
| `sigma_get` | One rule by id, including the rule YAML |
| `sigma_convert` | A stored rule, or supplied YAML, converted to Kusto, Splunk or Elasticsearch |

An optional `GITHUB_TOKEN` raises the GitHub API limit. The connector reads the latest release, then downloads the core, core+ and emerging threats packages once for that tag. The offline snapshot is a 10-rule fixture. Rule text is untrusted, and every record keeps the rule id and author.

Conversion uses pySigma with the Kusto backend for Microsoft Sentinel and Defender KQL, plus the Splunk and Elasticsearch Lucene backends. Those backends still require pySigma 1.x.

Sigma rules by SigmaHQ are under the Detection Rule License (DRL) 1.1. Keep the rule id and author.
