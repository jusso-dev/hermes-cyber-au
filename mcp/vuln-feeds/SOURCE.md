# vuln-feeds

- Upstream: OSV bucket and API (https://osv-vulnerabilities.storage.googleapis.com, https://api.osv.dev/v1), GitHub Advisory Database REST (https://api.github.com/advisories), cvelistV5 (https://github.com/CVEProject/cvelistV5), Exploit-DB (https://gitlab.com/exploit-database/exploitdb) and the Metasploit module metadata (https://github.com/rapid7/metasploit-framework).
- Auth: none for the daily feeds. The optional Dependabot alert read uses the owner's own fine-grained token in `GITHUB_DEPENDABOT_TOKEN`, read from a key file, never logged and never cached.
- Rate limit: five requests a second across the connector. GitHub allows 60 unauthenticated requests an hour and the daily run makes two to six. The OSV index files and the cvelistV5 delta log are read with a byte range, newest entries first.
- Terms: OSV records keep each source's licence. The GitHub Advisory Database is CC BY 4.0. CVE records are copyright The MITRE Corporation under the CVE Terms of Use. The exploitdb repository is GPL-2.0 (its README), each exploit keeps its author's rights, and only the index rows are read, never the exploit files. Metasploit module metadata is Rapid7's, BSD 3-clause.
- Verified: 2026-10-23
- Egress hosts: osv-vulnerabilities.storage.googleapis.com, api.osv.dev, api.github.com, raw.githubusercontent.com, gitlab.com

## Operator guide

Read-only daily feeds that `cyberau-mcp refresh` loads into the intel store and the morning email reads back.

| Tool | What it returns |
|---|---|
| `vuln_feed_list` | The feeds this connector reads and the intel store source id of each |
| `vuln_feed_recent` | New items from one feed over the last one to 14 days |

| Feed | Store source | What it adds |
|---|---|---|
| `osv-malicious` | `osv-mal` | MAL- malicious package records for npm, PyPI, crates.io and RubyGems |
| `ghsa` | `ghsa` | Reviewed GitHub advisories and malware advisories published in the window |
| `cvelist` | `cvelist` | CVE records newly published to cvelistV5 (up to 150 a run) |
| `exploit-db` | `exploit-db` | Exploits added to Exploit-DB, with the CVEs they name |
| `metasploit` | `metasploit` | Metasploit exploit modules, and modules naming a CVE, changed in the window |

`cyberau-mcp refresh --sources osv,ghsa,cvelist,exploitdb,metasploit --store` runs them. The `cyberau-ingest-vuln` job runs the five feeds, NVD, cve.now and pwn.watch once a day.

### OSV-Scanner style dependency scan

`refresh --sources osv` also reads the `purl` of every asset in `assets.yaml` and asks api.osv.dev which known vulnerabilities affect each package version, as OSV-Scanner does. Only the ecosystem, package name and version of each purl leave the machine. Findings are stored under the source `osv-scan` and listed in the briefing as "Your dependencies".

### Dependabot alerts

`refresh --sources dependabot` reads open critical and high Dependabot alerts for the repositories named in `dependabot.yaml` in the profile data directory. It is not part of the keyless daily run, because it needs a token.

```yaml
repos:
  - owner/repo
token_file: key.txt   # a path, chmod 600. Fine-grained token with Dependabot alerts read
```

### Safety

Feed text is untrusted. Titles and summaries are cut to one line, and the store wraps summaries. The connector never downloads an exploit or a module, only the index rows. A stale cache answer counts as a failed refresh.
