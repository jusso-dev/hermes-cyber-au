# Examples (demo data)

Every file in this directory is **DEMO DATA**. It is synthetic and made up for trying hermes-cyber-au. No file describes a real alert, person, organisation or threat.

- IP addresses come from the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- Domains and email addresses use `example.com`, `example.net` and `example.org`.
- Hashes are SHA-256 digests of short placeholder phrases. No file here is malware.
- The CVE ids in `iocs.txt` and the products in `assets.csv` are real public CVEs and products, so a live CISA KEV or EPSS lookup gives a real, sourced answer about them. The hosts that run them are fictional.

| File | What it is | Try it with |
|---|---|---|
| `edr-alert.json` | An EDR beacon alert from a fictional laptop | `cyber-au demo triage`, or the `incident-triage` skill |
| `phishing-email.eml` | A payroll phishing email with failing SPF and DMARC | The `phishing-analysis` skill |
| `iocs.txt` | Mixed indicators and two CVE ids | The `ioc-enrichment` and `vuln-prioritisation` skills |
| `assets.csv` | A small fictional asset list | The `vuln-prioritisation`, `soci-reporting` and `pspf-risk-assessment` skills |
| `incident-timeline.md` | The same fictional incident as a timeline | The `ndb-breach-notification` and `soci-reporting` skills |

`cyber-au demo triage` only reads files marked as demo (`"demo": true`). It matches them against a synthetic demo intel set and labels every line of output as demo. It never reads or writes your real intel store. For a real alert, use the `incident-triage` skill in a chat, which uses live sources.

Example prompts that use these files are in [docs/getting-started/first-hour.md](../docs/getting-started/first-hour.md).
