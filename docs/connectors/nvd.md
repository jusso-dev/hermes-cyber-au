# NIST National Vulnerability Database

Read-only CVE records from the NVD CVE API 2.0.

| Tool | What it returns |
|---|---|
| `nvd_get_cve` | One CVE: English description, CVSS, CWEs, and reference URLs |
| `nvd_search` | CVEs matching a keyword, CPE, date window, KEV flag, or CVSS severity |
| `nvd_cve_history` | Change events for one CVE |

An optional `NVD_API_KEY` raises the limit from 5 to 50 requests per 30 seconds. Descriptions are untrusted text.

This product uses data from the NVD API but is not endorsed or certified by the NVD.
