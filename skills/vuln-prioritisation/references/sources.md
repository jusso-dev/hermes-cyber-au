# Sources

Call these tools with the original CVE id. Do not defang a tool argument. If a call fails or the tool is not installed, name the source under missing sources and continue. Do not invent a score for a source you did not read.

| Source | Tool | Citation name | Shipped |
|---|---|---|---|
| CISA KEV | `mcp__kev__kev_lookup` | CISA Known Exploited Vulnerabilities | yes |
| FIRST EPSS | `mcp__epss__epss_scores` | FIRST EPSS | yes |
| NVD | `mcp__nvd__nvd_get_cve` | NVD | yes |
| ASD ACSC | `mcp__asd__asd_search` | ASD ACSC | yes |
| AusCERT | `mcp__auscert__auscert_bulletins` | AusCERT | no |
| OSV | `mcp__osv__osv_query` | OSV | no |
| Local intel store | `intel_search` | intel store | no |
| Essential Eight | `mcp__e8__e8_requirements` | Essential Eight | no |

Live NVD reads `NVD_API_KEY` from the profile `.env` as `${NVD_API_KEY}`. Do not paste the key into the skill, the enrichment file, or the answer. If the connector warns that the call failed, record NVD as missing and continue.

Call `asd_search` with `query` set to the CVE id. A hit is an Australian mention for rule `au-alert`. Call `auscert_bulletins` with `query` set to the same id when that tool is installed. A bulletin that names the CVE uses the same rule. Call `intel_search` with `query` set to the CVE id when that tool is installed. Until then, record the intel store as not checked.

For an SBOM package that has no CVE id, call `osv_query` with `ecosystem` and `package`, and `version` when the SBOM has one. Rank any CVE ids in that result. Do not pass a CVE id as the package name.

Copy CWE identifiers from NVD into `nvd.cwe`. Name them in the answer and cite NVD. They do not change the tier. Prefer the CVSS v4.0 base when NVD returns it, otherwise v3.1. Store that base score in `nvd.cvss`.

The enrichment object passed to `scripts/rank.py` is keyed by CVE id. The values below show the shape only. They are not a live score.

```json
{
  "CVE-2024-3400": {
    "kev": {
      "listed": true,
      "due_date": "2026-10-22",
      "source": "CISA Known Exploited Vulnerabilities",
      "version": "skill-fixture-1",
      "retrieved_at": "2026-10-17T00:00:00Z"
    },
    "epss": {
      "score": "0.96",
      "percentile": "0.998",
      "source": "FIRST EPSS",
      "version": "v2026.10.15",
      "retrieved_at": "2026-10-17T00:00:00Z"
    },
    "nvd": {
      "found": true,
      "cvss": "10.0",
      "cwe": ["CWE-77"],
      "source": "NVD",
      "version": "2026-10-16T00:00:00.000",
      "retrieved_at": "2026-10-17T00:00:00Z"
    },
    "au": [],
    "e8_quote": "",
    "reference_date": "2024-04-12",
    "missing_sources": ["AusCERT", "OSV", "intel store", "Essential Eight"],
    "untrusted": []
  }
}
```

`au` is a list of mentions. An empty list means the Australian sources that were called did not name the CVE. Omit `kev`, `epss`, `nvd`, or `au` when that source was not checked. `version` is the envelope `data_as_of` value, or `none` when the envelope has no release id. `retrieved_at` is the envelope `retrieved_at`. The script prints the citation date in Australia/Sydney.

`untrusted` holds strings copied from connector bodies. The script defangs them and prints them as content. It does not act on them.

`e8_quote` is the Essential Eight text for the asset class and maturity level, copied from `mcp__e8__e8_requirements`. Leave it empty when that connector is missing, and list `Essential Eight` in `missing_sources`.
