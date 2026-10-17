# Ranking rules

The configurable rules are `references/ranking.json`. `scripts/rank.py` reads that file. Replace the file to change a threshold. Do not put a patch duration in the rules. Durations come only from Essential Eight text supplied with the enrichment.

The first matching rule at the best tier wins. Tier 1 is ahead of tier 2. If two rules share a tier, the earlier rule in the file wins. The output names that rule id.

| Rule | Tier | When it fires |
|---|---|---|
| `kev-member` | 1 | The CVE is in the CISA KEV catalogue |
| `au-alert` | 1 | ASD's ACSC or AusCERT has published an item that names the CVE |
| `epss-high` | 1 | EPSS is 0.7 or higher |
| `epss-elevated` | 2 | EPSS is 0.1 or higher, and no tier 1 rule fired |
| `cvss-critical-exposed` | 2 | CVSS is 9 or higher and the asset class is internet-facing, and no tier 1 rule fired |
| `residual` | 3 | A real finding remains and no earlier rule fired |

EPSS of 0.1 on any asset class can fire `epss-elevated`. CVSS of 9 or higher fires `cvss-critical-exposed` only for asset class `internet-facing`. A high CVSS score on an internal-only asset stays on `residual` unless KEV, an Australian mention, or EPSS lifts it.

Asset class is one of:

| Class | Meaning |
|---|---|
| `internet-facing` | Internet-facing services |
| `workstations-office` | Workstations and office productivity suites |
| `other` | Everything else, including internal-only systems |

When one CVE is on several assets, the more exposed class wins: `internet-facing`, then `workstations-office`, then `other`. Do not infer the class from the CVE id. If the analyst did not supply a class, use `other`.

An id is `no-record` (unranked, not tier 3) when every source that was checked returned no record and the scanner row has no CVSS. An id is `not-enriched` when nothing was checked and the scanner row has no CVSS. Name sources that were not checked. A missing connector is not a negative result.

## Essential Eight

Ask `mcp__e8__e8_requirements` with `strategy` set to `patch_applications` and `maturity_level` set to the target level (1, 2, or 3). When the finding is an operating system, call it again with `strategy` set to `patch_operating_systems`. Pass the returned text through as the quote. The script may turn a duration that is written in that quote into a patch-by date in Australia/Sydney.

Use the duration in an "exploit" clause only when the CVE is in KEV or an Australian advisory names it. Otherwise use the duration that matches the asset class, then the first duration in the quote. A month in the quote is counted as 30 days, and the quote stays in the answer so the reader can see the source wording.

If the Essential Eight connector is unavailable, or the quote has no duration, or there is no release date to count from, leave patch-by as `not set`. Do not type a duration from memory.

The KEV due date is a CISA date. It is not the Essential Eight patch-by date. Show it in the KEV column and cite KEV.

## Batches

`batch_size` in the rules file is how many CVE ids go in one KEV or EPSS call. The script will not exceed 100, because `epss_scores` rejects longer lists. NVD `nvd_get_cve` takes one id per call. Unique the ids before batching. A 500-row export with 500 ids is 5 batches of 100.
