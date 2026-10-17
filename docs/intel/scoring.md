# Indicator scoring

The intel store keeps every observation. The indicator row stores one verdict and one confidence. Both are recomputed from the observations whenever an observation is ingested.

Canonical forms used for dedupe live in `plugins/cyber-au/store/canonical.py`. The dedupe key is `(type, value_norm)`.

## Verdict and confidence

Observations use four verdicts: `malicious`, `suspicious`, `benign` and `unknown`. Confidence is an integer from 0 to 100. A missing confidence counts as 50. A missing verdict counts as `unknown`.

1. Add up confidence for each verdict.
2. The verdict with the largest sum wins.
3. If two verdicts share that sum, the tie breaks in this order: `malicious`, `suspicious`, `benign`, `unknown`.
4. Let `support` be the winning sum, `supporters` the number of observations that cast the winning verdict, and `total` the sum of every observation's confidence.
5. The stored confidence is `support * support / (supporters * total)`, rounded half up (0.5 rounds away from zero, not to even), then capped at 100.
6. If there are no observations, or `total` is 0, the verdict is `unknown` and the confidence is 0.

A single observation keeps its own confidence, because `support`, `supporters` and `total` describe that one vote. A second observation of equal weight cuts the stored confidence in half and the tie break keeps the more severe verdict. A much stronger opposing report still wins on the sums.

`first_seen` is the earliest `observed_at`. `last_seen` is the latest. Timestamps are stored in UTC with a `Z` suffix. The original indicator spelling is kept for audit. Dedupe uses the canonical value.

## TLP

TLP 2.0 markings, from least restrictive to most restrictive: `CLEAR`, `GREEN`, `AMBER`, `AMBER+STRICT`, `RED`.

The indicator keeps the most restrictive marking seen on it. A later `CLEAR` observation does not lower an indicator that is already `AMBER`.

Local search, `intel_get` and `intel_search` return every marking, so an analyst can read notes written with `intel_add_observation`. That tool records `source_id = analyst` and defaults the marking to `AMBER`.

Export is a separate path. `export_records` and `cyberau-mcp store export` omit `AMBER` and anything more restrictive unless the caller passes `max_tlp`. When `max_tlp` is omitted the ceiling is `GREEN`, so `CLEAR` and `GREEN` can leave and `AMBER`, `AMBER+STRICT` and `RED` stay. Passing `max_tlp` is the explicit request. The ceiling includes that marking and every less restrictive one.

Vulnerabilities have no marking column. Catalogue rows are treated as `CLEAR`. An advisory uses the `default_tlp` of its source.

STIX 2.1 export is described in `docs/intel/stix.md`. DuckDB export is separate work.

## Retention, backup and public snapshots

`cyber_au.store.retention_days` in `config.yaml` sets how long an observation is kept. The default is 365 days. `cyberau-mcp store vacuum` folds observations older than that into `indicator_counters` (source, verdict, count, confidence sum, earliest and latest time) and then runs SQLite `VACUUM`. Advisories are kept. The indicator verdict and confidence are recomputed from the observations that remain and from those counters, using the same formula as ingest.

`cyberau-mcp store backup` uses the SQLite online backup API. Files land in `plugin-data/cyber-au/backups/` as `intel-<date>.sqlite`. Seven daily copies are kept. A later backup on the same local day replaces that day's file. `store backup --restore FILE` puts a backup back after an integrity check.

`cyberau-mcp store snapshot --public` writes `intel/snapshots/public-<date>.sqlite.zst`. The date is UTC. The file contains public-source TLP:CLEAR indicators, their public observations and counters, advisories from those sources, and catalogue vulnerabilities. A source is public when it is not the analyst source, not marked keyed, and its default marking is CLEAR. Rows marked GREEN, AMBER, AMBER+STRICT or RED are omitted. Analyst observations and keyed-source rows are omitted, including notes, tags and upstream references. Register a keyed source with `ensure_source(..., keyed=True)`. A keyed flag is not cleared later.

The weekly no-agent job `cyberau-store-vacuum` runs `scripts/cyberau_store_vacuum.sh`, which takes a backup and then vacuums. Newly shipped distribution jobs arrive paused.

## Worked examples

| Observations | Verdict | Confidence |
|---|---|---|
| malicious 80 | malicious | 80 |
| malicious 80 and benign 80 | malicious | 40 |
| malicious 10 and benign 90 | benign | 81 |
| malicious 1 and benign 1 | malicious | 1 |
| suspicious, confidence omitted | suspicious | 50 |
