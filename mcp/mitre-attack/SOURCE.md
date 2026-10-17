# mitre-attack

- Upstream: https://github.com/mitre-attack/attack-stix-data (`index.json`, then `enterprise-attack/enterprise-attack.json`, `mobile-attack/mobile-attack.json` and `ics-attack/ics-attack.json` on the `master` branch)
- Auth: none
- Rate limit: at most 5 requests in any 3 minutes. `index.json` is cached for 1 hour. A bundle is downloaded only when the index reports a version that is not already stored under `$CYBERAU_DATA_DIR/attack/<version>/`. Timeout 120 seconds, 3 retries, 256 MiB size cap.
- Terms: ATT&CK terms of use require attribution to MITRE. The attribution string is in every envelope. Confirm https://attack.mitre.org/resources/terms-of-use/ before reuse. This connector is not endorsed by MITRE.
- Verified: 2026-10-17
- Egress hosts: raw.githubusercontent.com

`index.json` returned HTTP 200 on 17 October 2026 and listed version 20.0 for the Enterprise, Mobile and ICS collections. The bundles were not downloaded for this change.

## Shipped snapshot and fixtures

`data/index.json` is the real index trimmed to the two newest versions of each collection. The bundles under `data/20.0/` and `tests/fixtures/*-attack.min.json` are small hand-written STIX 2.1 excerpts that follow the ATT&CK object model. Identifiers and relationships mirror ATT&CK, but descriptions are paraphrased and some objects are synthetic (a deprecated technique, a revoked technique and a revoked group) so the skip rules can be tested. Each bundle carries an `x_cyberau_note` starting `SYNTHETIC TEST DATA`, and the invented objects also carry `x_cyberau_synthetic` and a description that starts `SYNTHETIC TEST ENTRY`. Treat them as test data, not as current ATT&CK content. Whenever the shipped excerpt is served, the envelope carries a warning saying so. A live check from a network that can reach GitHub is still needed before treating the connector as current.

## Fallback order

1. Live fetch, stored under `$CYBERAU_DATA_DIR/attack/<version>/` (`cache: miss`, or `hit` when that version is already stored).
2. The newest stored version (`cache: stale`, with a warning).
3. The shipped snapshot (`cache: snapshot`, with a warning).
4. No data and an `unavailable` style warning.

With `CYBERAU_OFFLINE=1` the live step is skipped. `CYBERAU_ATTACK_SNAPSHOT` points at a directory laid out like `data/` and is used instead of everything else, which is how tests pin their data.

## Live probe

`cyberau-mcp health mitre-attack --live` fetches `index.json` and the ICS bundle (the smallest) without the cache, builds one record per tool group from it and validates each envelope against `schema/*.response.json`. `--schema-drift` checks the shipped or pinned enterprise snapshot for the fields the parser needs.

## Storage

Bundles are parsed into memory on first use and memoised per file. The SQLite index and the shared intel store are not built yet, so the versioned bundles on disk are the history.
