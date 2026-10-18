# mitre-attack

- Upstream: https://github.com/mitre-attack/attack-stix-data (`index.json`, then `enterprise-attack/enterprise-attack.json`, `mobile-attack/mobile-attack.json` and `ics-attack/ics-attack.json` on the `master` branch)
- Auth: none
- Rate limit: at most 5 requests in any 3 minutes. `index.json` is cached for 1 hour. A bundle is downloaded only when the index reports a version that is not already stored under `$CYBERAU_DATA_DIR/attack/<version>/`. Timeout 120 seconds, 3 retries, 256 MiB size cap.
- Terms: ATT&CK terms of use require attribution to MITRE. The attribution string is in every envelope. Confirm https://attack.mitre.org/resources/terms-of-use/ before reuse. This connector is not endorsed by MITRE.
- Verified: 2026-10-17
- Egress hosts: raw.githubusercontent.com

`index.json` returned HTTP 200 on 17 October 2026 and listed version 20.0 for the Enterprise, Mobile and ICS collections. The bundles were not downloaded for this change.

## Fixtures (no shipped snapshot)

The package ships no ATT&CK data. Everything it serves comes from a live fetch or from its own store under `$CYBERAU_DATA_DIR/attack/`.

`tests/fixtures/index.json` is the real index trimmed to the two newest versions of each collection. `tests/fixtures/*-attack.min.json` are small hand-written STIX 2.1 excerpts that follow the ATT&CK object model. Identifiers and relationships mirror ATT&CK, but descriptions are paraphrased and some objects are synthetic (a deprecated technique, a revoked technique and a revoked group) so the skip rules can be tested. Each bundle carries an `x_cyberau_note` starting `SYNTHETIC TEST DATA`, and the invented objects also carry `x_cyberau_synthetic` and a description that starts `SYNTHETIC TEST ENTRY`. They are test data only and are never served at runtime. A live check from a network that can reach GitHub is still needed before treating the connector as current.

## Fallback order

1. Live fetch, stored under `$CYBERAU_DATA_DIR/attack/<version>/` (`cache: miss`, or `hit` when that version is already stored).
2. The newest stored version (`cache: stale`, with a warning).
3. Unavailable: no data (`null` or `[]`, `cache: snapshot`) and a warning saying ATT&CK is unavailable and why.

With `CYBERAU_OFFLINE=1` the live step is skipped. `CYBERAU_ATTACK_SNAPSHOT` points at an operator-supplied directory holding `index.json` and `<version>/<domain>-attack.json` and is used instead of everything else, with a warning that the answer came from that snapshot and not a live fetch. Tests use it to pin the fixtures.

## Live probe

`cyberau-mcp health mitre-attack --live` fetches `index.json` and the ICS bundle (the smallest) without the cache, builds one record per tool group from it and validates each envelope against `schema/*.response.json`. `--schema-drift` checks the pinned snapshot, or else the newest stored enterprise bundle, for the fields the parser needs, and reports "no local copy to check" when there is neither.

## Storage

Bundles are parsed into memory on first use and memoised per file. The SQLite index and the shared intel store are not built yet, so the versioned bundles on disk are the history.

## Operator guide

Read-only ATT&CK techniques, groups and software from the `mitre-attack/attack-stix-data` bundles.

| Tool | What it returns |
|---|---|
| `attack_technique` | One technique or sub-technique by id: tactics, platforms, data sources, detection notes, mitigations and sub-techniques |
| `attack_search` | Techniques, groups and software in one domain (`enterprise`, `mobile` or `ics`) matching a keyword, best matches first |
| `attack_group` | One group by id or name or alias, with aliases, the techniques it uses and its software |

Detection notes and data sources come from the technique's own detection text and from the detection strategies, analytics and log sources that detect it. Revoked and deprecated objects are skipped, along with relationships that point at them. Looking up a revoked technique returns no data and a warning that names its replacement. `attack_technique` and `attack_group` check the enterprise, mobile and ICS bundles in that order and return the first match.

The connector reads `index.json` and downloads a bundle only when the index reports a version it has not stored. Each version is kept under `$CYBERAU_DATA_DIR/attack/<version>/`, so earlier versions stay available. If GitHub cannot be reached, it serves the newest stored version. With nothing stored it returns no data and a warning that ATT&CK is unavailable. No key is needed. Names, descriptions and detection text are untrusted. `detection` is null when ATT&CK has no detection text for the technique. Identifiers, URLs, platforms and dates are checked against fixed patterns and anything that does not fit is wrapped as untrusted text or dropped.

MITRE ATT&CK is a registered trademark of The MITRE Corporation. ATT&CK content is used under the ATT&CK Terms of Use (https://attack.mitre.org/resources/terms-of-use/). This connector is not endorsed by MITRE.
