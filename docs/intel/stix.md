# STIX 2.1 export

`intel_export_stix` and `cyberau-mcp store export --format stix21` write one STIX 2.1 bundle from the local intel store. The record export (`--format records`, the default) is unchanged and still uses a GREEN ceiling. This page is only the STIX path.

Import the same bundle with `cyberau-mcp store import-stix FILE`. Import replays observations into the store. Run it against an empty store to reproduce the exported indicators and verdicts.

## What is included

| Store | STIX 2.1 |
|---|---|
| ipv4, ipv6, domain, url, email | Observables `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `email-addr` |
| md5, sha1, sha256 | Observable `file` with one hash |
| verdict `malicious` or `suspicious` | `indicator` with a STIX pattern, `pattern_type` `stix`, `valid_from`, `confidence`, and `labels` |
| analyst observation on that indicator | `sighting` (see `docs/adr/0001-stix-sightings.md`) |
| other observations | `x_cyberau_sources` on the indicator, or on the observable when there is no indicator |
| vulnerability | `vulnerability` with `external_references` `source_name` `cve`, plus `x_cyberau_kev` and `x_cyberau_epss` when those fields are set |
| advisory | `report` with `object_refs` and `external_references` pointing at the source URL |
| `relationships` row whose ends are both in the bundle | `relationship` |
| exporting organisation | one `identity` |

`asn` and `cidr` stay in the store. They are not in this mapping. `AMBER+STRICT` and `RED` are never written into a bundle.

Observable ids are the ids already stored on the indicator. Those ids are UUIDv5 over the ID contributing properties, JSON canonicalised as in RFC 8785, namespace `00abedb4-aa42-466c-9c01-fed23315a9b7`, as defined for STIX cyber observables in STIX 2.1 section 2.9. Domain objects, sightings, reports, relationships and the bundle use a different namespace (`urn:cyber-au:stix:sdo` under the RFC 4122 URL namespace) so they do not reuse the observable namespace.

`labels` on an indicator is the stored verdict, `malicious` or `suspicious`. `indicator_types` is `malicious-activity` or `anomalous-activity`, which is the STIX 2.1 vocabulary for the same idea. The exact verdict is also `x_cyberau_verdict`.

Timestamps in the bundle come from stored fields (`first_seen`, `last_seen`, `observed_at`, `updated_at`, `published_at`). The producer identity uses the fixed timestamp `2020-01-01T00:00:00.000Z`. Objects are sorted by id and the JSON keys are sorted, so the same store produces the same bytes.

## TLP

The STIX ceiling defaults to `CLEAR`. `GREEN` and `AMBER` are included only when `max_tlp` is set to that marking or a more permissive one in the allowed set. The allowed set is `CLEAR`, `GREEN` and `AMBER`. `AMBER` is therefore an explicit request. That request is appended to `plugin-data/cyber-au/audit/YYYY-MM-DD.jsonl` as an `export` event. The line records the ceiling, the object count and the relative output path. It does not record indicator values. The tamper-evident hash chain is separate work.

Marking definitions are the TLP 2.0 objects published by the OASIS CTI TC in [cti-stix-common-objects](https://github.com/oasis-open/cti-stix-common-objects/tree/main/extension-definition-specifications/tlp-2.0), copied from `extension-definition-specifications/tlp-2.0/examples/`. A bundle includes a definition only when an exported object references it, plus the TLP 2.0 extension definition `extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d`.

| Marking | Id | In a bundle |
|---|---|---|
| TLP:CLEAR | `marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487` | when a CLEAR object is exported |
| TLP:GREEN | `marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb` | when a GREEN object is exported |
| TLP:AMBER | `marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421` | only after `max_tlp` `AMBER` |
| TLP:AMBER+STRICT | `marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003` | never |
| TLP:RED | `marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1` | never |

## Organisation

The identity `name` is `CYBERAU_ORG_NAME` when that is set, otherwise `cyber_au.organisation` in `config.yaml` under `CYBERAU_HOME`, `HERMES_HOME` or the current directory, otherwise `cyber-au`.

## Output path

`path` on `intel_export_stix`, and `--output` on the command, must be a `.json` file inside `plugin-data/cyber-au/exports/`. That directory is `exports` next to `intel.sqlite`. A relative path is resolved inside that directory. A path that leaves it is rejected. With no output path, the bundle is returned and nothing is written.

## Custom properties

`x_cyberau_kev` uses `date_added`, `due_date` and `ransomware`. `x_cyberau_epss` uses `epss`, `percentile` and `date`. `x_cyberau_cvss_v3`, `x_cyberau_cvss_v4` and `x_cyberau_cwe` are included when the vulnerability row has them. `x_cyberau_sources` lists `source_id`, `observed_at`, and any `source_ref`, `verdict`, `confidence`, `tags` and `note`. Notes are the inner text, not the store's untrusted wrapper.
