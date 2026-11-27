# MISP event export

`cyberau-mcp store export --format misp` writes the local intel store as MISP events in the MISP core format, so you can load them into your own MISP instance. Nothing is sent anywhere: the command writes files and stops. Sharing is decided by a person inside MISP after import.

The record export (`--format records`), the STIX export (`docs/intel/stix.md`) and the DuckDB export (`docs/intel/duckdb.md`) are unchanged.

## Run

```sh
cyberau-mcp store export --format misp --output weekly
cyberau-mcp store export --format misp --max-tlp AMBER --output team-amber
```

- `--output` is a plain directory name (letters, digits, `.`, `_`, `-`) under `plugin-data/cyber-au/exports/`. Paths, `..`, a leading dot and symlinks are refused. Without `--output` the directory is `exports/misp-<UTC date>`.
- The directory is built as `<name>.partial` and moved into place when complete. A failed export leaves any earlier export with that name untouched. A later export with the same name replaces it whole.
- `--since` and `--kind` are not accepted. The export covers every advisory and indicator within the TLP ceiling.
- The command prints a JSON summary: the output path, the ceiling, the number of events and attributes, and how many advisories and indicators the ceiling withheld.

## Layout

The directory is a MISP feed directory, as described in the "Manifest" section of the MISP core format draft:

- one `<event uuid>.json` file per event, each a JSON object with one `Event` key;
- `manifest.json`, indexed by event uuid, with `info`, `Orgc`, `analysis`, `date`, `threat_level_id`, `timestamp`, `Tag` and `integrity:sha256` (the SHA-256 of the event file).

In MISP, add the directory as a local feed (Sync Actions, Feeds, Add Feed, input source "Local", source format "MISP Feed") or import a single event file through Events, Import from, MISP JSON.

## Events

| Event | Built from | Attributes |
|---|---|---|
| One per advisory | An advisory within the ceiling | `link` (the advisory URL), `text` (the summary), `vulnerability` (each CVE in its references), and each indicator linked to it through `advisory_refs` or `relationships`. |
| One for the rest | Indicators within the ceiling that no exported advisory links to | One attribute per indicator. |

Indicator types map to MISP attribute types as follows. Every pair is valid for its category in the draft's category and type table.

| Store type | MISP type | Category |
|---|---|---|
| `ipv4`, `ipv6`, `cidr` | `ip-dst` | Network activity |
| `domain` | `domain` | Network activity |
| `url` | `url` | Network activity |
| `asn` | `AS` | Network activity |
| `email` | `email-src` | Payload delivery |
| `md5`, `sha1`, `sha256` | `md5`, `sha1`, `sha256` | Payload delivery |

- `to_ids` is `true` only for an indicator whose store verdict is `malicious`.
- An indicator attribute's comment gives the verdict, the confidence and the source ids that reported it. `first_seen` and `last_seen` come from the store.
- Every event is written with `published: false`, distribution `0` (your organisation only), threat level `4` (undefined) and analysis `0` (initial). Attributes use distribution `5` (inherit the event). Change these in MISP when you decide to share.
- Event and attribute uuids are UUIDv5 values derived from the advisory id, the indicator value and the organisation name, so a later export updates the same events in MISP rather than creating copies.
- The creator organisation (`Orgc`) is `CYBERAU_ORG_NAME`, else `cyber_au.organisation` in `config.yaml`, else `cyber-au`, as for the STIX export.

Advisory titles and summaries are untrusted upstream text. The summary attribute's comment says so. Treat it as data, not instructions, in MISP as well.

## TLP

The ceiling works like the record and DuckDB exports (`docs/intel/scoring.md`). Without `--max-tlp` it is `GREEN`. `--max-tlp` accepts `CLEAR`, `GREEN`, `AMBER`, `AMBER+STRICT` or `RED`.

- An indicator above the ceiling is left out. An advisory takes the `default_tlp` of its source; one above the ceiling is left out with its event.
- Every attribute carries one tag from the MISP `tlp` taxonomy for its own marking: `tlp:clear`, `tlp:green`, `tlp:amber`, `tlp:amber+strict` or `tlp:red`. CVE attributes are `tlp:clear`.
- Every event carries one `tlp:` tag: the most restrictive marking of its advisory and its indicator attributes.
- An export with a ceiling above `GREEN` is recorded as an `export` event in the hash-chained audit log (`plugin-data/cyber-au/audit/<date>.jsonl`) before any file is written. If the audit record cannot be written, nothing is exported.

## Validation

`tests/intel/test_misp_export.py` checks every event against `tests/fixtures/misp/misp-core-event.schema.json`, a JSON Schema derived from the MISP core format Internet-Draft (draft-dulaunoy-misp-core-format). The schema's source, commit and licence note are in `tests/fixtures/misp/README.md`. It checks the required fields, the enumerations, string timestamps and that each attribute type is valid for its category.

## Example queries

The MISP files are for MISP. For SQL over the same data, use the DuckDB export (`docs/intel/duckdb.md`), which has these and more:

- top KEV vendors this quarter (joins the KEV snapshot for vendor names);
- indicator overlap between sources (reads `observations` and `indicator_counters`).

---

Owner ticket: 059
Last verified: 28 November 2026
