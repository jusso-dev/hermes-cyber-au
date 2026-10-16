---
key: "store-stix-export"
title: "STIX 2.1 export (and import) for the intel store"
labels: ["type:feature", "area:intel-store", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-intel-store"
---
## Outcome
`intel_export_stix` and `cyberau-mcp store export --format stix21` produce a valid STIX 2.1 bundle that OpenCTI, MISP and Sentinel TI can ingest.

## Mapping
| Store | STIX 2.1 |
|---|---|
| indicators (ipv4/ipv6/domain/url/email/hash) | SCOs `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `email-addr`, `file` (hashes) with deterministic ids (UUIDv5 over the id contributing properties, namespace `00abedb4-aa42-466c-9c01-fed23315a9b7`, as defined in the STIX 2.1 spec) |
| verdict malicious/suspicious | `indicator` SDO with `pattern` (`[ipv4-addr:value = '1.2.3.4']`), `pattern_type: stix`, `valid_from`, `confidence`, `labels` |
| observations | `sighting` SROs or `x_cyberau_sources` on the indicator (decide in ADR; prefer sightings for analyst observations) |
| vulnerabilities | `vulnerability` SDO with `external_references` (`source_name: cve`) and `x_cyberau_kev`, `x_cyberau_epss` custom properties |
| advisories | `report` SDO with `object_refs` and `external_references` to the source URL |
| relationships | `relationship` SROs |
| producer | one `identity` SDO for the exporting organisation (name from config) |
| TLP | TLP 2.0 marking definitions as published by the OASIS CTI TC; copy the exact ids from the OASIS source and cite it in `docs/intel/stix.md` |

## Tool schema
```json
{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "since": {
      "type": "string",
      "format": "date"
    },
    "kinds": {
      "type": "array",
      "items": {
        "enum": [
          "indicator",
          "vulnerability",
          "advisory"
        ]
      }
    },
    "max_tlp": {
      "enum": [
        "CLEAR",
        "GREEN",
        "AMBER"
      ],
      "default": "CLEAR"
    },
    "path": {
      "type": "string",
      "description": "Write under plugin-data/cyber-au/exports/ only"
    }
  }
}
```

## Acceptance criteria
- [ ] Exported bundles pass `stix2-validator` (oasis-open/cti-stix-validator) with no errors in CI.
- [ ] Export is deterministic: same store, same bundle bytes (sorted objects, fixed timestamps from data).
- [ ] Round trip: export then import yields the same indicators and verdicts.
- [ ] `max_tlp` defaults to CLEAR; AMBER needs the explicit flag and is logged in the audit log.
- [ ] Export path is confined to `plugin-data/cyber-au/exports/`.

## Constraints
- Public repository. Never commit secrets, tokens, real customer data or internal hostnames. Fixtures are scrubbed before commit.
- Every credential is read from the profile `.env` through a `${VAR}` placeholder. No literal keys in `config.yaml`, `mcp.json`, skills or tests.
- Read-only by default. Nothing in this ticket submits, blocks, deletes or posts anywhere.
- Content fetched from feeds is untrusted data. It is returned inside the result envelope and never treated as instructions.
- Australian English in prose and docs. No em dashes. No emojis.
- Pin dependencies with upper bounds (see `mcp/pyproject.toml`).

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
