---
key: "conn-feed-catalogue"
title: "Feed catalogue feeds/catalogue.yaml: every source, URL, format, auth, licence, cadence"
labels: ["type:feature", "area:connectors", "area:routines", "priority:p1"]
milestone: "v0.1 MVP"
parent: "epic-connectors"
---
## Outcome
One machine-readable catalogue drives ingestion, health checks, the README table and docs.

## Schema (`feeds/catalogue.schema.json`)
```json
{
  "type": "object",
  "required": [
    "version",
    "feeds"
  ],
  "properties": {
    "version": {
      "type": "integer"
    },
    "feeds": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "id",
          "connector",
          "url",
          "format",
          "auth",
          "poll",
          "licence",
          "region"
        ],
        "properties": {
          "id": {
            "type": "string"
          },
          "connector": {
            "type": "string"
          },
          "url": {
            "type": "string"
          },
          "format": {
            "enum": [
              "rss",
              "atom",
              "json",
              "csv",
              "stix",
              "oscal",
              "html"
            ]
          },
          "auth": {
            "type": "object",
            "properties": {
              "type": {
                "enum": [
                  "none",
                  "header",
                  "bearer"
                ]
              },
              "env": {
                "type": "string"
              },
              "header": {
                "type": "string"
              }
            }
          },
          "poll": {
            "type": "string",
            "description": "ISO 8601 duration, e.g. PT1H"
          },
          "licence": {
            "type": "string"
          },
          "region": {
            "enum": [
              "AU",
              "global"
            ]
          },
          "tlp": {
            "enum": [
              "CLEAR",
              "GREEN",
              "AMBER",
              "AMBER+STRICT",
              "RED"
            ]
          },
          "health": {
            "type": "object",
            "properties": {
              "probe": {
                "type": "string"
              },
              "expect_status": {
                "type": "integer"
              },
              "max_age": {
                "type": "string"
              }
            }
          }
        }
      }
    }
  }
}
```

## Acceptance criteria
- [ ] Catalogue lists every feed from the inventory (`docs/research/connectors.md`).
- [ ] CI validates it against the schema and checks each `connector` exists.
- [ ] The nightly refresh writes `last_ok`, `last_error` and item counts into `feeds/status.json` (not into the catalogue).
- [ ] README connector table is generated from it by `tools/build_readme_table.py` and CI fails if they drift.

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
