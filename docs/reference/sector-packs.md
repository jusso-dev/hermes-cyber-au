# Sector packs

A sector pack adds sources, rules, skill notes and connector suggestions for one sector. Packs switch on from `org.yaml`, so a team turns one on or off without editing a core file.

Packs are reference data. They are guidance, not legal advice, and a pack cannot tell a skill to submit, send or post anything: the loader rejects that wording.

## Shipped packs

| Pack | Version | Covers | Evals |
|---|---|---|---|
| `energy-water` | 0.1.0 | SOCI risk management program rules for electricity, gas, liquid fuel, energy market and water assets (baseline and enhanced), the frameworks the CIRMP Rules accept (Essential Eight, AESCSF, C2M2, NIST, ISO 27001), phishing resistant MFA, OT material risks, the SOCI annual report, ASD OT principles and the Essentials for OT chapter. | `tests/packs/energy-water/evals.yaml` |
| `health` | 0.1.0 | My Health Records Act s 75 breach notification, the health service exception to the small business exemption, health information as sensitive information, and designated hospitals under the CIRMP Rules. Lighter first cut. | `tests/packs/health/evals.yaml` |

Sources were read on 2026-11-28 against the versions cited in each `pack.yaml`. The AEMO AESCSF page blocked automated retrieval on that date, so the energy-water pack quotes the AESCSF editions and security profiles from the CIRMP Rules, not from AEMO. Every rule is due for review by 2027-05-28.

## Turning packs on and off

| `org.yaml` | Active packs |
|---|---|
| `sector: energy-water`, no `sector_packs` | `energy-water`, plus any pack whose `sectors` list names `energy-water` |
| `sector_packs: [health]` | `health` only, whatever the sector |
| `sector_packs: [none]` | none |

Shipped packs live in `packs/<name>/` (a distribution-owned path, refreshed by `update`). Your own packs go in `plugin-data/cyber-au/packs/<name>/` on the profile, which an update never touches. A local pack with the same name as a shipped one replaces it.

`hermes cyber-au doctor` reports the active packs under `org.packs`, warns when a pack named in `org.yaml` is not installed, when a pack fails validation (it is skipped, not loaded), and when a rule is past its review date. `cyberau-mcp org packs` lists every installed pack as JSON.

## Format

`packs/<name>/pack.yaml`:

```yaml
name: example-pack            # must equal the directory name
version: 0.1.0
title: Example
description: One paragraph on what the pack adds.
sectors: [retail]             # org.yaml sectors that switch this pack on
reviewed: 2026-11-28
review_by: 2027-05-28
sources:                      # every rule cites one of these; every source is cited
  - id: example-act
    title: Example Act 2026
    version: Compilation No. 1
    url: https://www.legislation.gov.au/...
    retrieved: 2026-11-28
    note: optional, for example a register id
connectors:                   # optional; keys from mcp/servers.yaml
  - key: aureg
    why: Why this sector wants it. Setup does not switch it on for you.
rules:
  - id: example-rule
    title: Short title
    kind: obligation          # or guidance
    applies_when:             # optional; all must match the profile
      critical_infrastructure: true
      environments: [ot]      # any of; also sector, size, turnover, regulators
    skills: [soci-reporting]  # optional; which skills see the rule
    summary: Plain words, with the section in brackets.
    source: example-act
    section: s 1
    reviewed: 2026-11-28
    review_by: 2027-05-28
prompts:                      # optional; extra notes per skill
  incident-triage:
    - A question to ask, or a check to make.
playbooks: []                 # optional; paths under playbooks/
```

The loader (`plugins/cyber-au/store/packs.py`) checks every field: known keys, dates, `https` source URLs, `review_by` after `reviewed`, every rule's source listed, every source cited, condition values from the `org.yaml` contract, and no em dashes. The shipped-pack test also checks connector keys against `mcp/servers.yaml`, skill names against `skills/`, and playbook references against `playbooks/`.

## Adding a pack

1. Create `packs/<name>/pack.yaml` (or `plugin-data/cyber-au/packs/<name>/pack.yaml` for a private pack).
2. Read every source you cite and record the version and the date you read it. Write "I don't know" in a summary rather than guess.
3. Add `tests/packs/<name>/evals.yaml` with cases that write a synthetic `org.yaml` and check the rendered context. Use example.com names only.
4. Run `uv run --project mcp pytest -q tests/packs`.
