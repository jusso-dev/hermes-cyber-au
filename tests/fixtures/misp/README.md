# MISP core format schema

`misp-core-event.schema.json` checks the events written by `cyberau-mcp store export --format misp`. It is a JSON Schema (2020-12) written for this repository from the MISP core format Internet-Draft:

- Source: [draft-dulaunoy-misp-core-format](https://github.com/MISP/misp-rfc/blob/b10f23ac9eb9bf79867f1f3b413adcd396e21b79/misp-core-format/raw.md), repository `MISP/misp-rfc`, file `misp-core-format/raw.md`, commit `b10f23ac9eb9bf79867f1f3b413adcd396e21b79` (26 November 2025). Retrieved 28 November 2026.
- Licence: the draft is an Internet-Draft published under the IETF Trust provisions (`ipr = "trust200902"`); the `MISP/misp-rfc` repository declares no other licence. No text from the draft is copied here. The schema restates its field names, enumerations and the category and type table as facts, so a test can check them.

## What it checks

The draft's own JSON Schema (section "JSON Schema") requires only the `Event` key and leaves most fields as plain strings. This schema is stricter and follows the draft's prose:

- the `Event` wrapper, with `uuid`, `info`, `date`, `distribution`, `published`, `timestamp`, `Orgc` and `Attribute` required (the draft's MUST fields);
- `info` of 256 characters or fewer on one line, `date` as `YYYY-MM-DD`, Unix timestamps as strings of digits;
- the enumerations for `threat_level_id` (`1` to `4`), `analysis` (`0` to `2`), event `distribution` (`0` to `4`) and attribute `distribution` (`0` to `5`), and `sharing_group_id` of `0` unless distribution is `4`;
- every attribute's `category` is one of the 16 draft categories and its `type` is valid for that category (section "Attribute Attributes", "type");
- tags have a `name`, and `colour` is an RGB hex string.

It covers only the parts of the format that the export writes: events, attributes, tags and the creator organisation. Objects, galaxies, sightings, shadow attributes and sharing groups are not described and are rejected by `additionalProperties: false`, which keeps a change to the export from adding them unchecked.

To refresh it, read the category and type lists in the current draft and update the `allOf` rules under `$defs.attribute`.
