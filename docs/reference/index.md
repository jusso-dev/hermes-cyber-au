# Reference

- [Hermes structure](../research/hermes-structure.md), checked against NousResearch/hermes-agent commit `43faacfb8de7b29548547a7fbdedad0cc6e7391c` (release v0.22.2) on 16 October 2026.
- [Connector inventory](../research/connectors.md), checked on 16 October 2026.

A data-sources page is not in this checkout. The repository `NOTICE` file sits at the root. Attribution for the connector pages that exist is on those pages.

---

Owner ticket: docs-site
Last verified: 17 October 2026


## Bootstrap and reference data

Bootstrap initialises the intel store and imports KEV with `store ingest-kev`
when a local KEV catalogue is present. Store errors stop bootstrap and keep
the underlying error visible. Without a local KEV copy, fetch current data with
`cyberau-mcp refresh --sources kev --store` when online.

ISM and Essential Eight controls are reference documents, not threat indicators
or advisories. Their connectors read `mcp/asd-ism/data` and
`mcp/asd-essentials/data` directly. Bootstrap checks these required files instead
of calling the nonexistent `store load` command. ATT&CK uses its connector's
live fetch and cache; bootstrap does not import ATT&CK rows. This preserves the
existing store schema and avoids treating synthetic examples as live intel.
