---
name: taxii-ctis
description: Read a user-supplied TAXII 2.1 collection, including ASD CTIS when the user brings their own access.
version: 0.1.0
author: Justin Middler
license: Apache-2.0
metadata:
  hermes:
    tags: [Security, Australia, threat-intelligence]
    related_skills: [ioc-enrichment]
    requires_tools: []
---

# TAXII and ASD CTIS

## When to Use

Load this skill when the user wants indicators from a TAXII 2.1 collection they can reach, including ASD CTIS for network partners.

CTIS content is covered by the ASD Network Partner deed. It must not be copied into a public repository, a shared log, or an export without a TLP check.

Say that before the first TAXII call in a session.

off by default: licence terms. The connector stays `enabled: false` until the user turns it on in their profile. Do not enable it during an update.

## Quick Reference

Read-only tools: `taxii_list_collections`, `taxii_get_objects`, `taxii_lookup_indicator`, `taxii_sync_status`.

## Procedure

1. State the terms above if this is the first TAXII call in the session.
2. List collections with `taxii_list_collections`, then read objects or look up one indicator.
3. Use `taxii_sync_status` to report how fresh the local copy is.

## Pitfalls

- Do not submit or upload indicators.
- Leave TLP:AMBER and above out of anything sent outside the profile unless the user overrides that for this run.

## Verification

- The terms were stated before the first call.
- No TLP:AMBER or higher content left the profile without an override.
