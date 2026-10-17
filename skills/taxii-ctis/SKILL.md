---
name: taxii-ctis
description: Read a user-supplied TAXII 2.1 collection, including ASD CTIS when the user brings their own access.
---

CTIS content is covered by the ASD Network Partner deed. It must not be copied into a public repository, a shared log, or an export without a TLP check.

Say that before the first TAXII call in a session.

off by default: licence terms. The connector stays `enabled: false` until the user turns it on in their profile. Do not enable it during an update.

Read-only tools: `taxii_list_collections`, `taxii_get_objects`, `taxii_lookup_indicator`, `taxii_sync_status`. Do not submit or upload indicators. Leave TLP:AMBER and above out of anything sent outside the profile unless the user overrides that for this run.
