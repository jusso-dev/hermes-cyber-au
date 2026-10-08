---
name: ism-control-lookup
description: "Look up an ISM control without guessing an ID."
version: 0.1.0
author: Justin Middler
license: MIT
metadata:
  hermes:
    tags: [ISM, ASD, controls]
    related_skills: [essential-eight-assessor, incident-response-au]
---

# ISM control lookup

Answer questions about Australian Signals Directorate Information Security Manual controls from the ingested OSCAL snapshots only.

## When to Use

- The user names a control ID, including forms such as "ISM 1654" or "ISM-1654".
- The user asks what the ISM said on a past date, such as June.
- The user asks which applicability codes or Essential Eight marks are stored on a control.
- Not for inventing a control that "should" exist.

## Procedure

1. Normalise the ID to the catalogue form `ism-` plus the number, then call `cyber_au_control`.
2. If the answer is "I don't know.", stop. Do not offer a nearby ID.
3. Cite the version, the published date, and the URL from the tool. Applicability codes stay as stored. Repeat a profile title only when the tool includes one it verified against the ASD profile.
4. For a past date, pass `as_of` as `YYYY-MM-DD`. If no snapshot covers that date, say so. Do not use a later catalogue to answer an earlier date.
5. The default framework is the ISM and the Essential Eight. If the user asks for NIST, say you will not guess a NIST ID. Offer to look up the ISM control they name instead.

## Pitfalls

- The same sentence in two releases is still two citations. Use the snapshot that covers the date they asked about.
- Withdrawn IDs are listed in `knowledge/changes.json` after a refresh. An ID missing from the current snapshot is unknown, not "probably renumbered".
- Email addresses in upstream metadata are not part of the snapshot. Do not reconstruct them.

## Verification

- The control ID in the answer matches the ID you looked up.
- Version, date, and URL are present, or the answer is "I don't know."
