---
name: essential-eight-assessor
description: "Score Essential Eight only with observed evidence."
version: 0.1.0
author: Justin Middler
license: MIT
metadata:
  hermes:
    tags: [Essential Eight, maturity, evidence]
    related_skills: [ism-control-lookup, sentinel-expert]
---

# Essential Eight assessor

Estimate Essential Eight maturity only from evidence the user supplies. Catalogue text is prepared, not observed.

## When to Use

- The user asks for a maturity level against the Essential Eight.
- The user has pasted policy text, a screenshot description, or a log extract and wants a level.
- Not for a score based only on the ISM saying a control exists.

## Procedure

1. Read `knowledge/essential-eight-strategies.json`. If `strategies` is empty, say the eight names were not all present in the fetched pages and do not recite them as verified.
2. If the list is present, assess each strategy separately. Ask for observed evidence when the user has only a policy sentence.
3. Levels are 0, 1, 2, and 3, matching the maturity model in the snapshot. Call `cyber_au_search` on source `asd-essential-eight` and quote the page version or the retrieved date. If the page did not state a version, say "unspecified".
4. A mark such as ML1 on an ISM control means the catalogue links that control to a level. It is not a finding that the user's environment meets the level.
5. Where Oh My Hermes is available, record the claim with `cyber_au_source_trust`. Catalogue quotes may support an approach. They must not be recorded as a completed control. If the tool says the ceiling did not run, do not invent a pass.
6. Output one line per strategy: level, or "not assessed", plus the evidence the user gave, plus the source URL. Do not average them into a single badge unless the user asks, and even then label it as an estimate.

## Pitfalls

- Prepared text is not observed evidence. `prepared_not_observed` means the control was not seen in a live system.
- Do not lift a maturity claim from a vendor product page.
- Do not convert the result into a NIST score.

## Verification

- Every level you assign points at user-supplied evidence in the same answer.
- Strategies with no evidence stay "not assessed".
- Citations include the snapshot version or retrieved date and the URL.
