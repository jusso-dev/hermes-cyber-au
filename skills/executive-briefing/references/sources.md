# Source notes

Use these citation names. The version is the envelope field `data_as_of`, or `none` when that field is missing or is only a published date.

| Material | Citation name | Version |
|---|---|---|
| CISA KEV | CISA Known Exploited Vulnerabilities | `data_as_of` (catalogue version) |
| ASD ACSC feed | ASD ACSC alerts | `none` |
| Cloudflare Radar | Cloudflare Radar | `none`, unless the envelope has a release id |
| Information Security Manual | Australian Signals Directorate Information Security Manual | `data_as_of` (release tag) |
| Facts the analyst stated | analyst request | `none` |
| A stub or other fixture with no catalogue | hermes-cyber-au stub | `none` |

Write the retrieval date from `retrieved_at` as `YYYY-MM-DD` in Australia/Sydney.

## Tier 1

Open Tier 1 means all of the following:

- the vulnerability is in KEV, or an ASD ACSC alert names it, or an EPSS score in the material is at least 0.7
- the analyst's record, or `intel_search`, does not show it as remediated

Do not quote an EPSS score that was not in the tool result. If EPSS was not queried, say so. Do not add a vulnerability to the count because it feels severe.

## Numbers

The page may use these figures, each with a citation: KEV additions in the period, Australian outages, Australian attack trends, and the open Tier 1 count.

Exposure trends are the exception that is counts only: one line, no account names, no people, no file names, and no credential values.

## Cloudflare Radar

State this before the first Radar call in a session:

Cloudflare Radar API data is CC BY-NC 4.0: non-commercial use only, unless the organisation has an agreement with Cloudflare.

Attribute Cloudflare Radar on every figure taken from it. If the connector is disabled or there is no key, write "Cloudflare Radar is not available" and do not invent a figure.

## Victims

Do not print a victim's name. Count the names in an untrusted claim and say they were withheld. They are claims, not confirmed incidents.
