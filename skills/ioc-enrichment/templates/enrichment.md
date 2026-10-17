# Enrichment output

Start with this sentence:

This is guidance for an analyst, not legal advice or a formal assessment.

Then the findings, each with a citation on the next line:

Source: <name>, <version>, retrieved YYYY-MM-DD

Then this table. The indicator is defanged. A hash stays lowercase hex.
Write `unknown` when a date is missing. `sources` lists the ids that support
the verdict, or `none`.

| Indicator | Type | Verdict | Confidence | Sources | First seen | Last seen |
|---|---|---|---|---|---|---|
| 203[.]0[.]113[.]50 | ipv4 | malicious | 40 | feodo | 2026-09-01 | 2026-10-17 |

Then a JSON object that matches [the schema](../references/enrichment.schema.json).
Use `null` for a missing date. Do not put a raw address in `indicator`.

A store row is a proposal:

Proposal: store an observation for 203[.]0[.]113[.]50, type ipv4, verdict malicious, confidence 40, TLP:CLEAR, source feodo. Nothing has been written.

When there is nothing new to store:

No store proposal. Nothing has been written.

When a connector was not called because it is disabled or missing:

Missing sources: greynoise.
