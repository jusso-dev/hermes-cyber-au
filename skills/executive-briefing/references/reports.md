# Report templates

Two templates are built by `cyberau-mcp store report` from local data. Neither makes a network call, and neither sends, posts or submits anything.

| Template | Command | Built from |
|---|---|---|
| Monthly cyber summary | `cyberau-mcp store report monthly --month YYYY-MM` | KEV rows, advisories by feed, hostile indicator counts and watchlist match counts in the intel store; the Essentials evidence register; an optional obligations file |
| Incident summary | `cyberau-mcp store report incident --incident FILE` | An incident record such as `cyber-au demo triage --json`; the evidence register when the store exists; an optional obligations file |

Common options: `--format markdown` (default), `json` or `docx`; `--obligations FILE`; `--as-of YYYY-MM-DD`; `--path` for another store, such as the demo store.

## Shape

1. Title, then a DEMO DATA line when the input is demo data.
2. Period or incident id, the guidance line, and the not-sent line.
3. Headline, At a glance table, then the sections the inputs support.
4. Asks, each a `Proposal:` for a person.
5. Appendix A: Sources. One `Source: <name>, <version>, retrieved <YYYY-MM-DD>` line per key, with what was counted and how fresh it is.
6. Appendix B: Limitations. Missing inputs, routines that never ran, and what the figures cannot tell you.
7. Appendix C: Evidence references from the register and the incident record.

The body before Appendix A stays within 450 words.

## Rules the templates keep

- Every figure in the body names a source key, and every key appears in Appendix A.
- Indicator and watchlist figures are counts only. Feed titles are quoted and defanged.
- An empty KEV or advisory count is labelled as possibly missing data.
- Essentials progress reads Essentials rows only. Essential Eight rows are mentioned as a limitation, not counted.
- The obligations section restates the input file. It is not legal advice and nothing is lodged.
- Severity in an incident summary is the local triage rating, not an ASD or regulator classification.

## Obligations input

The report accepts the obligations checker's JSON without depending on it. Any of these shapes works: an `aureg_deadline` or `aureg_obligation` envelope, a list of envelopes, a document with an `obligations` list, or a plain list of records. It reads `regime`, `trigger`, `citation` and `deadlines[].due_at`.
