# Executive reports

`cyberau-mcp store report` drafts a one-page monthly cyber summary or an incident summary for executives, as markdown, JSON or docx. It is built from local data only and makes no network call.

## Inputs

| Input | Used for | When missing |
| --- | --- | --- |
| Briefing history in the intel store: KEV rows (`vulnerabilities`), advisories by feed, hostile indicators, watchlist matches | Monthly figures | Each zero is labelled as possibly missing data, not a quiet month |
| Essentials evidence register | Essentials progress, evidence references | Stated as a limitation |
| `--obligations FILE` | Reporting obligations table | Stated as a limitation |
| `--incident FILE` | Incident summary | Required for an incident summary |

`--obligations` takes JSON from the obligations checker or the au-regulatory connector: an `aureg_deadline` or `aureg_obligation` envelope, a list of envelopes, a document with an `obligations` list, or a plain list of obligation records. The report reads `regime`, `trigger`, `citation` and any `deadlines[].due_at`. It does not depend on the obligations engine being installed.

`--incident` takes a JSON object such as the output of `cyber-au demo triage --json`: `alert_id`, `title`, `detected_at`, `severity`, `severity_reasons`, `observables`, `matches`, `attack`, `personal_information`, `soci_asset`, and an optional `evidence` list.

## Every figure cites its source

Each figure carries a source key (`S1`, `S2`...). Appendix A lists every key as a `Source: <name>, <version>, retrieved <YYYY-MM-DD>` line with what was counted and how fresh it is (newest row date, last watchlist run, snapshot date). Appendix B keeps the limitations, including missing inputs. Appendix C keeps evidence references from the register and the incident record. The one-page body stays within 450 words; the appendices follow it.

Indicator and watchlist figures are counts only. Feed titles are quoted and defanged. Essential Eight rows in the register are never counted in Essentials progress. Asks are written as `Proposal:` lines for a person to act on.

## Commands

```sh
cyberau-mcp store report monthly --month 2026-10
cyberau-mcp store report monthly --start 2026-10-01 --end 2026-10-31 --obligations obligations.json
cyberau-mcp store report incident --incident incident.json --format docx
```

Without `--month` or `--start`/`--end`, the monthly report covers the last full month. `--format docx` needs the documents extra (`uv sync --project mcp --extra documents`) and writes under `plugin-data/cyber-au/exports/`.

## Try it on demo data

```sh
hermes -p cyber-au cyber-au demo load
cyberau-mcp store report monthly --month 2026-10 \
  --path "$CYBERAU_DATA_DIR/demo/intel-demo.sqlite" \
  --obligations "$CYBERAU_DATA_DIR/demo/obligations-demo.json"
hermes -p cyber-au cyber-au demo triage --json > incident.json
cyberau-mcp store report incident --incident incident.json \
  --path "$CYBERAU_DATA_DIR/demo/intel-demo.sqlite"
```

`demo load` adds synthetic KEV rows, advisories, evidence register rows and an obligations file to the separate demo store. Reports from it start with a DEMO DATA line.

The report is guidance. It is not legal advice, an audit or a certification. It is not sent, posted or submitted, and no regulator is contacted.
