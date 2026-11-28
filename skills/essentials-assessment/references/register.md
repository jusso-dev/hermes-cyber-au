# Evidence register

The evidence register is a table in the local intel store (`essentials_evidence`, store migration 0004). It holds the organisation's own record of evidence against ASD Essentials actions and, kept separate, Essential Eight requirements. It is a self-assessment, not an ASD rating, an ASD assessment or an IRAP assessment. Every report and export says so.

## Fields

| Field | Meaning |
| --- | --- |
| `framework` | `essentials` or `essential-eight`. The two are never mixed. |
| `chapter` | Essentials: `enterprise-it`, `cloud` or `ot`. Essential Eight: the strategy key, such as `regular_backups`. |
| `action_id` | Essentials: the ASD principle id and the action's position in that principle, such as `PRO-13.4`. Essential Eight: the ISM id, such as `ism-1511`. |
| `status` | `met`, `partial`, `not met`, `unknown` or `not applicable`. A maturity level is refused. |
| `evidence` | A link or short note. Do not paste secrets or personal information. |
| `owner` | Who owns the action. |
| `review_date` | When the evidence is next reviewed, `YYYY-MM-DD`. |
| `source` | Where the evidence came from, such as `identity provider report`. Defaults to `analyst`. |
| `evidence_date` | When the evidence was gathered, `YYYY-MM-DD`. Defaults to today in Australia/Sydney. |

The register also stores the hash of the ASD action text and the snapshot date it was recorded against. When ASD changes the wording, the row is shown as `reference changed` so someone checks the evidence still fits.

Freshness is worked out when a report is read: `review overdue`, `evidence older than 12 months`, `review due within 30 days`, `no review date` or `current`.

## Commands

```bash
cyberau-mcp store evidence actions --chapter enterprise-it
cyberau-mcp store evidence record --framework essentials --chapter enterprise-it \
  --action PRO-13.4 --status partial --evidence "MFA for administrators only" \
  --owner "IT operations" --review-date 2027-03-31 --source "identity provider report" \
  --evidence-date 2026-10-02
cyberau-mcp store evidence record --framework essential-eight --chapter regular_backups \
  --action ism-1511 --status met --source "backup system log"
cyberau-mcp store evidence import register.csv
cyberau-mcp store evidence report            # markdown gap report
cyberau-mcp store evidence report --json
cyberau-mcp store evidence export --format xlsx
cyberau-mcp store evidence export --format docx --output board-pack.docx
```

`import` reads a CSV with the header `framework,chapter,action_id,status,evidence,owner,review_date,source,evidence_date`. Every row is checked first, and nothing is written if any row is wrong.

`report` covers the chapters named with `--chapter`, else the chapters that have rows, else the environments in `org.yaml` (`it`, `ot`, `cloud`).

## Gap report

The gap report lists, per chapter, every action that is `not met`, `partial`, `unknown`, overdue for review or recorded against older ASD wording. Not met comes first, then partial, then unknown, each in ASD priority phase order. A priority phase only sequences work. It is not a maturity level. The suggested next step quotes the ASD action text and the report cites the ASD chapter, its snapshot date and its URL.

Essential Eight rows appear in their own section and sheet. They are never counted in an Essentials figure, and no Essentials result is derived from an Essential Eight maturity level. ASD says the two do not map directly.

## Exports

xlsx and docx need the optional documents extra:

```bash
uv sync --project mcp --extra documents
```

Without it, `export` prints that command and exits with status 2. Files are written under `plugin-data/cyber-au/exports/` only. Paths outside it, `..` segments, symlinks and other suffixes are refused. Spreadsheet cells are written as text, so a note that starts with `=` cannot run as a formula. Nothing is sent, uploaded or attached.
