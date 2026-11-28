# Essentials evidence register

`cyberau-mcp store evidence` keeps the organisation's own evidence against ASD Essentials actions, and Essential Eight requirements where a team still uses them, in the local intel store. It prints a gap report by chapter and exports an xlsx register or a docx gap report that can go to management or an assessor.

Every output says it is a self-assessment, not an ASD rating, an ASD assessment or an IRAP assessment. Nothing is sent, posted or submitted.

## Two frameworks, kept separate

ASD notes that Essential Eight maturity levels do not map directly to ASD Essentials effectiveness ratings. The register keeps them apart:

- each row is keyed by `framework` (`essentials` or `essential-eight`), so the same id cannot be shared;
- Essentials figures read only Essentials rows. Essential Eight rows sit in their own report section and xlsx sheet;
- a status is `met`, `partial`, `not met`, `unknown` or `not applicable`. A maturity level such as `ML2` is refused;
- nothing converts an Essential Eight maturity level into an Essentials result. A test records every Essential Eight requirement as met and checks that no Essentials figure changes.

## Fields

| Field | Meaning |
| --- | --- |
| `framework` | `essentials` or `essential-eight`. |
| `chapter` | Essentials: `enterprise-it`, `cloud` or `ot`. Essential Eight: the strategy key, such as `regular_backups`. |
| `action_id` | Essentials: the ASD principle id and the action's position within that principle in ASD's published order, such as `PRO-13.4`. Essential Eight: the ISM id, such as `ism-1511`. |
| `status` | See above. No record shows as `unknown`, which is not a failure. |
| `evidence` | A link or a short note. |
| `owner` | Who owns the action. |
| `review_date` | When the evidence is next reviewed. |
| `source` | Where the evidence came from. Defaults to `analyst`. |
| `evidence_date` | When the evidence was gathered. Defaults to today, Australia/Sydney. |

Ids are checked against the shipped ASD snapshot through the asd-essentials connector. Each row also stores the hash of the ASD text it was recorded against and the snapshot date. When ASD rewords an action, the row shows `reference changed` until someone checks it.

Freshness is worked out when a report is read: `review overdue`, `evidence older than 12 months`, `review due within 30 days`, `no review date` or `current`.

ASD numbers principles, not individual actions. The `.1`, `.2` suffix is this register's own position count within a principle. If ASD inserts an action mid-principle, later suffixes shift. The stored text hash catches that, and the row is flagged.

## Commands

```sh
cyberau-mcp store evidence actions --chapter enterprise-it
cyberau-mcp store evidence record --framework essentials --chapter enterprise-it \
  --action PRO-13.4 --status partial --evidence "MFA for administrators only" \
  --owner "IT operations" --review-date 2027-03-31 --source "identity provider report"
cyberau-mcp store evidence import register.csv
cyberau-mcp store evidence list
cyberau-mcp store evidence report [--chapter ot] [--json]
cyberau-mcp store evidence export --format xlsx
cyberau-mcp store evidence export --format docx --output board-pack.docx
```

`import` reads a CSV with the header `framework,chapter,action_id,status,evidence,owner,review_date,source,evidence_date` and writes every row or none.

Without `--chapter`, the report covers chapters that already have rows, or else the environments in `org.yaml`.

## Gap report

For each chapter, the report counts actions by status and lists every action that is not met, partial, unknown, overdue for review or recorded against older ASD wording. Not met comes first, then partial, then unknown, each in ASD priority phase order. A priority phase only sequences work; it is not a maturity level. The next step for each quotes the ASD action, and the chapter is cited with its snapshot date and cyber.gov.au URL.

## Exports

xlsx and docx use an optional extra:

```sh
uv sync --project mcp --extra documents
```

That installs `openpyxl` (3.1 or later, below 4) and `python-docx` (1.1 or later, below 2). Without them, `export` prints the command above and exits with status 2. The markdown report still works.

- The xlsx has four sheets: About (the self-assessment notice and citations), Essentials register (every action in scope, with its row), Gaps by chapter, and Essential Eight register when there are Essential Eight rows.
- The docx is the gap report.
- Files go under `plugin-data/cyber-au/exports/` only. Other paths, `..`, symlinks and other suffixes are refused. A file is written to `<name>.partial` and moved into place when complete.
- Cell text is stored as text, so a note that starts with `=` cannot run as a formula when the file is opened.

The register lives in `intel.sqlite`, so `cyberau-mcp store backup` covers it. It is the organisation's record: keep the database and exports out of version control.
