# M365-Secure assessment reports

Read-only parser for JSON reports written by `m365-assess`. This is not an MCP server. It does not call Microsoft, and it does not need a credential. You run M365-Secure yourself, then import the local `_Assessment-Results_<domain>.json` file.

| Tool | What it returns |
|---|---|
| `evidence_import` | Normalised findings, summary and framework roll-ups from a schema 1.1 report |

The tool takes one argument, `path`, the filesystem path of the JSON report. The result is the usual evidence envelope. `data.records` holds one record per finding. Free-text fields are wrapped as untrusted text. `attribution` names M365-Secure on every envelope, including failures. The tool is read-only (`readOnlyHint`) and may read a path you supply (`openWorldHint`).

The report object follows M365-Secure schema 1.1, confirmed from [jusso-dev/M365-Secure](https://github.com/jusso-dev/M365-Secure) commit `9fae976a0acfda3f55795013d7f78739c86a94a9` (`src/report/json.rs`, `src/assessment/finding.rs`, `src/assessment/severity.rs`, `src/assessment/engine.rs`, `src/compliance/mapping.rs`). The checked shape is in `plugins/cyber-au/evidence/schema/m365_secure_report.schema.json`. Finding `status` and `severity` use serde lowercase (`pass`, `notlicensed`, `high`). Summary `status_counts` and `severity_counts` use the Display labels (`Pass`, `Not Licensed`, `High`).

There is no egress host. A URL is refused. When `CYBERAU_OFFLINE=1` and the file is missing, the envelope warns that the report is unavailable. A file that is present is read either way. Rate limits do not apply. Cache state for a report that was read is `snapshot`.

M365-Secure is published under the MIT licence. This parser is not endorsed by Microsoft.
