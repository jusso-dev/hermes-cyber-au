# Renderer input

`scripts/render_assessment.py` reads one JSON object. The model builds it from the evidence the user supplied and from tool payloads. A block it cannot read is treated as a missing source, so keep to these names.

Top level keys:

| Key | Value |
| --- | --- |
| `as_of` | Retrieval date, `YYYY-MM-DD`. |
| `framework` | `essential-eight`, `essentials`, or `both`. |
| `strategies` | List of strategy values from [sources](sources.md). |
| `chapter` | `enterprise-it`, `cloud`, or `ot`, for the Essentials. |
| `controls_requested` | List of ISM control ids the user asked for. |
| `nist_requested` | `true` only when the user asked for NIST. |
| `include_transition` | `true` only when the user asked for the transition mapping. |
| `import_requested`, `import_path` | `true` and the path the user gave, when an M365-Secure report was named. |
| `evidence` | List of `{ref, text, status, requirement_id}`. Use `strategy` instead of `requirement_id` when the evidence is not tied to a requirement. Use `control_id` for an ISM control. `status` is `met`, `partial`, `not met`, or `unknown`. `text` is the supplied evidence, unchanged. |

One block per tool, named `e8`, `essentials_chapter`, `essentials_transition`, `ism`, `nist`, and `evidence_import`. Set `{"available": false}` when the tool was absent, disabled, or returned an error. When it returned a payload, set `available` to `true` and copy these from the tool result:

| Block key | Copy from |
| --- | --- |
| `source` | Envelope `source`. |
| `version` | Envelope `data_as_of`, or the release in the data. |
| `retrieved_at` | Envelope `retrieved_at`. |

Then add the data the renderer reads, copied unchanged:

- `e8`: `strategies`, a list of `{strategy, maturity_level (1, 2 or 3), requirements: [{id, text, ism_ids}]}`.
- `essentials_chapter`: `chapter`, and `domains`, a list of `{domain, phase, actions: [{id, text}]}`.
- `essentials_transition`, `nist`: `mappings`, a list of `{id, text}`.
- `ism`: `controls`, a map from control id to `{found: true, statement}`. Leave a control out, or set `found` to `false`, when the tool reported no matching control. Do not write a statement for it.
- `evidence_import`: `records`, a list of `{text}`.

Never type requirement text, a control statement, or a mapping into these blocks yourself. A requirement with no evidence is `unknown`. A requirement with no retrieved text is `missing`.

Do not commit the input JSON. It holds the organisation's assessment evidence.
