# Information Security Manual (ISM) OSCAL catalogue

Read-only ISM controls from the Australian Signals Directorate OSCAL releases.

| Tool | What it returns |
|---|---|
| `ism_get_control` | One control: statement, applicability, section, release tag, and source SHA-256 |
| `ism_search` | Controls matching text, optionally limited to one baseline |
| `ism_list_baseline` | Control ids selected by a baseline profile |
| `ism_diff` | Controls added, removed, or whose statement changed between two releases |

`ISM-1173`, `1173`, and `ism-1173` resolve to the same OSCAL id. The shipped snapshot keeps releases `v2026.06.18` and `v2026.09.4`, trimmed to 20 controls each. An optional `GITHUB_TOKEN` raises the GitHub API limit. Control text is untrusted.

The September 2026 catalogue has statement parts and applicability properties. It does not include a separate guideline part, so `guideline` is empty unless a later release adds one.

Information Security Manual content is published by the Australian Signals Directorate. This connector is not endorsed by ASD.
