# asd-blueprint

- Upstream: https://blueprint.asd.gov.au/
- Auth: none
- Rate limit: search reads the shipped snapshot and does not call the site. A refresh fetches one HTML page every 5 seconds and is meant to run weekly. Timeout 30 seconds, 3 retries. 429 and 503 honour Retry-After.
- Terms: Licence not confirmed. The Blueprint is published by the Australian Signals Directorate. This connector is a reference lookup. It is not an ASD assessment and it is not endorsed by ASD.
- Verified: 2026-10-17
- Egress hosts: blueprint.asd.gov.au

The shipped snapshot holds two configuration pages retrieved on 17 October 2026: the conditional access policy "ADM - S - Limit admin sessions" and "Per-user MFA". Each record is an item and value from those pages, with the page link. Free text is wrapped as untrusted. The live health probe fetches both pages. A refresh is all or nothing: it writes `$CYBERAU_DATA_DIR/blueprint-index.json`. Matching rows are also appended to `$CYBERAU_DATA_DIR/blueprint-observations.jsonl`.

## Operator guide

Read-only lookup of published Blueprint configuration settings. This is not an ASD assessment and it is not endorsed by ASD.

| Tool | What it returns |
|---|---|
| `blueprint_search` | Matching settings with the Blueprint page link |

Search reads a shipped snapshot of two pages (a conditional access policy and per-user MFA). It does not call blueprint.asd.gov.au on each query. A weekly refresh may fetch those pages, at most one request every 5 seconds. A refresh replaces the stored index only when every page is fetched live and parsed; otherwise the previous index stays. Answers from the shipped snapshot carry a warning with the snapshot date saying they are not a live page fetch. The live health probe fetches every page the tool depends on and fails if any fetch fails or times out. Titles, setting names and values are untrusted text.

No API key. A 401 or 403 from the site is reported as a refusal. Nothing in this connector sends a credential.

Licence not confirmed. Blueprint guidance is published by the Australian Signals Directorate at https://blueprint.asd.gov.au/. Confirm the current terms before reuse. This project is not affiliated with or endorsed by ASD.
