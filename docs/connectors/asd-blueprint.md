# ASD Blueprint for Secure Cloud

Read-only lookup of published Blueprint configuration settings. This is not an ASD assessment and it is not endorsed by ASD.

| Tool | What it returns |
|---|---|
| `blueprint_search` | Matching settings with the Blueprint page link |

Search reads a shipped snapshot of two pages (a conditional access policy and per-user MFA). It does not call blueprint.asd.gov.au on each query. A weekly refresh may fetch those pages, at most one request every 5 seconds. Titles, setting names and values are untrusted text.

No API key. A 401 or 403 from the site is reported as a refusal. Nothing in this connector sends a credential.

Licence not confirmed. Blueprint guidance is published by the Australian Signals Directorate at https://blueprint.asd.gov.au/. Confirm the current terms before reuse. This project is not affiliated with or endorsed by ASD.
