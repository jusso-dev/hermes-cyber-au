# asd-blueprint

- Upstream: https://blueprint.asd.gov.au/
- Auth: none
- Rate limit: search reads the shipped snapshot and does not call the site. A refresh fetches one HTML page every 5 seconds and is meant to run weekly. Timeout 30 seconds, 3 retries. 429 and 503 honour Retry-After.
- Terms: Licence not confirmed. The Blueprint is published by the Australian Signals Directorate. This connector is a reference lookup. It is not an ASD assessment and it is not endorsed by ASD.
- Verified: 2026-10-17
- Egress hosts: blueprint.asd.gov.au

The shipped snapshot holds two configuration pages retrieved on 17 October 2026: the conditional access policy "ADM - S - Limit admin sessions" and "Per-user MFA". Each record is an item and value from those pages, with the page link. Free text is wrapped as untrusted. A refresh writes `$CYBERAU_DATA_DIR/blueprint-index.json`. Matching rows are also appended to `$CYBERAU_DATA_DIR/blueprint-observations.jsonl`.
