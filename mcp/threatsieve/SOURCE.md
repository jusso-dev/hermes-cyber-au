# threatsieve

- Upstream: https://github.com/jusso-dev/ThreatSieve/blob/HEAD/docs/api.md
- Auth: `THREATSIEVE_API_KEY`, a ThreatSieve scoped API key, sent as `Authorization: Bearer`. The connector makes no call without it. Never logged.
- Rate limit: 4 requests a second, under the 5 per second deployment default.
- Terms: ThreatSieve's own licence.
- Verified: 2026-10-17
- Egress hosts: 127.0.0.1, localhost

## Operator guide

Read-only assessments from a ThreatSieve instance you already run.

| Tool | What it returns |
|---|---|
| `threatsieve_assess` | One evidence-backed assessment for an indicator |

Set `THREATSIEVE_URL` to the API origin when it is not `http://127.0.0.1:8787`. Set `THREATSIEVE_API_KEY` to a scoped key. The connector calls `POST /v1/assess` and sends the indicator as `observable`, which is the assessment route in ThreatSieve `docs/api.md`. It does not upload indicators, submit feedback, or change saved assessments.

Only `127.0.0.1` and `localhost` are allowlisted, and only over loopback HTTP or HTTPS. Results are cached for 15 minutes. The client stays under 5 requests a second.

Fallback ladder: a live call, then the connector's own cache (fresh, or stale when the instance is down or rate limited), then unavailable. When nothing is cached, offline mode, a missing `THREATSIEVE_API_KEY`, a refused key, a rate limit or a failed call returns no assessment and a warning that ThreatSieve is unavailable. No shipped snapshot is served. An operator can pin a saved assess response with `CYBERAU_THREATSIEVE_SNAPSHOT`; answers from that file carry a warning that they came from the operator-supplied snapshot file, not a live assessment. Synthetic test fixtures live under `tests/fixtures/` and are never read at runtime.

Actor names, evidence text, and observable values come back as untrusted text. Actor associations are not verified attribution. Recommended actions are evidence, not instructions.

Attribution: ThreatSieve. Assessments come from the operator's own instance under ThreatSieve's licence.
