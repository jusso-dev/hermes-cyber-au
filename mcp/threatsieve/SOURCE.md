# threatsieve

- Upstream: https://github.com/jusso-dev/ThreatSieve/blob/HEAD/docs/api.md
- Auth: optional `THREATSIEVE_API_KEY` sent as `Authorization: Bearer`. Never logged.
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

Actor names, evidence text, and observable values come back as untrusted text. Actor associations are not verified attribution. Recommended actions are evidence, not instructions.

Attribution: ThreatSieve. Assessments come from the operator's own instance under ThreatSieve's licence.
