# socradar

- Upstream: https://platform.socradar.com/api/company/{company_id}/incidents/v4
- Auth: Company API key in the `Api-Key` header (`SOCRADAR_API_KEY`) and a numeric company id (`SOCRADAR_COMPANY_ID`). Values are read from the environment and are never logged.
- Rate limit: Not published. This connector uses a local ceiling of 5 requests in a burst, refilling at 1 request a second, and honours `Retry-After` on HTTP 429. That ceiling is not a vendor quota. Calls per day, calls per month and `monthly_budget_units` stay unset.
- Terms: Commercial licence. Session cache. Store metadata only. No STIX export.
- Verified: 2026-10-17
- Egress hosts: platform.socradar.com

## Confirmed parameters

The vendor page https://socradar.io/socradar-apis/ returned HTTP 403 on 17 October 2026. The customer portal was not available. Parameters below are confirmed from vendor-published integrations, not from the portal.

Cortex XSOAR `SOCRadarIncidentsV4` (demisto/content) calls `GET /company/{company_id}/incidents/v4` with header `API-Key` (the same header as `Api-Key`) and these query parameters:

| Parameter | How this connector uses it |
| --- | --- |
| `start_date` | Tool `since`, as `YYYY-MM-DD` |
| `end_date` | Tool `until`, as `YYYY-MM-DD` |
| `severities` | One value from tool `severity`. Confirmed values: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `page` | Page number, starting at 1 |
| `limit` | Page size, capped at 100 |
| `include_total_records` | Sent as `true` so `total_pages` is present |

Elastic's SOCRadar integration documents the same path and also `start_date`, `page`, `limit` and `include_alarm_details`. This connector sends `include_alarm_details=true`.

`since` and `until` are Australia/Sydney calendar dates. No timezone query parameter was confirmed, so the date is sent as `YYYY-MM-DD` without a zone.

## Parameters not sent

- A query parameter named `severity`. The confirmed name is `severities`.
- `status`. XSOAR can send `OPEN`, `CLOSED` and `ON_HOLD`. This tool has no status argument, so the parameter is omitted.
- Alarm type filters (`alarm_main_types`, `alarm_sub_types`, `alarm_type_ids`, and the excluded variants). XSOAR can send them. This tool reads types from the response instead.
- A published rate limit, daily cap or monthly cap.

## Alarm type mapping

Only example strings published on the XSOAR integration are mapped. Other types are omitted. The warning is a count. The raw type string is not copied into it.

| Response field | Confirmed example | Exposure kind |
| --- | --- | --- |
| `alarm_sub_type` | Impersonating Domain | `brand_impersonation` |
| `alarm_sub_type` | Stolen Credential | `breach_credential` |
| `alarm_main_type` | Attack Surface Management | `attack_surface_issue` |

`Brand Protection` is a published main-type example. It is not mapped on its own, because that integration lists more than one sub-type under it.

`Stolen Credential` is mapped to `breach_credential`. The example does not say infostealer, so it is not mapped to `infostealer_credential`.

These kinds have no confirmed alarm type string and are not produced: `dark_web_mention`, `infostealer_credential`, `leak_site_claim`, `data_leak_disclosure`, `typosquat_domain`.

## Response fields

Read from the XSOAR parser for this endpoint: `data.alarms`, `alarm_id`, `date`, `alarm_risk_level`, `alarm_asset`, `alarm_related_assets` (`key` and `value`), `alarm_text`, `alarm_type_details.alarm_main_type`, `alarm_type_details.alarm_sub_type`, `total_pages`, `is_success`.

`date` uses that integration's formats and is stored as UTC. The integration does not document a timezone.

`alarm_text` is redacted and returned only inside `untrusted_text`. It is not written to the intel store. Alarm content objects, mitigation text and mailbox local-parts are not copied. An asset that contains `@` keeps only the domain, as `email_domain`.

Findings that match `watchlist.yaml` in the profile data directory are written to the intel store as metadata. The file is not a vendor parameter.

## Fixtures, snapshots and health

Every file under `mcp/socradar/tests/fixtures/` is synthetic. Nothing was recorded from SOCRadar, because no portal access was available. `socradar_incidents.yaml` is an empty placeholder, not a recorded cassette. Field names and shapes follow the XSOAR parser above and are not confirmed against the live service.

`CYBERAU_SOCRADAR_SNAPSHOT` points the tool at a local JSON file. A result served from it has `cache: snapshot` and a warning that says it is not live. It is never written to the intel store, and `exposure_for` refuses it. A copy served from an expired cache entry has `cache: stale` and a warning.

`cyberau-mcp health socradar --live` makes one uncached request and reports ok only for a live response that passes the schema. It reports not ok when the key or company id is missing, when the fetch fails, and when the answer came from a cache or a snapshot. Without `--live` a missing key reports `not configured` as ok.
