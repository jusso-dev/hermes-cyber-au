# Bundled hunt schemas

These files are a partial extract for the offline KQL check. They are not the full vendor catalogue.

Each file records `source_name`, `version`, and `retrieved`. Cite a column or table with that name and version. `version` is `none` when the page has no catalogue release id. `retrieved` is the date the column list was read (YYYY-MM-DD).

`partial` is true. A column that is not in the file is not confirmed. Do not say the vendor table lacks that column. Drop the column and check again, or stop and say it is not confirmed.

| File | Table | Product |
|---|---|---|
| `device-process-events.json` | `DeviceProcessEvents` | Microsoft Defender XDR advanced hunting |
| `device-file-events.json` | `DeviceFileEvents` | Microsoft Defender XDR advanced hunting |
| `security-event.json` | `SecurityEvent` | Microsoft Sentinel (Azure Monitor Logs) |

`DeviceFileEvents` page text stated it was last updated on 2026-06-22. That date is `page_updated` on the file. The other two pages were read on the `retrieved` date. Their page-updated dates were not copied.

The checker in `scripts/check_kql.py` is the reference. It requires the table name in the query, a comparison on that table's `time_column`, and columns from the bundled file. It refuses any statement that starts with a dot (a management command), `externaldata`, and the outbound `evaluate` plugins such as `http_request`. It checks every bare identifier, not only those in a comparison. It does not run the query.

Source: Microsoft Learn DeviceProcessEvents table, none, retrieved 2026-10-17.
Source: Microsoft Learn DeviceFileEvents table, none, retrieved 2026-10-17.
Source: Microsoft Learn SecurityEvent table, none, retrieved 2026-10-17.
