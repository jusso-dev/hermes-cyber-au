# Automatic cleanup

Bootstrap enables two local, no-agent jobs once: `cyberau-store-expire` at 02:30 daily and `cyberau-store-maintenance` at 03:00 Sunday, in the scheduler's configured timezone. No model or API key is needed. Other jobs still arrive paused. Updates preserve an operator's later pause choice; `plugin-data/cyber-au/maintenance-enabled.json` records the initial decision. Existing manually paused or previously run jobs are not resumed by bootstrap.

The nightly job compacts observations after 365 days, and expires feed advisories, EPSS history and stale Feodo-only IOCs after 180 days. Configure these windows with `cyber_au.store.retention_days` and `cyber_au.store.feed_retention_days`. IOCs with another source or a relationship are retained. A successful full feed refresh also reconciles withdrawn entries.

Weekly maintenance takes an integrity-checked store backup first, then compacts and vacuums the database so freed pages return to the filesystem. It keeps seven daily store backups. It then runs `scripts/cyberau_cleanup.py --apply`:

| Artefact | Retention |
| --- | --- |
| HTTP response cache | Delete responses past their TTL plus seven days of fallback grace; vacuum SQLite |
| EPSS diagnostic journal | Rotate on write at 5 MiB plus one response batch; keep one previous generation |
| Downloaded Sigma releases | Keep newest two; delete recognised package files from older releases after 30 days |
| Pre-migration store backups | Keep newest seven; delete older matching backups after 30 days |
| Generated public store snapshots | Keep newest seven; delete older matching snapshots after 30 days |
| Feed-ingest and maintenance cron output | Keep newest seven per job; delete older timestamped output after 30 days |

Cleanup is restricted to known profile paths and filenames. Sigma directories containing custom files are left alone. Symlinks are refused, and a lock prevents overlapping cleanup runs. Briefings, investigation evidence, analyst observations, custom rules, installed skills, credentials, audit logs and active Python environments are not age-deleted. Shipped skills and generated references use stable paths and are replaced in place during distribution updates; they do not need age-based deletion. Keep locally authored skills outside distribution-owned paths when updating.

Preview disposable file and cache cleanup without deleting anything:

```sh
python3 "$HERMES_HOME/scripts/cyberau_cleanup.py" --profile-home "$HERMES_HOME"
```

Add `--apply` to execute the plan. JSON output reports selected file bytes, expired cache rows and reclaimed cache database bytes. The weekly job includes this output in its local run report. This is profile retention, not host-wide disk management: audit logs, investigation records and external snapshots still need an operator's archive policy. Retention limits age and retained generations, not an absolute disk quota.

To pause automatic cleanup:

```sh
hermes -p cyber-au cron pause cyberau-store-expire
hermes -p cyber-au cron pause cyberau-store-maintenance
```
