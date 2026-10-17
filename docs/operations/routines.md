# Shipped routines

Installing this distribution adds five cron jobs. `cron/jobs.json` holds the definition of each job (name, schedule, prompt or script, skills, delivery). It does not set `enabled`, `state`, `paused_at`, or `paused_reason`.

On a new install, Hermes stores every new job id as paused. On an update, Hermes refreshes the definition for an id that already exists and keeps that job's pause or resume choice. An id that appears for the first time in a later version starts paused, including on an update.

Times follow `timezone: Australia/Sydney` in `config.yaml`.

| Id | Name | When (Sydney) | Delivery |
|---|---|---|---|
| `cyberau-ingest-public` | Ingest public feeds | every 60 minutes | `local` |
| `cyberau-morning-brief` | Morning cyber briefing (AU) | 07:30 every day (`30 7 * * *`) | `origin` |
| `cyberau-kev-watch` | KEV and EPSS watch for my assets | every 360 minutes | `origin` |
| `cyberau-weekly-exec` | Weekly executive summary | 08:00 Monday (`0 8 * * 1`) | `origin` |
| `cyberau-store-maintenance` | Store vacuum and backup | 03:00 Sunday (`0 3 * * 0`) | `local` |

Hermes does not accept the phrase `every 1d at 07:30`. The morning job uses the cron expression `30 7 * * *`. With `timezone: Australia/Sydney`, that is 07:30.

## Turn a routine on

Jobs do nothing until you resume the ones you want:

```bash
hermes -p cyber-au cron list
hermes -p cyber-au cron resume cyberau-morning-brief
hermes -p cyber-au cron run cyberau-morning-brief
```

`hermes -p cyber-au cron pause <id>` pauses one job again. `hermes pause` and `hermes resume` stop and start the scheduler for every job. They do not rewrite each job's own paused flag.

Shipped delivery is `origin` or `local` (saved on this machine). A shipped job has no recorded origin chat, so `origin` sends to the first home channel you have configured for the profile. If none is configured, Hermes skips delivery and keeps the output in the job's last output, which `hermes -p cyber-au cron list` shows. This repository does not name a person, an email address, or a Slack, Teams, or Telegram channel. To send a briefing somewhere else, set the target on your own profile with `hermes cron edit <id> --deliver <target>` after you have resumed the job. Do not put that target in the shipped file.

## Scripts

`cyberau-ingest-public` and `cyberau-store-maintenance` set `no_agent` and name a script. Hermes resolves that name inside `$HERMES_HOME/scripts/` and runs it with a sanitised environment, so provider credentials are not inherited. The ingest script does not open the profile `.env`. Keyed feeds run inside the agent jobs, where each MCP server receives its keys from `mcp_servers.*.env`.

These scripts call `cyberau-mcp refresh` and `cyberau-mcp store`, which the shared library does not implement yet (it exits with `refresh is not part of the shared library yet`). Until the connector and store tickets land, a resumed script job reports that failure line and changes nothing.

Ingest refreshes the keyless sources `asd`, `kev`, `epss`, `auscert`, and `feodo`. Store maintenance runs `cyberau-mcp store backup`, then `store compact` (retention compaction), then `store vacuum`. Each script prints one line on success and one short line on failure. That line is what Hermes delivers.

## Quiet KEV watch

`cyberau-kev-watch` replies with the single word NOTHING when no asset matches. Hermes delivers that word.

To suppress delivery when there is nothing to report, change the prompt so the no-match reply is only `[SILENT]`. Hermes then skips the chat message and still saves the output under the profile's `cron/output/` directory. A failed run is still delivered.

```bash
hermes -p cyber-au cron edit cyberau-kev-watch --prompt 'Check new KEV entries and EPSS jumps above 0.5 against the asset inventory in plugin-data/cyber-au/assets.yaml. Report only matches. If nothing matches, reply with only [SILENT].'
```
