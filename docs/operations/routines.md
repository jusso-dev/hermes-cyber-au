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

The commands below were run against Hermes Agent v0.22.2. Each output is what that command printed.

## Turn a routine on

Jobs do nothing until you resume the ones you want:

```bash
hermes -p cyber-au cron list
hermes -p cyber-au cron resume cyberau-morning-brief
hermes -p cyber-au cron run cyberau-morning-brief
```

`hermes -p cyber-au cron list` on a fresh install:

```text

┌─────────────────────────────────────────────────────────────────────────┐
│                         Scheduled Jobs (profile: cyber-au)              │
└─────────────────────────────────────────────────────────────────────────┘

  cyberau-ingest-public [paused]
    Name:      Ingest public feeds
    Schedule:  every 60m
    Repeat:    ∞
    Next run:  None
    Deliver:   local
    Script:    cyberau_ingest.sh
    Mode:      no-agent (script stdout delivered directly)

  cyberau-morning-brief [paused]
    Name:      Morning cyber briefing (AU)
    Schedule:  30 7 * * *
    Repeat:    ∞
    Next run:  None
    Deliver:   origin
    Skills:    acsc-advisory-digest, vuln-prioritisation, executive-briefing

  cyberau-kev-watch [paused]
    Name:      KEV and EPSS watch for my assets
    Schedule:  every 360m
    Repeat:    ∞
    Next run:  None
    Deliver:   origin
    Skills:    vuln-prioritisation

  cyberau-weekly-exec [paused]
    Name:      Weekly executive summary
    Schedule:  0 8 * * 1
    Repeat:    ∞
    Next run:  None
    Deliver:   origin
    Skills:    executive-briefing

  cyberau-store-maintenance [paused]
    Name:      Store vacuum and backup
    Schedule:  0 3 * * 0
    Repeat:    ∞
    Next run:  None
    Deliver:   local
    Script:    cyberau_store_maintenance.sh
    Mode:      no-agent (script stdout delivered directly)

  ⚠  Scheduler is not ready for profile 'cyber-au': no gateway serves it and no fresh ticker heartbeat.
     If no gateway is running: hermes gateway install
                    sudo hermes gateway install --system  # Linux servers
     Check status:  hermes cron status
```

The warning means a scheduled fire waits until a gateway is running for the profile. `hermes -p cyber-au cron run` still starts the job immediately.

`hermes -p cyber-au cron resume cyberau-morning-brief`:

```text
Resumed job: Morning cyber briefing (AU) (cyberau-morning-brief)
  Next run: 2026-10-18T07:30:00+11:00
```

The `+11:00` offset is `timezone: Australia/Sydney` in `config.yaml`, on the date of this run. Change that `timezone:` value when the whole profile should keep a different clock. Every cron expression follows it.

`hermes -p cyber-au cron run cyberau-morning-brief`:

```text
Triggered job: Morning cyber briefing (AU) (cyberau-morning-brief)
  Next run: 2026-10-18T07:30:00+11:00
  Ran now: failed.
```

The run failed because the profile has no model configured. The list at the end of this page prints the error text.

## Stop every routine

`hermes pause` and `hermes resume` are the global stop. They hold every scheduled fire for the profile you select, and they leave each job's own paused flag as it is. For this profile:

```bash
hermes -p cyber-au pause
hermes -p cyber-au resume
```

`hermes -p cyber-au pause`:

```text
⏸️  Hermes paused
    sentinel: /tmp/hermes-cyberau-lab/profiles/cyber-au/ESTOP
    Cron dispatch, kanban dispatch, and new gateway turns are on hold.
    In-flight work keeps running. Run `hermes resume` to lift the pause.
```

The sentinel path is the profile directory for the session that produced this transcript. On your machine the same line prints your cyber-au profile path. Pass `-p cyber-au` on `hermes resume` as well. Without `-p`, the stop applies to the default profile.

A manual run still starts while the global stop is held. `hermes -p cyber-au cron run cyberau-morning-brief` during the pause:

```text
Triggered job: Morning cyber briefing (AU) (cyberau-morning-brief)
  Next run: 2026-10-18T07:30:00+11:00
  Ran now: failed.
```

`hermes -p cyber-au resume`:

```text
▶️  Hermes resumed - dispatch picks up on the next tick.
```

They do not rewrite each job's own paused flag.

## Pause one job

`hermes -p cyber-au cron pause cyberau-morning-brief` pauses that job again:

```text
Paused job: Morning cyber briefing (AU) (cyberau-morning-brief)
```

A paused job stays paused until you resume it. `hermes -p cyber-au cron run cyberau-morning-brief` then prints:

```text
Triggered job: Morning cyber briefing (AU) (cyberau-morning-brief)
  Next run: 2026-10-18T07:30:00+11:00
  Job is paused/disabled; resume it before running.
```

## Change the time

Edit the schedule on your profile. The shipped file in this repository keeps `30 7 * * *`.

```bash
hermes -p cyber-au cron edit cyberau-morning-brief --schedule "45 7 * * *"
```

```text
Updated job: cyberau-morning-brief
  Name: Morning cyber briefing (AU)
  Schedule: 45 7 * * *
  Skills: acsc-advisory-digest, vuln-prioritisation, executive-briefing
```

Resume the job so the next fire uses the new expression. With `timezone: Australia/Sydney`, `45 7 * * *` is 07:45.

```text
Resumed job: Morning cyber briefing (AU) (cyberau-morning-brief)
  Next run: 2026-10-18T07:45:00+11:00
```

That resume command is the same `hermes -p cyber-au cron resume cyberau-morning-brief` as above. Use a cron expression such as `30 7 * * *` or `0 8 * * 1`. Hermes does not accept `every 1d at 07:30`.

To leave the night alone, put the hour you want in the expression. The hour is Sydney time because it follows `timezone:`.

## Delivery

Shipped delivery is `origin` or `local` (saved on this machine). A shipped job has no recorded origin chat, so `origin` sends to the first home channel you have configured for the profile. If none is configured, Hermes skips delivery and keeps the output in the job's last output, which `hermes -p cyber-au cron list` shows. This repository does not store a person, an email address, a chat id, or a webhook URL. The Slack, email, and Telegram targets, and the reason Microsoft Teams is not listed, are under Morning briefing below. Set any extra target on your own profile with `hermes cron edit <id> --deliver <target>` after you have resumed the job. Do not put that target in the shipped file.

Keep webhook URLs out of the job and out of this repository.

`local` writes the output under the profile's `cron/output/` directory. `origin` is the success target on the morning, KEV, and weekly jobs. To keep a job on this machine, set `local` on the profile:

```bash
hermes -p cyber-au cron edit cyberau-weekly-exec --deliver local
```

```text
Updated job: cyberau-weekly-exec
  Name: Weekly executive summary
  Schedule: 0 8 * * 1
  Skills: executive-briefing
```

The edit command prints the name, schedule, and skills. `hermes -p cyber-au cron list` prints the new target on the `Deliver:` line. After this edit the weekly job shows `Deliver: local`.

## Failures

Shipped jobs do not set `failure_deliver`, so a failure is sent the same way as a success. For an `origin` job with no recorded origin chat, that is the first configured home channel, or the job's last output when no home channel is configured.

Point failure notices at `local` when they should stay on this machine. Successes keep the job's `deliver` value.

```bash
hermes -p cyber-au cron edit cyberau-kev-watch --failure-deliver local
```

```text
Updated job: cyberau-kev-watch
  Name: KEV and EPSS watch for my assets
  Schedule: every 360m
  Skills: vuln-prioritisation
```

`cron list` still shows `Deliver: origin` for that job. `Deliver` is the success target. The failure override stays on the job.

An empty value clears the override, and failures follow `deliver` again:

```bash
hermes -p cyber-au cron edit cyberau-kev-watch --failure-deliver ''
```

```text
Updated job: cyberau-kev-watch
  Name: KEV and EPSS watch for my assets
  Schedule: every 360m
  Skills: vuln-prioritisation
```

Each recurring job counts consecutive failed runs. From the second failure in a row, `cron list` adds that count to the last-run line. A delivery problem does not increase the count. The next successful run clears it.

When the count reaches `cron.failure_nudge_threshold` in `config.yaml` (default 3), the failure message Hermes delivers asks you to fix the job or pause it. Set the threshold to 0 to leave that sentence out. The two morning-brief runs on this page (the first `cron run`, and the same command during the global stop) are why the check list at the end of this page says `2 failures in a row`.

`[SILENT]` applies to a successful run. A failed run is still delivered, unless `failure_deliver` is `local`, in which case the notice stays on this machine and `cron list` still shows the error.

## Scripts

`cyberau-ingest-public` and `cyberau-store-maintenance` set `no_agent` and name a script. Hermes resolves that name inside `$HERMES_HOME/scripts/` and runs it with a sanitised environment, so provider credentials are not inherited. The ingest script does not open the profile `.env`. Keyed feeds run inside the agent jobs, where each MCP server receives its keys from `mcp_servers.*.env`.

These scripts call `cyberau-mcp refresh` and `cyberau-mcp store`, which the shared library does not implement yet (it exits with `refresh is not part of the shared library yet`). Until the connector and store tickets land, a resumed script job reports that failure line and changes nothing.

Ingest refreshes the keyless sources `asd`, `kev`, `epss`, `auscert`, and `feodo`. Store maintenance runs `cyberau-mcp store backup`, then `store compact` (retention compaction), then `store vacuum`. Each script prints one line on success and one short line on failure. That line is what Hermes delivers.

## Morning briefing

`cyberau-morning-brief` follows `skills/daily-briefing/references/format.md`. The window is 72 hours on Monday and 24 hours on every other day, in Australia/Sydney. The default briefing is under 600 words. An analyst can ask for `detail: full`.

The asset inventory is `plugin-data/cyber-au/assets.yaml` on the profile. That file is yours. It is not in this repository. Matching is described in `skills/daily-briefing/references/matching.md`.

Shipped delivery stays `origin`, the owner channel. `local` is also treated as the owner channel. Those renderings name matching assets. If the deliver value includes any other target, the briefing reports exposure as counts only.

Hermes v0.22.2 can send the job to these gateway targets:

| Target | Where it goes |
|---|---|
| `slack` | Slack home channel |
| `email` | Email home channel |
| `telegram` | Telegram home channel |

```bash
hermes -p cyber-au cron edit cyberau-morning-brief --deliver slack
```

Microsoft Teams is not a delivery target in that Hermes version, so this repository does not list one. Do not store a webhook URL, a chat id, or an email address here. A chat id, if you use one, stays on the profile you edit locally.

## Quiet hours

`cyberau-kev-watch` replies with the single word NOTHING when no asset matches. Hermes delivers that word.

To suppress delivery when there is nothing to report, change the prompt so the no-match reply is only `[SILENT]`. Hermes then skips the chat message and still saves the output under the profile's `cron/output/` directory. A failed run is still delivered.

That is how you set quiet hours for a routine. A successful reply of only `[SILENT]` does not ping the channel, including through the night if the check still runs.

To stop the job from running in those hours, it needs a cron schedule. `cyberau-kev-watch` ships as `every 360m`, an interval, and an interval cannot exclude hours. Replace it with a cron expression that lists only the hours you want. The hours follow `timezone: Australia/Sydney`. For example, to check at 08:00, 14:00, and 20:00 and stay quiet overnight:

```bash
hermes -p cyber-au cron edit cyberau-kev-watch --schedule "0 8,14,20 * * *"
```

Jobs that already use a cron expression, such as `cyberau-morning-brief`, only need the hour changed as in "Change the time".

```bash
hermes -p cyber-au cron edit cyberau-kev-watch --prompt 'Check new KEV entries and EPSS jumps above 0.5 against the asset inventory in plugin-data/cyber-au/assets.yaml. Report only matches. If nothing matches, reply with only [SILENT].'
```

```text
Updated job: cyberau-kev-watch
  Name: KEV and EPSS watch for my assets
  Schedule: every 360m
  Skills: vuln-prioritisation
```

## Check the jobs

After the schedule change, the weekly `local` delivery, and the KEV failure override (before the empty `--failure-deliver` clear), `hermes -p cyber-au cron list` printed:

```text

┌─────────────────────────────────────────────────────────────────────────┐
│                         Scheduled Jobs (profile: cyber-au)              │
└─────────────────────────────────────────────────────────────────────────┘

  cyberau-ingest-public [paused]
    Name:      Ingest public feeds
    Schedule:  every 60m
    Repeat:    ∞
    Next run:  None
    Deliver:   local
    Script:    cyberau_ingest.sh
    Mode:      no-agent (script stdout delivered directly)

  cyberau-morning-brief [active]
    Name:      Morning cyber briefing (AU)
    Schedule:  45 7 * * *
    Repeat:    ∞
    Next run:  2026-10-18T07:45:00+11:00
    Deliver:   origin
    Skills:    acsc-advisory-digest, vuln-prioritisation, executive-briefing
    Last run:  2026-10-17T15:27:23.778129+11:00  error: RuntimeError: Cron job 'Morning cyber briefing (AU)' has no model configured (job.model=None, HERMES_MODEL='', config.yaml model.default missing or empty). Set a per-job model via `hermes cron edit cyberau-morning-brief --model <name>` or set a default with `hermes model <name>`.  (2 failures in a row)
    Execution: failed  7a71754efacf4ba9bbfbdacf946c051d
    ⚠ Last failure at 2026-10-17T15:27:23.778129+11:00: RuntimeError: Cron job 'Morning cyber briefing (AU)' has no model configured (job.model=None, HERMES_MODEL='', config.y…

  cyberau-kev-watch [paused]
    Name:      KEV and EPSS watch for my assets
    Schedule:  every 360m
    Repeat:    ∞
    Next run:  None
    Deliver:   origin
    Skills:    vuln-prioritisation

  cyberau-weekly-exec [paused]
    Name:      Weekly executive summary
    Schedule:  0 8 * * 1
    Repeat:    ∞
    Next run:  None
    Deliver:   local
    Skills:    executive-briefing

  cyberau-store-maintenance [paused]
    Name:      Store vacuum and backup
    Schedule:  0 3 * * 0
    Repeat:    ∞
    Next run:  None
    Deliver:   local
    Script:    cyberau_store_maintenance.sh
    Mode:      no-agent (script stdout delivered directly)

  ⚠  Scheduler is not ready for profile 'cyber-au': no gateway serves it and no fresh ticker heartbeat.
     If no gateway is running: hermes gateway install
                    sudo hermes gateway install --system  # Linux servers
     Check status:  hermes cron status
```
