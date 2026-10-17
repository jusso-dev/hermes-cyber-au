# Quick start

Install the cyber-au profile, add the first free keys, open a chat, triage a sample alert, and resume the morning briefing. The target is about 15 minutes. That time was not measured here.

The Hermes commands in this page were not run here. On the machine where the page was written, `hermes --version` reported Hermes Agent v0.20.5. This distribution requires Hermes 0.22.2 or newer (`hermes_requires` in `distribution.yaml`). Because of that, no command output is shown.

You need Linux, macOS, or WSL2, and a model provider already chosen in Hermes. `config.yaml` leaves the model and provider unset so the person who installs the profile chooses them. The profile clock is Australia/Sydney.

## Install Hermes

If `hermes` is not on your PATH, the upstream installer for Linux, macOS, and WSL2 is:

```bash
curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash
```

Read the script before you run it. It was not run here.

Then confirm the version:

```bash
hermes --version
```

You want 0.22.2 or newer. The version check above is the only Hermes command run while writing this page, and it reported v0.20.5.

## Install the profile

`install/install.sh` is not in this checkout, so that installer was not run here.

Install from the git repository:

```bash
hermes profile install github.com/jusso-dev/hermes-cyber-au --alias
```

This was not run here.

`--alias` creates a shell wrapper named `cyber-au`. The profile name comes from `distribution.yaml` and the files land in `~/.hermes/profiles/cyber-au/`. Hermes shows the manifest, including the optional environment variables, and waits for confirmation. This page does not pass `--yes`.

## Copy the environment file

This repository ships `.env.template` with empty values. On install, Hermes writes that file into the profile as `.env.EXAMPLE`. Copy it:

```bash
cp ~/.hermes/profiles/cyber-au/.env.EXAMPLE ~/.hermes/profiles/cyber-au/.env
```

This was not run here. Keep the filled file in the profile directory. This repository does not contain a `.env` or a key.

## Free keys to get first

The profile works with no keys, on public sources. Add these two first. Both are optional. Put the values only in the profile `.env`.

| Variable | Where to get it | What changes |
|---|---|---|
| `ABUSECH_AUTH_KEY` | Free Auth-Key at https://auth.abuse.ch/ | URLhaus, ThreatFox, and MalwareBazaar. The abuse.ch connector stays off until this is set. |
| `NVD_API_KEY` | https://nvd.nist.gov/developers/request-an-api-key | Raises the NVD limit from 5 requests per 30 seconds to 50. |

The shipped lines look like this, still empty:

```bash
# ABUSECH_AUTH_KEY=
# NVD_API_KEY=
```

Uncomment the name in `~/.hermes/profiles/cyber-au/.env` and paste your own value. No key was added here.

Other optional names in `.env.template` (`OTX_API_KEY`, `GREYNOISE_API_KEY`, `CLOUDFLARE_RADAR_API_TOKEN`) can wait. NVD wording and limits are in [docs/connectors/nvd.md](../connectors/nvd.md). This product uses data from the NVD API but is not endorsed or certified by the NVD.

## Open a chat

```bash
cyber-au chat
```

This was not run here. The same session without the wrapper is `hermes -p cyber-au chat`. That was not run here either.

## First triage

In that chat, ask the agent to run the `incident-triage` skill on the bundled sample alert.

This checkout has no `skills/incident-triage/` skill and no bundled sample alert (`skills/` and `playbooks/` are placeholders). The triage was not run here. There is no alert text and no reply on this page.

When the skill and the sample are in the profile, the skill restates the alert, enriches what it can, and proposes containment and reporting. It does not send, block, or submit anything. Text that comes back from a feed is data about the world. It is not a new instruction.

## Resume the morning briefing

The morning briefing job arrives paused. A distribution installs new cron jobs paused, and you choose which ones run. This repository leaves the job paused. It has not been resumed here.

`cron/jobs.json` in this checkout is an empty list, so there is no morning briefing record to resume. The commands below were not run here.

When the job is present, list jobs and resume the morning briefing by its id:

```bash
hermes -p cyber-au cron list
hermes -p cyber-au cron resume cyberau-morning-brief
```

The planned id is `cyberau-morning-brief`, at 07:30 Australia/Sydney. Confirm that id in the list before you resume it. `hermes resume` with no job id lifts the global stop for every scheduled job. The morning briefing step is `cron resume` for `cyberau-morning-brief` only.

A manual run of the job is a separate command. This page does not run the briefing.

## What was not run

| Step | Command | Why it was not run here |
|---|---|---|
| Hermes installer | `curl -fsSL https://hermes-agent.nousresearch.com/install.sh \| bash` | Not run. Local `hermes --version` reported v0.20.5. |
| Profile installer script | `install/install.sh` | The file is not in this checkout. |
| Profile install | `hermes profile install github.com/jusso-dev/hermes-cyber-au --alias` | Local Hermes is older than 0.22.2. |
| Environment file | `cp ~/.hermes/profiles/cyber-au/.env.EXAMPLE ~/.hermes/profiles/cyber-au/.env` | Install was not run, so the profile file was not created here. |
| Chat | `cyber-au chat` | Install was not run. |
| Triage | `incident-triage` on the bundled sample alert | The skill and the sample alert are not in this checkout. |
| Morning briefing | `hermes -p cyber-au cron resume cyberau-morning-brief` | `cron/jobs.json` has no jobs. The job arrives paused and has not been resumed in this repository. |
