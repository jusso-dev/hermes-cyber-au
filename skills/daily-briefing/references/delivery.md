# Delivery

The shipped job `cyberau-morning-brief` keeps `deliver: origin`. That is the owner channel: the first home channel configured for the profile. `local` (saved on this machine) is also an owner channel. Pause and resume behaviour is unchanged. This file does not store a webhook URL, a chat id, or an email address.

Set any other target on the installed profile after the job is resumed. Do not put that target in `cron/jobs.json`.

Hermes v0.22.2 (commit `43faacf`) gateway targets include:

| Target | Where it goes |
|---|---|
| `slack` | Slack home channel |
| `email` | Email home channel |
| `telegram` | Telegram home channel |

```bash
hermes -p cyber-au cron edit cyberau-morning-brief --deliver slack
```

Microsoft Teams is not a delivery target in that Hermes version. This repository does not invent a Teams target.

A Telegram or Slack chat id, when you need one, belongs in the profile you edit locally. The Hermes form is `telegram:<chat>` and `slack` for the home channel. Do not commit the id.

If the deliver value includes anything other than `origin` or `local`, render with `--channel external`. Exposure outside the owner channel is counts only.
