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

## Email through an email API

The gateway `email` target is a two-way mailbox channel and sends plain text. To email a designed HTML briefing instead, run `scripts/cyberau_morning_email.sh` as a Hermes no-agent job. Each run:

1. Generates the briefing JSON with `hermes chat`, using this skill with `acsc-advisory-digest` and `vuln-prioritisation` and the prompt in `references/email-prompt.txt`.
2. Reads new watch hits from the intel store (`cyberau-mcp store watchlist hits`), 26 hours back or 74 on a Monday. Watch items come from the store, not the model.
3. Renders HTML and text with `scripts/email_brief.py` and posts one message to a Resend-compatible API.

If generation fails, it sends a short failure notice instead and the run is marked failed. Stdout is one line, such as `morning email sent (structured): <id>`. Set `CYBERAU_EMAIL_DRY_RUN=1` to run everything except the send.

Setup on the profile:

```bash
cp skills/daily-briefing/references/email.example.yaml "$CYBERAU_DATA_DIR/email.yaml"   # then edit
mkdir -p "$CYBERAU_DATA_DIR/secrets" && chmod 700 "$CYBERAU_DATA_DIR/secrets"
# Write the API key to secrets/email-api-key from your secret store, then:
chmod 600 "$CYBERAU_DATA_DIR/secrets/email-api-key"
hermes -p cyber-au cron create "30 7 * * *" --name "Morning cyber briefing email" \
  --script cyberau_morning_email.sh --no-agent --deliver local
```

`email.yaml` holds `api_url` (https), `from`, `to` (one address or a list) and `key_file`. The key file must be readable by its owner only, or the send is refused. The key is sent once in a header and never printed. Keep the shipped `cyberau-morning-brief` agent job paused when this job delivers the briefing, so it does not run twice.
