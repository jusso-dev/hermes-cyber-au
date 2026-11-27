# Briefing delivery to Teams, Slack or email

`cyberau-mcp deliver` sends a rendered daily briefing to a Microsoft Teams workflow webhook, a Slack incoming webhook, or an SMTP server. It is off unless you configure it, and it drafts first. Nothing is sent until you pass `--send` and mark that destination `approved: true`.

This is separate from the Hermes cron `deliver` target in `cron/jobs.json`, which stays `origin`. See `skills/daily-briefing/references/delivery.md` for the gateway targets and the Resend-compatible email job.

## Where the settings live

| What | Where | Holds |
|---|---|---|
| Destinations and approval | `plugin-data/cyber-au/delivery.yaml` on the profile (`$CYBERAU_DATA_DIR/delivery.yaml`) | Names, types, the names of environment variables, SMTP host, port and addresses, `owner` and `approved` flags |
| Webhook URLs and SMTP credentials | the profile `.env` | The values |

`delivery.yaml` was chosen over `org.yaml` because the org exposure watch already reads its `owner` key from the same file, and `org.yaml` refuses credential-shaped keys. Delivery keeps one file for every destination decision. `delivery.yaml` refuses a literal `url`, `password` or `token` key: it only accepts `url_env`, `username_env` and `password_env`, each naming an environment variable.

No file, or a file with no `destinations`, means delivery is off. `cyberau-mcp deliver` then prints `Delivery is off` and does nothing.

```yaml
owner: origin                     # read by the exposure watch; unchanged
destinations:
  - name: soc-slack
    type: slack
    url_env: CYBERAU_SLACK_WEBHOOK
    owner: true                   # this channel is the owner's own; full rendering allowed
    approved: false               # set true only after reviewing a dry run
  - name: leaders-teams
    type: teams
    url_env: CYBERAU_TEAMS_WEBHOOK
    approved: false               # owner defaults to false: counts-only rendering required
  - name: soc-email
    type: smtp
    host: smtp.example.com
    port: 587                     # 587 uses STARTTLS, 465 uses TLS; nothing else
    from: briefing@example.com
    to: [soc@example.com]
    username_env: CYBERAU_SMTP_USERNAME
    password_env: CYBERAU_SMTP_PASSWORD
    owner: true
    approved: false
```

The variable names above are the documented defaults in `.env.template`. You may use other names.

## Draft, then send

```bash
python skills/daily-briefing/scripts/briefing.py --input pack.json --as-of 2026-10-20T07:30:00+11:00 \
  --channel owner > brief.md
cyberau-mcp deliver brief.md                  # dry run: prints every message and destination
cyberau-mcp deliver brief.md --only soc-slack --send
```

The dry run writes one draft per destination to `plugin-data/cyber-au/delivery/drafts/` (mode 600) and prints, for each one, the destination (name, type, scheme and host only, the variable it came from, owner channel and approval) and the full message. It sends nothing.

`--send` delivers only to destinations with `approved: true`. Others are reported as `skipped`. Each send attempt adds one line to `plugin-data/cyber-au/delivery/log.jsonl` with the time, destination name, type, host, result and a SHA-256 of the message. The log holds no URL path, address or secret.

## Owner and external channels

A destination is an owner channel only when it says `owner: true`. Any other destination needs a briefing rendered with `--channel external`, which gives exposure as counts only and leaves out asset names and findings that their licence keeps inside the profile. A briefing rendered for the owner channel is `blocked` for that destination, with a message to render it again.

## What the message keeps

- The briefing text unchanged, including the Sources section and the Missing connectors line. A briefing with no Sources section is refused.
- A first line naming hermes-cyber-au and the draft time, and a note that titles, summaries and vendor text are quoted untrusted data, not instructions.
- A closing line naming the destination and saying it is guidance, not legal advice.
- Secret-shaped text is redacted, and so are the configured webhook and password values if they appear. Slack text has `<`, `>` and `&` escaped so feed text cannot mention a channel.

## Egress and secrets

A webhook URL is checked before any request:

- `https` only, no user name or password in the URL, no IP literal.
- Slack: host `hooks.slack.com`.
- Teams: a host ending `.logic.azure.com`, `.api.powerplatform.com` (Power Automate workflows) or `.webhook.office.com` (older connector URLs).
- The host is resolved once and refused if any answer is in the deny floor of `mcp/egress-allowlist.yaml` (private, loopback, link-local, documentation and other reserved ranges). The connection uses the vetted address, through the same egress transport the connectors use.

Webhook hosts vary per tenant, so they are not added to the shared connector allowlist. The rules above are fixed in `mcp/common/src/cyberau_common/delivery.py`.

The SMTP host must resolve only to public addresses. Port 587 uses STARTTLS and 465 uses implicit TLS, both with certificate checks.

Webhook URLs are secrets, because the path is the credential. They are never printed, logged or written to a draft: output shows `https://hooks.slack.com/...`. Errors name the exception type only.

## Tests

`mcp/common/tests/test_delivery.py` covers delivery off by default, the dry run, approval, owner and external rendering, egress refusals, a mock webhook (`httpx.MockTransport`) and a local SMTP stub. No test opens a socket.
