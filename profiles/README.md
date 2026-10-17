# Organisation profiles

Hermes installs one home from a distribution. `hermes profile install` copies this repository into a single profile directory (`~/.hermes/profiles/<name>/`) with one `SOUL.md`, one `cron/jobs.json`, and one `.env`. It cannot install the watcher, analyst, skeptic, briefer, and librarian as five homes in one step. That limit is in the Hermes profile distribution installer (checked against NousResearch/hermes-agent `43faacf`, the `v0.22.2` notes in `docs/research/hermes-structure.md`).

These five roles are overlays. Install the distribution once per role, then apply that role's overlay onto the new home. Apply again after `hermes profile update`, because an update replaces the distribution-owned `SOUL.md` and merges `cron/jobs.json`.

```bash
hermes profile install /path/to/hermes-cyber-au --name watcher --yes
uv run --directory /path/to/hermes-cyber-au/mcp \
  python -m cyberau_hindsight.profiles \
  --role watcher \
  --home ~/.hermes/profiles/watcher
```

Repeat with `--name` and `--role` set to `analyst`, `skeptic`, `briefer`, and `librarian`.

Applying an overlay copies that role's `SOUL.md`, paused cron job, and env example into the home. It writes the role name to `plugin-data/cyber-au/profile-role`. It does not edit a git checkout, and it does not create or change skills. Copy `.env.EXAMPLE` to `.env` yourself. No host and no API key are filled in.

## What each role does

| Role | Connector keys | Hindsight | Scheduled delivery | Handoff step |
|---|---|---|---|---|
| watcher | yes, the only role | retain and recall | local, paused | posts |
| analyst | no | recall only | local, paused | claims |
| skeptic | no | recall only | local, paused | answers |
| briefer | no | recall only | origin (the owner), paused | drafts |
| librarian | no | retain and recall | local, paused | none |

The briefer is the only role whose job may deliver to the owner. Every job ships with `paused: true` and `enabled: false`. Hermes also pauses jobs that arrive through a distribution install. Nothing sends mail, Slack, or a message to a regulator.

## Memory

`memories/MEMORY.md` stays inside each home. It is a small frozen snapshot and it is not shared. Shared memory is Hindsight, using the banks `org`, `intel`, and `lessons`. This slice implements retain and recall. It does not implement reflect.

The client is the `hindsight` MCP server under `mcp/hindsight`. It stays off until `HINDSIGHT_BASE_URL` is set. The API key is `HINDSIGHT_API_KEY` from the environment. Read-only profiles set `HINDSIGHT_READ_ONLY=1`, which blocks retain. The flag is not the only gate. Retain also needs `CYBERAU_PROFILE_ROLE` to be `watcher` or `librarian`, so a missing flag, a missing role, or an unknown role cannot retain. When Hermes passes `HERMES_HOME`, a role that differs from the one in `plugin-data/cyber-au/profile-role` is refused too. Only the librarian may mark a memory confirmed. The base URL must be https. The host is resolved before every request, and private, loopback, link-local, multicast, reserved, IPv4-mapped, and 6to4 addresses are refused, so a Hindsight server on loopback or a private network is not supported. Recall text is wrapped as untrusted data unless the bank is `org` and the record is marked confirmed.

## Handoffs

Handoffs are a JSONL queue at `$CYBERAU_DATA_DIR/handoffs.jsonl`. Each record has a claim, sources, confidence, TLP marking, and `untrusted: true`. The watcher posts, the analyst claims, the skeptic answers, and the briefer drafts. Feed text is stored as those fields. It is not copied into a prompt. A handoff is data. A later step may raise the TLP marking but may not lower it. The file is created with mode 0600, and secret-shaped values are redacted before they are written.
