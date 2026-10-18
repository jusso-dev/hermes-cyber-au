# Dashboard

`dashboard/server.py` is a read-only web page for one Hermes profile. It uses only the Python standard library, never runs a job, and never calls a feed.

```bash
python3 dashboard/server.py --profile ~/.hermes/profiles/cyber-au
```

Open <http://127.0.0.1:8765/>.

## Pages

| Path | What it shows |
|---|---|
| `/` | Routines, the newest report each wrote, handoffs, conversation snapshots, chat state |
| `/latest/<job>` and `/reports/<job>/<file>` | One routine report |
| `/conversations/<profile>/<session>` | A longer snapshot of one stored conversation |
| `/sources` | Feed freshness and provenance |

## Conversation history

The dashboard reads the selected profile and sibling profiles in the same Hermes installation. A fresh Cyber AU profile can be empty even when another Hermes installation has conversations. Separate containers or data volumes do not share history, and chats in other applications are not imported. Check the profile path shown on the dashboard before treating an empty page as lost history.

## Allowed hosts

The dashboard has no login, so it checks who a request is addressed to. A request is served only when its `Host` header names one of:

- the `--bind` address (unless it is `0.0.0.0` or `::`),
- `localhost`, `127.0.0.1` or `::1`,
- a name given with `--allowed-host NAME` (repeat it) or in `CYBERAU_DASHBOARD_ALLOWED_HOSTS` (comma separated).

The port is not compared, so a Docker port mapping still works. A request that also sends an `Origin` header must name an allowed host there too. Anything else gets `421 Misdirected Request`.

This blocks DNS rebinding: a page on `attacker.example` can point its own name at `127.0.0.1`, but the browser still sends `Host: attacker.example`, so the dashboard refuses it. Every response also carries `frame-ancestors 'none'` and `X-Frame-Options: DENY`, so no other site can frame it.

```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "Host: attacker.example:8765" http://127.0.0.1:8765/
# 421
```

In the container the server binds `0.0.0.0`, so list the address you browse to:

```bash
docker run -d --name cyberau-dashboard -v /path/to/hermes-data:/opt/data:ro \
  -e CYBERAU_DASHBOARD_ALLOWED_HOSTS=192.0.2.10,dashboard.example.com \
  -p 192.0.2.10:8765:8765 cyberau-dashboard
```

Without the variable, a browser on the LAN gets 421. The server prints its allowed hosts when it starts.

## Sources page

`/sources` lists every feed in `feeds/catalogue.yaml`:

| Column | Where it comes from |
|---|---|
| Server | The profile `config.yaml` `mcp_servers` entry: `enabled`, `disabled`, or `not in config` |
| Key | `plugin-data/cyber-au/bootstrap-status.json`, which bootstrap writes with the variables that were unset. The profile `.env` is never opened |
| Last success, Items, Last error | Refresh status JSON (below), the ASD ACSC connector's `feed_status` table, and the intel store |
| Age, State | Time since the last success. `overdue` means older than twice the catalogue `poll` interval |
| Data as of | The newest `data_as_of` from ASD ACSC, else the newest stored row date |
| Cache | ASD ACSC fetch method: `live`, `stale`, `manual` or `snapshot` |
| Licence | The catalogue licence summary |

Refresh status files are read from, in order: every `--feed-status FILE`, else `plugin-data/cyber-au/feed-status.json` and `feeds-status.json`, and `status.json` beside the catalogue (the nightly workflow writes that one). Write one from a profile with:

```bash
cyberau-mcp refresh --sources asd,kev,epss --store \
  --status ~/.hermes/profiles/cyber-au/plugin-data/cyber-au/feed-status.json
```

Other flags: `--catalogue PATH` (default `<profile>/feeds/catalogue.yaml`, then the copy beside the server) and `--data-dir PATH` (default `$CYBERAU_DATA_DIR`, else `<profile>/plugin-data/cyber-au`). Databases are opened read-only.

## Provenance in answers

Skills end each answer with a provenance footer built from the result envelopes: `cyberau-mcp provenance results.json`. See the `references/sources.md` file in each main skill.

Tests: `python3 -m pytest tests/dashboard`.
