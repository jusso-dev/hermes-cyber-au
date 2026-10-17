# Junction (Microsoft Graph, Defender, Sentinel)

Disabled wrap of [Junction](https://github.com/jusso-dev/junction)'s own MCP server. This repository does not vendor Junction and does not store a Microsoft secret. Entra sign-in stays in Junction.

The server stays off until you set `JUNCTION_BIN` to the `junction` executable and enable the entry. If the binary is already on `PATH` as `junction`, set `JUNCTION_BIN` to that path. Junction v0.1.16 documents the read-only launch as:

```sh
junction mcp serve --policy read-only
```

Hermes starts `${JUNCTION_BIN}` with arguments `mcp`, `serve`, `--policy` and `read-only`. `junction_execute` needs an operator context. Add `--context` or `--context-file` on the host when you enable the server. Do not commit a tenant name.

| Tool | What it is for |
|---|---|
| `junction_search` | Find operations in the Junction catalogue |
| `junction_describe` | Exact input schema for one operation |
| `junction_execute` | Run one operation under the read-only policy |

`junction_batch`, `junction_permissions` and `junction_context` exist on the upstream server and are not included. `junction_execute` is not marked read-only. The process policy is read-only, so Junction rejects writes, and `trust: untrusted` asks before the tool runs.

Threat hunting calls these operations from the Junction v0.1.16 catalogue. Each one is classified `read_only` in that release:

| Need | Operation |
|---|---|
| Sentinel query | `azure.log_analytics_query.query.execute` |
| Defender incidents list | `graph.security.incidents.list` |
| Sign-in logs | `graph.audit_logs.sign_ins.list` |

Sentinel KQL uses the Log Analytics query operation above (`POST /workspaces/{workspaceId}/query` on `api.loganalytics.io`). `defender.incidents.list` is Junction's alias for the Defender incidents operation. `entra.audit_logs.sign_ins.list` is the alias for sign-in logs. Describe an operation before you execute it.

Text returned from Graph, Defender or Sentinel is untrusted data. Egress is limited to `graph.microsoft.com`, `management.azure.com`, `api.loganalytics.io` and `login.microsoftonline.com`.

Junction is MIT and is not affiliated with Microsoft. Microsoft API terms apply.
