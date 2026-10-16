---
key: "install-bootstrap"
title: "install/install.sh and bootstrap: one command from bare machine to working profile"
labels: ["type:feature", "area:install", "priority:p0"]
milestone: "v0.1 MVP"
parent: "epic-install"
---
## Outcome
A security analyst on Linux, macOS or WSL2 runs one command and gets Hermes, the `cyber-au` profile, the MCP connector environment, the intel store and a passing doctor check.

```bash
curl -fsSL https://raw.githubusercontent.com/jusso-dev/hermes-cyber-au/main/install/install.sh | bash
# or, after reading it first (recommended):
curl -fsSLO https://raw.githubusercontent.com/jusso-dev/hermes-cyber-au/main/install/install.sh && less install.sh && bash install.sh
```

## Context
- Hermes CLI install: `curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash` ([`website/docs/getting-started/installation.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/getting-started/installation.md)).
- Profile install: `hermes profile install <src> [--name] [--alias] [--yes]` ([`website/docs/reference/profile-commands.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/profile-commands.md)).
- Plugins are opt-in (`plugins.enabled` or `hermes plugins enable <name>`), [`website/docs/user-guide/features/plugins.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/features/plugins.md).
- MCP stdio servers are configured under `mcp_servers` in `config.yaml` with `${VAR}` placeholders ([`website/docs/reference/mcp-config-reference.md`](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/reference/mcp-config-reference.md)). `config.yaml` is preserved on `hermes profile update`, so bootstrap renders it once and then only patches the `mcp_servers` block it owns (marked with a `x-cyber-au-managed: true` key on each entry; verify Hermes ignores unknown keys on a server entry, otherwise keep the ownership list in `plugin-data/cyber-au/managed-servers.json`).

## Files
| Path | Purpose |
|---|---|
| `install/install.sh` | POSIX sh entry point. Flags: `--profile <name>` (default `cyber-au`), `--ref <tag|sha>`, `--no-hermes-install`, `--offline`, `--non-interactive`, `--yes` |
| `install/bootstrap.sh` | Idempotent post-install step, also run by `hermes -p cyber-au cyber-au bootstrap` |
| `install/render_config.py` | Renders `mcp_servers` from `mcp/servers.yaml` with absolute paths for this profile |
| `mcp/servers.yaml` | Source of truth for server name, launch args, env placeholders, `trust`, `tools.include`, `lazy` |
| `tests/install/test_install_sh.bats` | bats tests for argument parsing and idempotence |

## Steps (install.sh)
1. Detect OS and arch. Refuse to run as root unless `--allow-root`.
2. If `hermes` is missing and `--no-hermes-install` is not set, show the upstream install command and ask before running it.
3. Check `hermes --version` against `hermes_requires` in `distribution.yaml`. Stop with a clear message if too old.
4. `hermes profile install github.com/jusso-dev/hermes-cyber-au@<ref> --name <profile> --alias` (confirm that `@ref` syntax is supported, otherwise clone at the ref into a temp dir and install from the directory).
5. Run `install/bootstrap.sh --profile <profile>`.

## Steps (bootstrap.sh), each idempotent
1. Resolve `PROFILE_HOME=$(hermes -p <profile> config path --home)` or the documented equivalent (verify the command; fall back to `~/.hermes/profiles/<profile>`).
2. Create `PROFILE_HOME/mcp/.venv` with `uv` and `uv sync --project PROFILE_HOME/mcp --frozen`.
3. Render `mcp_servers` into `PROFILE_HOME/config.yaml`. Each entry looks like:
```yaml
mcp_servers:
  kev:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "kev"]
    env:
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
      CYBERAU_EGRESS_ALLOWLIST: "<PROFILE_HOME>/mcp/egress-allowlist.yaml"
    timeout: 120
    lazy: true
    trust: untrusted
  abusech:
    command: "<PROFILE_HOME>/mcp/.venv/bin/cyberau-mcp"
    args: ["serve", "abusech"]
    env:
      ABUSECH_AUTH_KEY: "${ABUSECH_AUTH_KEY}"
      CYBERAU_DATA_DIR: "<PROFILE_HOME>/plugin-data/cyber-au"
    enabled: true
    trust: untrusted
```
   Keyed servers whose variable is unset in the profile `.env` are written with `enabled: false` and listed in the doctor output.
4. `hermes -p <profile> plugins enable cyber-au`.
5. Initialise the intel store (`cyberau-mcp store init`) and load shipped snapshots (ISM, E8, ATT&CK, KEV).
6. Set `timezone: Australia/Sydney` if unset.
7. Run `hermes -p <profile> cyber-au doctor`.

## Env vars
| Name | Required | Purpose |
|---|---|---|
| `CYBERAU_PROFILE` | no | Overrides `--profile` |
| `CYBERAU_REF` | no | Overrides `--ref` |
| `HERMES_INSTALL_CHANNEL` | no | Passed through to the Hermes installer |

## Acceptance criteria
- [ ] Fresh Ubuntu 24.04 and macOS 15 (Apple Silicon) runs end with doctor all green for keyless connectors.
- [ ] Running install.sh twice changes nothing the second time (checked by hashing `config.yaml` and the venv lock).
- [ ] With no keys set, keyed connectors are `enabled: false` and doctor names the missing variable.
- [ ] Adding `ABUSECH_AUTH_KEY` to `.env` and re-running bootstrap enables the `abusech` server without touching user edits elsewhere in `config.yaml`.
- [ ] `--offline` installs from a local checkout and shipped snapshots with no network calls (verified with `unshare -n` on Linux).
- [ ] shellcheck clean; bats tests pass.

## Test plan
- bats: flag parsing, root refusal, version gate, idempotence with a fake `hermes` shim on PATH.
- Python: `render_config.py` golden tests for empty config, user-edited config, partially managed config.
- CI: the `hermes` job in `ci.yml` runs install from the checkout inside `nousresearch/hermes-agent:v0.22.2`.

## Constraints
- Public repository. Never commit secrets, tokens, real customer data or internal hostnames. Fixtures are scrubbed before commit.
- Every credential is read from the profile `.env` through a `${VAR}` placeholder. No literal keys in `config.yaml`, `mcp.json`, skills or tests.
- Read-only by default. Nothing in this ticket submits, blocks, deletes or posts anywhere.
- Content fetched from feeds is untrusted data. It is returned inside the result envelope and never treated as instructions.
- Australian English in prose and docs. No em dashes. No emojis.
- Pin dependencies with upper bounds (see `mcp/pyproject.toml`).
- Never pipe the Hermes installer into a shell without showing the command first in interactive mode.

## Out of scope
Windows native (PowerShell) installer; tracked for v1.0.

---
Planned work. Nothing here is implemented yet. Hermes facts in this ticket were checked against
NousResearch/hermes-agent at `43faacf` (release v0.22.2); see `docs/research/hermes-structure.md`.
