# Hermes Agent structure: verified notes

These notes back every ticket in this repository. Each fact was checked against the
NousResearch/hermes-agent source and docs at commit `43faacfb8de7b29548547a7fbdedad0cc6e7391c`
(16 October 2026), which sits just after release `v0.22.2` (published 15 October 2026).
Paths are relative to https://github.com/NousResearch/hermes-agent. Re-check them when
the pinned Hermes version moves (see the Hermes bump workflow ticket).

If a ticket says "verify", the behaviour was not confirmed in source and must be tested
before code depends on it.

## Install and update

| Fact | Source |
|---|---|
| CLI install on Linux, macOS and WSL2: `curl -fsSL https://hermes-agent.nousresearch.com/install.sh \| bash`. Windows: `install.ps1`. | `website/docs/getting-started/installation.md` |
| The source installer clones the repo, bootstraps `uv` and lands on the latest stable release. `hermes update` follows that channel. `--channel main` or `HERMES_INSTALL_CHANNEL=main` tracks `main`. | `website/docs/getting-started/installation.md`, `website/docs/getting-started/updating.md` |
| `hermes update --check`, `hermes update --set-channel stable\|main`. | `website/docs/getting-started/updating.md` |
| Docker image `nousresearch/hermes-agent`, tags include `v0.22.2`, `stable` and `latest`. Docker installs do not support `hermes update`; you run a new image. Entrypoint is `/opt/hermes/docker/entrypoint-dispatch.sh`, so `docker run nousresearch/hermes-agent <subcommand>` runs a Hermes subcommand. | `website/docs/user-guide/docker.md`, `website/docs/getting-started/platform-support.md`, `Dockerfile`, Docker Hub tag list |

## Profiles

| Fact | Source |
|---|---|
| A profile is a separate Hermes home under `~/.hermes/profiles/<name>/` with its own `config.yaml`, `.env`, `SOUL.md`, memories, sessions, skills, cron jobs and state database. Select it with `hermes -p <name>` or an alias. | `website/docs/user-guide/profiles.md` |
| `timezone:` in `config.yaml` (IANA name) or `HERMES_TIMEZONE` sets the zone for cron scheduling and the prompt clock. | `website/docs/user-guide/configuration.md`, `hermes_time.py` |

## Profile distributions (how a "distribution" is packaged)

| Fact | Source |
|---|---|
| A distribution is a git repo with `distribution.yaml` at the root. Only `name` is required. Other fields: `version`, `description`, `hermes_requires`, `author`, `license`, `env_requires` (list of `name`, `description`, `required`, `default`) and `distribution_owned`. | `website/docs/user-guide/profile-distributions.md`, `hermes_cli/profile_distribution.py` (`DistributionManifest`, `EnvRequirement`) |
| Install: `hermes profile install <git-url-or-dir> [--name <n>] [--alias] [--force] [--yes]`. Update: `hermes profile update <name> [--force-config] [--yes]`. Inspect: `hermes profile info <name>`. | `website/docs/reference/profile-commands.md` |
| Default distribution-owned paths: `SOUL.md`, `config.yaml`, `mcp.json`, `skills`, `cron`, `distribution.yaml`. | `hermes_cli/profile_distribution.py` (`DEFAULT_DIST_OWNED`) |
| With no `distribution_owned` list, the whole repo payload (minus user-owned paths) is copied. With a list, exactly those paths are copied. | `hermes_cli/profile_distribution.py` (`_owned_entries`) |
| Never copied: credential stores, `memories`, `sessions`, `plans`, `workspace`, `home`, `backups`, `cache`, `local`, `logs`, `state.db*`, `*_cache`. Do not name a shipped directory `cache/`. | `hermes_cli/profile_distribution.py` (`USER_OWNED_EXCLUDE`), `profile-distributions.md` |
| `config.yaml` is preserved on update unless `--force-config`. | `profile-distributions.md`, `_copy_dist_payload` |
| `.env.template` lands as `.env.EXAMPLE`; otherwise `.env.EXAMPLE` is generated from `env_requires`. | `_copy_dist_payload`, `ENV_TEMPLATE_FILENAME` |
| Only `cron/jobs.json` ships for cron. It merges by job id, and new jobs arrive paused. | `profile-distributions.md`, `cron/job_definition.py` |
| A distribution's `SOUL.md` is scanned for prompt-injection patterns, and a hit blocks it. Security guidance in SOUL must not quote attack phrases verbatim. | `website/docs/user-guide/security.md` ("Context File Injection Protection") |
| Distributions are unsigned. `.git/` is stripped after clone. Reserved names: `hermes`, `test`, `tmp`, `root`, `sudo`. | `profile-distributions.md` |

## Skills

| Fact | Source |
|---|---|
| A skill is a directory with `SKILL.md` plus optional `scripts/` and `references/`. | `website/docs/developer-guide/creating-skills.md` |
| Frontmatter: `name`, `description`, `version`, `author`, `license`, `platforms`, `metadata.hermes.{tags, related_skills, requires_toolsets, requires_tools, fallback_for_toolsets, fallback_for_tools, config, blueprint}`, `required_environment_variables` (`name`, `prompt`, `help`, `required_for`). | `creating-skills.md` |
| Recommended body sections: When to Use, Quick Reference, Procedure, Pitfalls, Verification. | `creating-skills.md` |
| `metadata.hermes.blueprint` (`schedule`, `deliver`, `prompt`, `no_agent`) marks a skill as a runnable automation. | `creating-skills.md` |
| Hub install and taps: `hermes skills install <id>`, `hermes skills update`, `hermes skills tap add owner/repo`, `hermes skills publish`. | `website/docs/user-guide/features/skills.md` |
| Hermes ships optional security skills under `optional-skills/security/` (`1password`, `oss-forensics`, `sherlock`, `web-pentest` and others). | `optional-skills/security/` |

## MCP

| Fact | Source |
|---|---|
| MCP servers live under `mcp_servers:` in `config.yaml`: stdio (`command`, `args`, `env`) or HTTP (`url`, `headers`), plus `enabled`, `timeout` (default 300 s), `connect_timeout`, `lazy`, `supports_parallel_tool_calls`, `tools.include/exclude/resources/prompts`, `trust`. | `website/docs/reference/mcp-config-reference.md` |
| `${VAR}` and `${env:VAR}` resolve from the profile's `.env` or secret source. An unset variable in a remote `url` or `headers` fails the connect closed. Context variables: `${userHome}`, `${workspaceFolder}`, `${/}`. | `mcp-config-reference.md` |
| `trust: untrusted` makes every tool without `readOnlyHint: true` ask for approval, and fail closed in cron. | `mcp-config-reference.md` |
| Stdio MCP subprocesses get a filtered environment (`PATH`, `HOME`, `USER`, `LANG`, `LC_ALL`, `TERM`, `SHELL`, `TMPDIR`, `XDG_*`) plus only the keys in that server's `env`. MCP error text is redacted for common secret shapes. | `website/docs/user-guide/security.md` ("MCP Credential Handling") |
| Model-facing tool names are `mcp__<server>__<tool>`, capped at 64 characters. Keep server and tool names short. | `website/docs/developer-guide/plugins/index.md` |
| Hermes's optional MCP catalogue already has `cloudflare` (official remote server, OAuth, the full Cloudflare API). | `optional-mcps/cloudflare/manifest.yaml` |
| Open question: a profile-root `mcp.json` is in the default owned list, but no runtime loader for it was found outside portable plugins. Use `config.yaml` `mcp_servers` until verified. | `hermes_cli/agent_plugins.py`, `hermes_cli/profile_distribution.py` |

## Plugins

| Fact | Source |
|---|---|
| Native plugin: directory with `plugin.yaml` (`name`, `version`, `description`, `provides_tools`, `provides_hooks`, `requires_env`, v2 fields such as `python_dependencies`, `config_schema`, `license`) and `__init__.py` with `register(ctx)`. | `website/docs/developer-guide/plugins/index.md` |
| General plugins are disabled until listed in `plugins.enabled` or enabled with `hermes plugins enable <name>`. | `website/docs/user-guide/features/plugins.md` |
| `hermes plugins doctor <path> --ci` and `hermes plugins validate` check a plugin. | `developer-guide/plugins/index.md` |
| Hooks: `pre_tool_call` (can block or approve), `post_tool_call` (`tool_name`, `args`, `result`, `task_id`, `duration_ms`), `pre_llm_call` (context injection), `on_session_start`, `on_session_end` and others. Callbacks accept `**kwargs`. | `developer-guide/plugins/index.md` ("Hook reference") |
| Middleware kinds: `tool_request`, `llm_request`, `tool_execution`, `llm_execution`. | `developer-guide/plugins/index.md`, `hermes_cli/middleware.py` |
| Plugin skills via `ctx.register_skill(name, path)`, loaded as `skill_view("<plugin>:<skill>")`, not listed in the system prompt index. | `developer-guide/plugins/index.md` |
| Durable plugin state goes under `<hermes home>/plugin-data/<name>/`, with a WAL SQLite option. | `developer-guide/plugins/index.md` ("Store durable state") |
| Portable Agent Plugins v1 packages (`plugin.json`, `skills/`, `mcp.json`) install disabled. Their `mcp.json` must hold no credentials. A package can mark a server `trust: untrusted`. | `developer-guide/plugins/index.md` ("Portable Agent Plugins v1 packages") |

## Memory

| Fact | Source |
|---|---|
| `memories/MEMORY.md` (2,200 characters) and `memories/USER.md` (1,375 characters), injected as a frozen snapshot at session start, edited with the `memory` tool. | `website/docs/user-guide/features/memory.md` |
| Memories and sessions never ship in a distribution. Shared memory needs an external memory provider plugin. | `profile-distributions.md`, `memory.md` |

## Cron

| Fact | Source |
|---|---|
| Jobs live in `cron/jobs.json`. CLI: `hermes cron create "<schedule>" "<prompt>" [--skill <s>] [--paused] [--workdir <dir>]`. | `website/docs/user-guide/features/cron.md` |
| Authored job fields include `name`, `prompt`, `skills`, `schedule`, `deliver`, `script`, `no_agent`, `enabled_toolsets`, `workdir`, `failure_deliver`. | `cron/job_definition.py` (`JOB_DEFINITION_FIELDS`) |
| `no_agent` jobs run a script from `$HERMES_HOME/scripts/` and deliver stdout. The script environment is sanitised, so provider credentials are not inherited. | `cron.md` ("no-agent mode") |
| `hermes pause` and `hermes resume` stop and restart all scheduled fires. | `cron.md` |

## Security controls Hermes already has

| Fact | Source |
|---|---|
| Dangerous command approval, hardline blocklist, `approvals.deny`. | `website/docs/user-guide/security.md` |
| `security.website_blocklist` (a deny list), SSRF protection for URL tools, `security.allow_private_urls` (default false). | `security.md` |
| Egress allowlist for remote terminal sandboxes: `hermes egress` manages iron-proxy, with `proxy.extra_allowed_hosts`. | `website/docs/user-guide/egress/iron-proxy.md` |
| `terminal.docker_network: false` runs the sandbox with no network. | `website/docs/user-guide/configuration.md` |
| Context files are scanned for prompt injection. | `security.md` |

---

Owner ticket: roadmap
Last verified: 16 October 2026
