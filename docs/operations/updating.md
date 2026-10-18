# Updating and pinning

Analysts refresh the cyber-au distribution with one command. The update replaces distribution-owned files and leaves the operator's own data where it is.

## Update

```bash
hermes -p cyber-au cyber-au update
```

The command does three things, in order:

1. `hermes profile update cyber-au --yes` replaces distribution-owned files. `cron/jobs.json` is merged by job id. A job that is new in this release arrives paused. Bootstrap enables only the two local [maintenance jobs](cleanup.md) once and preserves subsequent manual pauses. A job you have already enabled stays enabled. `.env`, `memories/`, the intel store under `plugin-data/cyber-au/`, and your edits to `config.yaml` are kept.
2. `install/bootstrap.sh` needs Python 3.11 or newer on `PATH` (it tries `python3`, then `python3.13`, `python3.12` and `python3.11`). It syncs the MCP virtualenv when `uv` is on `PATH`, patches the `mcp_servers` block when the renderer is present, and applies store migrations.
3. `hermes -p cyber-au cyber-au doctor` reports what is healthy.

`config.yaml` is preserved unless you pass `--force-config`. That flag replaces `config.yaml` with the copy shipped by the distribution. There is no flag that deletes `.env`.

```bash
hermes -p cyber-au cyber-au update --force-config
```

A local checkout can be applied without contacting the recorded git remote:

```bash
hermes -p cyber-au cyber-au update --source /path/to/hermes-cyber-au
```

## Roll back to a tag

```bash
hermes -p cyber-au cyber-au update --to v0.1.0
```

The command reinstalls the distribution files from that tag in the git checkout that contains this plugin. Pass `--source` when the tag lives in a different local checkout. It does not fetch from the network.

If the tag's store migrations are older than the migrations already applied to the intel store, the command stops before it changes the profile and prints a refusal. Store downgrades are not supported. `--source` runs the same check against the checkout it applies.

The directory `backups/` at the profile root is yours. An update never overwrites it. Migration snapshots are written to `plugin-data/cyber-au/backups/` instead, which the file replace also leaves alone.

## Store migrations

Migrations are numbered SQL files, `plugins/cyber-au/store/migrations/NNNN_*.sql`. They run in filename order. Each file runs inside a transaction. Statements are split by SQLite, so triggers and comments containing semicolons are safe. Migration files must not issue `BEGIN`, `COMMIT`, `ROLLBACK` or `END` of their own. Before the first file runs, a copy of `plugin-data/cyber-au/intel.sqlite` is written under `plugin-data/cyber-au/backups/`.

If a migration fails for any reason, including an unreadable file, the store is restored from that copy and the command prints the backup path. Rows that were already in the store stay as they were.

## Hermes version policy

`hermes_requires` in `distribution.yaml` is the minimum Hermes version for this distribution. That floor moves only in the weekly bump PR opened by `deps-and-hermes-bump` (`.github/workflows/deps-and-hermes-bump.yml`). Feature changes do not edit the floor.

`hermes update` updates Hermes itself, on the stable channel or on main (`hermes update --set-channel stable` or `hermes update --set-channel main`). It does not update this distribution. `cyber-au update` updates this distribution. It does not change which Hermes you have installed.

To pin Hermes, set its channel with `hermes update --set-channel`. To pin this distribution, run `cyber-au update --to <tag>`.
