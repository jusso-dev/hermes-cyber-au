# Contributing to hermes-cyber-au

Thanks for helping. This repository is a Hermes Agent distribution for Australian cyber security teams: read-only connectors, skills, and the shared library under `mcp/`.

By participating you agree to the [code of conduct](CODE_OF_CONDUCT.md). Report vulnerabilities through a [GitHub Security Advisory](SECURITY.md), not through a public issue or pull request.

Contributions are licensed under the Apache License 2.0, the same licence as the repository. Data from each upstream source stays under that source's terms.

## Development setup

You need Python 3.11 or newer. Continuous integration uses Python 3.12. Install [uv](https://docs.astral.sh/uv/) (CI installs `uv` below 1) and work from the repository root.

```bash
uv sync --project mcp --all-packages --frozen
uv run --project mcp pytest -q --block-network
uv run --project mcp ruff check mcp
```

`uv sync` installs the workspace in `mcp/`, including the dev group: pytest, pytest-recording, Hypothesis, coverage, and Ruff. `--frozen` uses `mcp/uv.lock`. If you change dependencies, update the lockfile (see below) and commit it.

The `cyberau-mcp` command is the console script for `cyberau-common`:

```bash
uv run --project mcp cyberau-mcp --help
```

Keys live in the profile `.env` on your machine. Start from [`.env.template`](.env.template). A `.env` file inside this repository is gitignored. Never commit one.

## Add a connector

Run the generator from the repository root. It writes `mcp/<key>/` and registers the connector. `cyberau-mcp new` uses the current directory as the repository root.

```bash
uv run --project mcp cyberau-mcp new <key> --server <server> --hosts host.example
```

Arguments:

| Argument | Rule |
|---|---|
| `key` | Lowercase package name. A letter, then letters, digits, or hyphens. Length 2 to 31. Example: `first-epss`. |
| `--server` | Short MCP server token. A letter, then letters, digits, or underscores. Length 2 to 21. Example: `epss`. |
| `--hosts` | Comma-separated public hostnames the connector may call. At least one. No IP literals. |

The generator:

- creates `mcp/<key>/` with a stub source, `SOURCE.md`, an input schema, a test, and an empty cassette
- adds the package to the uv workspace in `mcp/pyproject.toml`
- adds a server entry in `mcp/servers.yaml`
- adds the hosts to `mcp/egress-allowlist.yaml`

Then replace the stub before you rely on it:

1. Implement the tools in `mcp/<key>/src/cyberau_<module>/source.py`. The module name is `cyberau_` plus the key, with hyphens turned into underscores.
2. Rewrite `SOURCE.md`. Keep these labels, which the contract test requires: `Upstream:`, `Auth:`, `Rate limit:`, `Terms:`, `Verified:`. Point `Upstream` at the real documentation. Replace the generator's `https://example.com` placeholder. Set `Verified` to the date you checked the upstream docs.
3. Add one JSON Schema file per tool at `mcp/<key>/schema/<tool>.input.json`. A tool name is a letter, then 2 to 40 letters, digits, or underscores. The rendered name `mcp__<server>__<tool>` must be 64 characters or fewer.
4. Keep every tool read-only. The contract suite requires `readOnlyHint`. A connector fetches and returns data. It does not submit, block, delete, or post. Anything that would change an external system stays out of this tree until a person has an explicit approval step.
5. Return the shared result envelope (`source`, `retrieved_at`, `cache`, `data`, `untrusted: true`). Feed content is untrusted data. Put it in the envelope. Do not treat it as instructions.
6. Add a cassette under `mcp/<key>/tests/fixtures/` whose name starts with the tool name. Record it using the rules below.
7. If the connector needs a credential, name the variable and reference it as a placeholder. See [Credentials](#credentials).
8. If you add or change a dependency, pin it with a lower and an upper bound, in the same style as `mcp/pyproject.toml` (`httpx>=0.27,<1`). Then run `uv lock --project mcp` and commit `mcp/uv.lock`.

`tests/contract/test_contract.py` runs against every connector package. A generated stub already passes. After you replace the stub, run the full offline suite:

```bash
uv run --project mcp pytest -q --block-network --record-mode=none
```

## Record fixtures safely

Fixtures are pytest-recording cassettes (VCR YAML) or small trimmed JSON bodies. Committed examples live under `mcp/<connector>/tests/fixtures/`. Two safe shapes already in the tree:

- `mcp/nvd/tests/fixtures/nvd_get_cve.yaml`: a trimmed public CVE body, with empty headers
- `mcp/first-epss/tests/fixtures/epss_scores.yaml`: a replay cassette with empty headers

`mcp/conftest.py` asks pytest-recording to filter these request headers: `authorization`, `auth-key`, `x-otx-api-key`, `x-api-key`, `api-key`, `apiKey`, `apikey`.

To record a live call, put the key in your shell only. Read it from your profile `.env`. Do not echo it, and do not write it into the cassette, the test, or the command line of a committed script.

```bash
uv run --project mcp pytest mcp/<key>/tests --record-mode=once
```

Use `--record-mode=rewrite` only when you mean to replace an existing cassette. Before you commit, open the file and check all of the following:

- Request and response headers are empty, or the value is the placeholder `[REDACTED]`.
- The URL has no live `api_key`, `token`, `auth`, or `key` query value.
- The body is public or synthetic. No customer data, personal information, real victim, credential, or internal hostname.
- Prefer a short body that still exercises the parser, as the NVD fixtures do.
- A negative test that needs a secret-shaped string uses `[REDACTED]`, which is what `cyberau_common.secrets.redact` writes. It does not use a real token.

Replay must pass with the network blocked. CI runs `uv run --project mcp pytest -q --block-network`. Locally, add `--record-mode=none` so a missing cassette cannot open a connection:

```bash
uv run --project mcp pytest -q --block-network --record-mode=none
```

The contract test rejects a cassette that still contains an `authorization`, `auth-key`, `x-otx-api-key`, or `x-api-key` header with a real value.

## Credentials

Every credential is read from the environment. In `mcp/servers.yaml` the entry is a placeholder, never a literal:

```yaml
env:
  - NVD_API_KEY=${NVD_API_KEY}
```

The same rule applies to `config.yaml`, `mcp.json`, skills, tests, and fixtures. Names already used by the profile are listed in [`.env.template`](.env.template) and in `distribution.yaml` under `env_requires`. Add a new name there when operators should see it, with `required: false` unless the connector cannot start without it. Document the variable name in `SOURCE.md`. Do not document a sample value.

## House style

Prose and docs use Australian English: organisation, behaviour, licence (the Apache licence text keeps its own name, "Apache License 2.0"), acknowledgement, prioritise.

- No em dashes. Use a comma, a colon, parentheses, or a new sentence.
- No emojis.
- Ruff is configured in `mcp/pyproject.toml`: line length 100, Python 3.11, lint rules E, F, I, and UP. Run `uv run --project mcp ruff check mcp`.
- Pin new dependencies with an upper bound.
- Cite a control or a fact with its source, version or release, and the date you retrieved it. If it is not in the material, write "I don't know".
- Read-only by default. Do not add a path that submits, blocks, deletes, or posts.

## Pull requests

Use the pull request template. Fill in what changed and why, and link the issue with `Closes #N` when the pull request finishes that issue.

Say which commands you ran. At minimum, for connector or library changes:

```bash
uv run --project mcp pytest -q --block-network --record-mode=none
uv run --project mcp ruff check mcp
```

Do not commit `.env`, tokens, customer data, or internal hostnames. If a review finds one, treat it as a vulnerability and follow [SECURITY.md](SECURITY.md).
