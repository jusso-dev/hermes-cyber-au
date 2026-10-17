# Secrets

Credentials stay out of the repository, the logs, the cache, exports, prompts, and tool results.

`mcp/servers.yaml` and the rendered `config.yaml` contain `${VAR}` placeholders only. Hermes resolves `${VAR}` and `${env:VAR}` from the active profile's secret scope (the profile `.env`, or a secret source). An unset variable in a remote MCP `url` or `headers` fails the connection closed, and the variable name is reported in the server status. Fix the profile secret scope. The next connection renders the reference again.

## Prefer a secret source

Use a Hermes secret source instead of a plain `.env` when you can. Hermes loads secret sources after the profile `.env` and before it reads credentials. Bitwarden, 1Password, and a command helper ship with Hermes. Any other backend, including the operating system keychain, is a secret source plugin: a directory with `plugin.yaml` and an `__init__.py` that registers a `SecretSource`. Map each name from `distribution.yaml` (`NVD_API_KEY`, `OTX_API_KEY`, and the rest) in that source so the value never sits in a file.

The command helper can read the operating system keychain. That keeps the key out of `.env`.

A plain `.env` still works. Copy `.env.template`, fill in the values locally, and keep the file mode at `600`. `cyberau-mcp doctor` warns when `.env` is not mode `600`. The fix is `chmod 600 .env`. The check does not print file contents.

Distributions do not ship `.env`, filled `.env.EXAMPLE` files, or a credential store. A portable plugin `mcp.json` is visible data. Do not put a key in it.

## Redaction

`cyberau_common.secrets.redact()` runs on log lines, result envelopes, exception text, and audit records before they are written or exported. It covers these header names:

- `Authorization`
- `Auth-Key`
- `apiKey`
- `X-OTX-API-KEY`
- `key`

It also replaces the value of every variable named in `distribution.yaml` when that value appears in those outputs. Values shorter than 8 characters are not substituted globally, because they collide with ordinary words. The header patterns above still cover them.

Recorded HTTP cassettes use pytest-recording `filter_headers` for those header names. A post-record scrubber rewrites any remaining non-placeholder value to `[REDACTED]`. The test suite fails if a cassette still has one of those headers set to anything other than a `${VAR}` placeholder, `[REDACTED]`, or the recorder's `XXXX` marker.

## CI

`ci/workflows/ci.yml` runs gitleaks over the full git history. `.gitleaks.toml` allowlists a ticket frontmatter line of the form `key: "slug"`, which is an identifier. A unit test rejects literal credentials in `mcp/servers.yaml`, `config.yaml`, and the rendered config.
