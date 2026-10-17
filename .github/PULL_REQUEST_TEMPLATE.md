## What changed

<!-- One short paragraph on why, not a file list. -->

## Checks

- [ ] `uv run --project mcp pytest -q --block-network --record-mode=none`
- [ ] `uv run --project mcp ruff check mcp` (if Python changed)
- [ ] No secrets, tokens, customer data, or internal hostnames
- [ ] Credentials appear only as `${VAR}` placeholders, read from the profile `.env`
- [ ] New or updated fixtures are scrubbed. Auth headers are empty or `[REDACTED]`
- [ ] Australian English. No em dashes. No emojis
- [ ] New dependencies have an upper bound, and `mcp/uv.lock` is updated
- [ ] Read-only: this change does not submit, block, delete, or post
- [ ] Connector changes keep `SOURCE.md` labels and pass `tests/contract/test_contract.py`

## Related issue

Closes #

Vulnerabilities belong in a [GitHub Security Advisory](https://github.com/jusso-dev/hermes-cyber-au/security/advisories/new), not in this pull request.
