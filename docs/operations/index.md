# Operations

Build from the repository root with the pinned docs dependencies:

```bash
python3 -m venv .venv-docs
.venv-docs/bin/python -m pip install -r requirements-docs.txt
.venv-docs/bin/mkdocs build --strict
```

Check spelling and house style:

```bash
.venv-docs/bin/codespell docs
.venv-docs/bin/python tools/docs/style_check.py
```

`codespell` flags American spellings using the Australian list in `tools/docs/en-AU.txt`. Code spans, URLs and vendor product names are skipped. The style check rejects em dashes and emojis. It requires each page to name an owner ticket that exists in `tickets/` and a last-verified date, and it requires a connectors page for every `mcp/*/SOURCE.md`.

`site/` is build output. GitHub Pages is not configured in this checkout.

## Feed catalogue and status

`feeds/catalogue.yaml` lists every upstream source: its connector, the `mcp/servers.yaml` server, URLs, format, auth, poll interval, licence, region, whether it needs a key and whether it is on by default. `feeds/catalogue.schema.json` is its schema. The catalogue is hand maintained. No job writes to it. Auth entries hold environment variable names only, never values. Where a licence or other fact is not confirmed in the connector's `SOURCE.md`, the entry says so.

`feeds/status.json` holds run state. `cyberau-mcp refresh --catalogue feeds/catalogue.yaml` writes it beside the catalogue, with `last_run`, `last_ok`, `last_error` and `item_count` for each source it refreshed. Its keys match the catalogue's `refresh` field. Sources with `refresh_supported: false` are accepted by the nightly workflow but skipped until they have an adapter.

`tests/test_feed_catalogue.py` checks the catalogue against the schema, `mcp/servers.yaml`, `mcp/egress-allowlist.yaml`, the declared environment variables and the refresh source keys. `tools/ci/validate_repo.py` also validates it. Connector pages under `docs/connectors/` list each connector's feeds from the catalogue, so rerun `tools/build_connector_docs.py` after an edit.

---

Owner ticket: docs-site
Last verified: 18 October 2026
