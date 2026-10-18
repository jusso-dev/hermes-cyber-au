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

---

Owner ticket: docs-site
Last verified: 17 October 2026
