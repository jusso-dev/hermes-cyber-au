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

`codespell` keeps the Australian spellings in `tools/docs/en-AU.txt`. The style check rejects em dashes and emojis, and it requires each page to name an owner ticket and a last-verified date.

`site/` is build output. GitHub Pages is not configured in this checkout. Files under `ci/workflows/` are proposed workflows, not active GitHub Actions.

---

Owner ticket: docs-site
Last verified: 17 October 2026
