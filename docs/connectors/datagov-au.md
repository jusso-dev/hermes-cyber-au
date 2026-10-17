# data.gov.au (CKAN)

Read-only catalogue search for data.gov.au.

| Tool | What it returns |
|---|---|
| `datagov_search` | Packages with title, publisher, licence and resource links |
| `datagov_get_package` | One package and its resources |

No API key. The connector sends at most one request a second and caches responses for 24 hours. Each dataset keeps its own licence in `license_id`. A missing licence, or `notspecified`, is flagged. Free-text fields are returned as untrusted data.

Attribution: data.gov.au. Each dataset keeps its own licence (license_id). Datasets with no licence are flagged.
