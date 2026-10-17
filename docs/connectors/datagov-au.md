# data.gov.au (CKAN)

Read-only catalogue search for data.gov.au.

| Tool | What it returns |
|---|---|
| `datagov_search` | Packages with title, publisher, licence and resource links |
| `datagov_get_package` | One package and its resources |

No API key. The connector sends at most one request a second and caches responses for 24 hours. Each dataset keeps its own licence in `license_id`. A missing licence, or `notspecified`, is flagged. Free-text fields, and any identifier, format or URL that is not plain, are returned as untrusted data.

With `CYBERAU_OFFLINE=1` the connector answers from cache, then from a small synthetic sample snapshot shipped with it. A stale cached copy, a snapshot file set in `CYBERAU_DATAGOV_SNAPSHOT` and the shipped sample are each labelled in `cache` and carry a warning. The shipped sample is not data.gov.au data. Snapshot answers are not written to the observation store. A redirect outside the allowlist is refused and is not answered from cache.

Attribution: data.gov.au. Each dataset keeps its own licence (license_id). Datasets with no licence are flagged.
