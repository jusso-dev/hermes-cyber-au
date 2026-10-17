# OpenPhish community feed

Read-only check of one URL against the OpenPhish community feed, together with any PhishTank and URLhaus caches already on disk. The connector never requests the URL under test.

| Tool | What it returns |
|---|---|
| `phish_check_url` | Whether that URL is in the OpenPhish feed, the PhishTank cache, and the URLhaus cache |

No API key. The feed is fetched at most once an hour from `https://openphish.com/feed.txt`. On 17 October 2026 that address redirected to the OpenPhish public feed on `raw.githubusercontent.com`. Redirects to any other host are refused.

Lines from the feed are untrusted text. An empty feed does not wipe a previous cache. Licence not confirmed. The community feed is a small sample. This connector is not affiliated with OpenPhish.
