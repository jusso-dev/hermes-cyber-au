# Release in force

Use `published_at` from [the release list](releases.json). Do not parse the date from the tag. `v2026.09.4` was published on 2026-09-03. `v2026.06.18` was published on 2026-06-18.

The release in force on a calendar date is the latest release whose published date is on or before that date. Compare dates in `YYYY-MM-DD`. A release published on the date itself is in force that day.

| Release | Published |
|---|---|
| v2026.06.18 | 2026-06-18 |
| v2026.09.4 | 2026-09-03 |

If the date is before 2026-06-18, this snapshot has no release in force. Say so. Do not guess an earlier catalogue.

`scripts/release_in_force.py` reads the release list and the date, then prints the tag or `none`. It does not use the network.
