# FIRST EPSS

Read-only scores from the FIRST Exploit Prediction Scoring System.

| Tool | What it returns |
|---|---|
| `epss_scores` | Score, percentile, date and model version for up to 100 CVEs |
| `epss_history` | Daily scores for one CVE, last 30 points |
| `epss_top` | CVEs above a score threshold |

No API key. Cite the model version and the score date on every claim. The public API allows 1,000 requests a minute. Larger jobs should use the daily bulk file linked from the FIRST site rather than a hard-coded download URL.

Attribution: FIRST EPSS.
