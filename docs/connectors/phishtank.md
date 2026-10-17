# PhishTank verified phishing URLs

Read-only check against the PhishTank verified-online database.

| Tool | What it returns |
|---|---|
| `phishtank_check_url` | Whether a URL is in the cached verified-online set, with the normalised PhishTank record |

The connector downloads `online-valid.json` at most once an hour, follows PhishTank's CDN redirect, and compares the URL locally. It does not request the URL under test. An optional `PHISHTANK_APP_KEY` is placed in the download path and raises the daily allowance. Without a key, PhishTank allows only a few downloads a day. The target name is untrusted text.

PhishTank is operated by Cisco Talos. Licence not confirmed. This connector is not endorsed by PhishTank.
