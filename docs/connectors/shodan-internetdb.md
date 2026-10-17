# Shodan InternetDB

Read-only passive exposure lookup for one IP address. No API key.

| Tool | What it returns |
|---|---|
| `internetdb_ip` | Open ports, hostnames, CPEs, tags and vulnerability identifiers |

InternetDB is free for non-commercial use. Commercial use needs a Shodan enterprise licence. The service publishes no rate limit, so this connector stays at one request a second and caches each address for 24 hours. Only public IPv4 and IPv6 addresses are sent upstream. Private, loopback, link-local, scoped, multicast and reserved addresses are refused before any request. If the service answers 429, the connector waits for `Retry-After` only up to 20 seconds, then gives up. Hostnames and tags are untrusted text. Hits are appended locally so later checks can see what was returned.

Shodan InternetDB. Free for non-commercial use; commercial use needs an enterprise licence.
