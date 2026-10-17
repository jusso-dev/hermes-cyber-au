# Spamhaus DROP

Read-only checks against the Spamhaus Don't Route Or Peer lists: DROP (IPv4), DROPv6 and ASN-DROP.

| Tool | What it returns |
|---|---|
| `drop_check_ip` | Whether an IPv4 or IPv6 address is inside a DROP netblock, with the SBL id |
| `drop_check_asn` | Whether an autonomous system number is on ASN-DROP |
| `drop_list_status` | Last fetch time and entry counts for each list |

Public feeds, with no API key. The three lists are cached for 24 hours and refreshed at most once an hour. Registry names, AS names and domains come back as untrusted text.

Attribute Spamhaus. The lists are provided free of charge. Formal licence text was not confirmed.

Checked against the public JSON feeds on 17 October 2026.
