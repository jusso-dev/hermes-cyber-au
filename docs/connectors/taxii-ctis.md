# Generic TAXII 2.1 reader

Read-only TAXII 2.1 client for an API root the user supplies. That includes ASD's Cyber Threat Intelligence Sharing (CTIS) platform when the user is a Network Partner and brings their own API root, collection id, and HTTP Basic credentials. The same client can read any other TAXII 2.1 root the user points it at.

The connector ships off. A fresh install renders `enabled: false` even when the environment variables are set. The user turns it on with `enabled: true` in their profile `config.yaml`. A profile update keeps that choice and does not switch the connector back on or off.

off by default: licence terms.

CTIS content is covered by the ASD Network Partner deed. It must not be copied into a public repository, a shared log, or an export without a TLP check. Say that before the first TAXII call in a session.

| Tool | What it returns |
|---|---|
| `taxii_list_collections` | Collections the credentials can read |
| `taxii_get_objects` | One page range of STIX objects, filtered by `added_after` and type |
| `taxii_lookup_indicator` | Stored indicators whose value is an IP, domain, URL, or hash |
| `taxii_sync_status` | Last sync time, object count, and error for each collection |

Titles, descriptions, and indicator patterns are untrusted text.

## Terms and TLP

CTIS content is covered by the ASD Network Partner deed. It must not be copied into a public repository, a shared log, or an export without a TLP check.

Objects marked TLP:AMBER, TLP:AMBER+STRICT, or TLP:RED stay inside the profile. They are left out of STIX export and of briefings sent outside the profile unless the user overrides that for the current run. TLP:CLEAR and TLP:GREEN may be exported. This connector does not submit, upload, or contribute indicators.

Onboarding for CTIS is through the ASD partner portal: https://www.cyber.gov.au/become-a-partner

## Credentials

Set these in the profile environment. Nothing is built in.

- `TAXII_API_ROOT`
- `TAXII_COLLECTION_ID`
- `TAXII_USERNAME`
- `TAXII_PASSWORD`

The shipped egress allowlist has no host. Add the API root host before the first live call. Poll at most once an hour. For CTIS, ask for indicators no older than a month. Passing an older `added_after` still works for other TAXII servers, and the answer includes a warning.

The API root must be https and carry no userinfo, query or fragment. A discovery document can only point the client at another root on the same host. A redirect off the allowlist is refused and no credential is sent on any redirect. With no live access the tools fall back to a synthetic sample that is labelled as such.

This connector is not endorsed by ASD.
