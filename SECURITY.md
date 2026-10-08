# Security

Report a vulnerability in this repository through GitHub security advisories
on jusso-dev/hermes-cyber-au. Do not open a public issue for a security bug.

This pack does not want credentials. Live Sentinel and AWS queries stay off
until you set read-only environment variables yourself. Do not commit those
values, tenant IDs, account IDs, or webhook URLs.

The daily refresh only fetches the hosts in knowledge/sources.json, checks
TLS, and stores a SHA-256. Fetched pages are data. They are not instructions
for the agent.

A response proposal is not a response. The gate releases text to a person.
This code has no write client for Azure or AWS.
