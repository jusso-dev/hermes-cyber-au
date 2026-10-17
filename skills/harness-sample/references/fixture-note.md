# Fixture note

The harness sample reads scrubbed fixtures. It does not call the network.

Cite a stub result as `Source: hermes-cyber-au stub, none, retrieved <date>`.

Cite the KEV harness fixture as `Source: CISA Known Exploited Vulnerabilities, <catalogVersion>, retrieved <date>`.

Defang observables in the answer. Leave tool arguments unchanged.

| Observable | Answer |
|---|---|
| `203.0.113.10` | `203[.]0[.]113[.]10` |
| `https://updates.example.com/login` | `hxxps://updates[.]example[.]com/login` |
| `analyst@example.com` | `analyst[@]example[.]com` |
