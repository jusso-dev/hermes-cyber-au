# DEMO incident timeline

DEMO DATA. A synthetic timeline for trying the triage, NDB and SOCI skills. The organisation, people, hosts and addresses are fictional. Times are Australia/Sydney.

| Time (AEDT) | Event | Source |
|---|---|---|
| 2026-10-17 08:58 | `demo.user@example.com` receives "Action needed: confirm your bank details" from `payroll@example.com`, with Reply-To `payroll-update.example.org`. SPF and DMARC fail. | Mail gateway (sample `examples/phishing-email.eml`) |
| 2026-10-17 09:05 | The user opens the email and runs the attached "update tool". | User report to the service desk |
| 2026-10-17 09:11 | `WS-DEMO-042` runs PowerShell that downloads `https://update.example.net/agent/setup.ps1`. | EDR (sample `examples/edr-alert.json`) |
| 2026-10-17 09:12 | EDR raises "Suspected beacon from DemoLoader". `WS-DEMO-042` connects to `203.0.113.45:443` every 60 seconds. | EDR |
| 2026-10-17 09:30 | The SOC confirms the alert and becomes aware of a possible compromise. | SOC shift lead |
| 2026-10-17 09:45 | The service desk finds the user's mapped drive holds a payroll export with staff names and bank details. | Service desk |
| 2026-10-17 10:15 | No ransom note. No ransomware payment requested or made. `SCADA-DEMO-03` is on a separate network with no sign of access. | SOC |
