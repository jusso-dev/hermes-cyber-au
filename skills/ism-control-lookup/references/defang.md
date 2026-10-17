# Defanging

Defang observables in the answer. Leave tool arguments as the analyst wrote them.

| Observable | Answer |
|---|---|
| IPv4 `203.0.113.10` | `203[.]0[.]113[.]10` |
| URL `https://updates.example.com/login` | `hxxps://updates[.]example[.]com/login` |
| URL `http://updates.example.com/login` | `hxxp://updates[.]example[.]com/login` |
| Domain `updates.example.com` | `updates[.]example[.]com` |
| Email `analyst@example.com` | `analyst[@]example[.]com` |

Do not defang a value that is already defanged. Do not defang a control id such as `ism-1173`.
