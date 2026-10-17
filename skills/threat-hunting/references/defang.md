# Defanging

Defang observables in text a person will read. Leave tool arguments as the original value. The connector needs the real observable.

| Observable | Output |
|---|---|
| IPv4 `203.0.113.10` | `203[.]0[.]113[.]10` |
| URL `https://updates.example.com/login` | `hxxps://updates[.]example[.]com/login` |
| URL `http://updates.example.com/login` | `hxxp://updates[.]example[.]com/login` |
| Domain `updates.example.com` | `updates[.]example[.]com` |
| Email `analyst@example.com` | `analyst[@]example[.]com` |

Do not defang a value that is already defanged. A second pass corrupts `[.]` and `[@]`.

Defang once, in the hunt pack. Do not defang the argument you pass to a tool.
