#!/usr/bin/env bash
# Refresh the daily vulnerability feeds into the intel store: OSV (MAL- alerts and the
# inventory dependency scan), GitHub advisories, the CVE List, NVD, Exploit-DB, Metasploit,
# cve.now and pwn.watch. The morning email reads them back as the vulnerability digest.
# Hermes runs this from $HERMES_HOME/scripts with a sanitised environment. Every source here is
# keyless. Dependabot alerts need a token and run separately (see mcp/vuln-feeds/SOURCE.md).
set -euo pipefail
unset CDPATH
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
exec bash "$script_dir/cyberau_ingest.sh" osv,ghsa,cvelist,nvd,exploitdb,metasploit,vulnfeeds
