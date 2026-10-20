#!/usr/bin/env bash
# Morning briefing by email, run by Hermes cron as a no-agent job.
#
# 1. Generates the briefing JSON with `hermes chat` (daily-briefing and helpers).
# 2. Reads new watch hits straight from the intel store, not from the model.
# 3. Renders HTML and text, and sends them through the email API in email.yaml.
#
# Settings: email.yaml in the profile data directory (api_url, from, to, key_file).
# The API key file must be chmod 600. It is read by email_brief.py and never printed.
# Hermes runs this file from $HERMES_HOME/scripts with a sanitised environment, and
# delivers stdout verbatim, so every outcome is one line without secrets.
set -uo pipefail
unset CDPATH
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
if [[ -n ${HERMES_HOME:-} ]]; then
  profile=$HERMES_HOME
else
  profile=$(cd -- "$script_dir/.." && pwd)
fi
data=${CYBERAU_DATA_DIR:-$profile/plugin-data/cyber-au}
config=$data/email.yaml
py=$profile/mcp/.venv/bin/python
cli=$profile/mcp/.venv/bin/cyberau-mcp
email=$profile/skills/daily-briefing/scripts/email_brief.py
prompt=$profile/skills/daily-briefing/references/email-prompt.txt
for need in "$py" "$cli"; do
  if [[ ! -x $need ]]; then
    printf 'morning email failed: %s is not installed\n' "${need#"$profile"/}"
    exit 1
  fi
done
if [[ ! -f $config ]]; then
  printf 'morning email failed: no email.yaml in the profile data directory\n'
  exit 1
fi
hermes_bin=$(command -v hermes || true)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

day=$(TZ=Australia/Sydney date +%F)
label=$(TZ=Australia/Sydney date "+%A %-d %B %Y")
sed "s/DATE_LABEL/$label/" "$prompt" > "$work/prompt.txt"

failed=""
if [[ -z $hermes_bin ]]; then
  failed="hermes is not on PATH"
elif ! timeout "${CYBERAU_EMAIL_TIMEOUT:-1500}" "$hermes_bin" chat --query-file "$work/prompt.txt" \
    --oneshot -Q -s daily-briefing,acsc-advisory-digest,vuln-prioritisation \
    > "$work/out.txt" 2> "$work/err.txt" || [[ ! -s $work/out.txt ]]; then
  failed="generation did not finish"
fi

# 26 hours back, 74 on a Monday so the weekend is covered.
hours=26
[[ $(TZ=Australia/Sydney date +%u) == 1 ]] && hours=74
since=$(date -u -d "-${hours} hours" +%Y-%m-%dT%H:%M:%SZ)
if ! "$cli" store watchlist hits --since "$since" > "$work/watches.json" 2> /dev/null; then
  : > "$work/watches.json"
fi

args=(send "$work/out.txt" --date-label "$label" --day "$day" --config "$config"
  --watches "$work/watches.json")
[[ -n $failed ]] && args+=(--failed "$failed")
# CYBERAU_EMAIL_DRY_RUN=1 runs everything except the send.
[[ ${CYBERAU_EMAIL_DRY_RUN:-0} == 1 ]] && args+=(--dry-run)
"$py" "$email" "${args[@]}" || exit 1
# A failure notice was sent, but the run itself still failed.
[[ -z $failed ]] || exit 1
