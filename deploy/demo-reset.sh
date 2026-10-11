#!/usr/bin/env bash
# Get the demo back to a clean slate without touching anything people would want to keep.
#
#   cd ~/tripwire && bash deploy/demo-reset.sh        # asks first; add -y to skip the question
#
# Clears, and only this:
#   - family links, pending invites and cooldowns (family.json on the gateway's volume),
#   - the iMessage rate-limit counts (the gateway holds them in memory, so it is restarted),
#   - the website box's rate-limit counts (the analyzer forgets them; it is not restarted).
# Stored reports, screenshots, the dashboard's recent events, the analyzer and Caddy are left alone.
# The gateway is down for a few seconds while it restarts; Photon delivers what arrives meanwhile.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" != "-y" ]; then
  echo "This forgets every family link and pending invite, and every rate-limit count."
  echo "Reports and screenshots stay. The gateway restarts (a few seconds)."
  read -r -p "Reset the demo? [y/N] " answer
  [ "$answer" = "y" ] || [ "$answer" = "Y" ] || { echo "Nothing changed."; exit 1; }
fi

# 1. The gateway is stopped first, so it cannot write the links back as it shuts down, and its
#    family file is removed from its own volume with a throwaway container (no chat is started).
docker compose stop gateway >/dev/null
docker compose run --rm --no-deps --entrypoint rm gateway -f /app/data/family.json
echo "family links: cleared"

# 2. The gateway comes back with empty rate-limit counts.
docker compose start gateway >/dev/null
echo "iMessage rate limits: cleared (gateway restarted)"

# 3. The website box's counts, on the running analyzer, over the private network.
docker compose exec -T analyzer python - <<'PY'
import urllib.request

request = urllib.request.Request("http://127.0.0.1:8001/internal/reset-limits", method="POST")
status = urllib.request.urlopen(request, timeout=5).status
assert status == 204, status
print("website box rate limits: cleared")
PY

echo "Done. Reports, screenshots and the dashboard are untouched."
