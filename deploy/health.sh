#!/usr/bin/env bash
# Is the demo ready? One OK or FAIL line per check, and a non-zero exit if any failed.
#
#   cd ~/tripwire && bash deploy/health.sh
#   sudo bash deploy/health.sh        # to also read the firewall rules (otherwise that line says so)
#
# It scans example.com through the public address, so it counts as one of the website box's ten
# checks an hour; bash deploy/demo-reset.sh clears that. It sends no iMessage and changes no links.
set -uo pipefail
cd "$(dirname "$0")/.."

failures=0
ok() { printf 'OK    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); }

# The public name, from .env (only this one value is read).
host="$(grep -E '^SITE_HOST=' .env 2>/dev/null | head -n1 | cut -d= -f2- | tr -d "\"' \r")"

# --- the three containers -------------------------------------------------------------------
container_state() { # service -> "status health" ("" if there is no container)
  local id
  id="$(docker compose ps -q "$1" 2>/dev/null | head -n1)"
  [ -n "$id" ] && docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}-{{end}}' "$id" 2>/dev/null
}

state="$(container_state analyzer)"
case "$state" in
  "running healthy") ok "analyzer container is running and healthy" ;;
  "") fail "analyzer container not found (docker compose up -d)" ;;
  *) fail "analyzer container is: $state" ;;
esac

state="$(container_state gateway)"
if [ "${state%% *}" != "running" ]; then
  fail "gateway container is: ${state:-not found}"
elif docker compose logs --tail 300 gateway 2>/dev/null | grep -q "gateway up"; then
  ok "gateway container is running and connected to the chat provider"
else
  fail "gateway container is running but has not logged \"gateway up\" (docker compose logs gateway)"
fi

state="$(container_state caddy)"
case "${state%% *}" in
  running) ok "caddy container is running" ;;
  *) fail "caddy container is: ${state:-not found}" ;;
esac

# --- the live stream and a scan, through the public address -------------------------------------
if [ -z "$host" ]; then
  fail "SITE_HOST is not set in .env, so the /events and scan checks were skipped"
else
  headers="$(curl -sS -m 4 -D - -o /dev/null -H 'Accept: text/event-stream' "https://$host/events" 2>/dev/null || true)"
  if grep -qiE '^HTTP/[0-9.]+ 200' <<<"$headers" && grep -qi '^content-type: text/event-stream' <<<"$headers"; then
    ok "/events streams (200, text/event-stream)"
  else
    fail "/events did not answer 200 text/event-stream at https://$host/events"
  fi

  started="$(date +%s)"
  response="$(curl -sS -m 90 -w '\n%{http_code}' -H 'content-type: application/json' \
    -d '{"url":"example.com"}' "https://$host/api/check" 2>&1)"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"
  id="$(sed -n 's/.*"id":"\([a-f0-9]\{12\}\)".*/\1/p' <<<"$body")"
  if [ "$code" = "429" ]; then
    fail "scan: the website box is rate-limited (run bash deploy/demo-reset.sh, then try again)"
  elif [ -z "$id" ]; then
    fail "scan: /api/check did not return a report id (HTTP $code)"
  else
    report="$(curl -sS -m 10 "https://$host/api/report/$id" 2>/dev/null)"
    verdict="$(sed -n 's/.*"verdict":"\([a-z_]*\)".*/\1/p' <<<"$report")"
    shot="$(curl -s -m 10 -o /dev/null -w '%{http_code}' "https://$host/shots/$id.png")"
    page="$(curl -s -m 10 -o /dev/null -w '%{http_code}' "https://$host/r/$id")"
    seconds=$(($(date +%s) - started))
    if [ "$verdict" = "no_red_flags" ] && [ "$shot" = "200" ] && [ "$page" = "200" ]; then
      ok "scan of example.com: no_red_flags in ${seconds}s, screenshot and report page served"
    else
      fail "scan of example.com: verdict=${verdict:-none} screenshot=HTTP $shot report page=HTTP $page (${seconds}s)"
    fi
  fi
fi

# --- Gemini --------------------------------------------------------------------------------------
gemini="$(docker compose exec -T analyzer python - 2>&1 <<'PY'
import asyncio

import gemini

if not gemini.configured():
    print("FAIL GEMINI_API_KEY is not set: replies use the plain template wording")
else:
    schema = {"type": "OBJECT", "properties": {"ok": {"type": "BOOLEAN"}}, "required": ["ok"]}
    answer = asyncio.run(gemini.generate_json("Answer with JSON only.", [{"text": "Is 2 + 2 equal to 4?"}], schema, 15))
    if answer is None:
        print(f"FAIL the key is set but model {gemini.model_name()} did not answer (check GEMINI_MODEL, or the key)")
    else:
        print(f"OK Gemini answers (model {gemini.model_name()})")
PY
)"
last="$(tail -n1 <<<"$gemini")"
case "$last" in
  OK*) ok "${last#OK }" ;;
  FAIL*) fail "${last#FAIL }" ;;
  *) fail "Gemini check could not run: $last" ;;
esac

# --- the firewall --------------------------------------------------------------------------------
as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo -n "$@"; fi; }

if ! rules_text="$(as_root iptables -S DOCKER-USER 2>/dev/null)"; then
  fail "firewall rules could not be read (run: sudo bash deploy/health.sh)"
else
  rules="$(grep -c 'tripwire-egress' <<<"$rules_text" || true)"
  input="$(as_root iptables -S INPUT 2>/dev/null | grep -c 'tripwire-egress' || true)"
  bridge="$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || echo missing)"
  if [ "${rules:-0}" -ge 7 ] && [ "${input:-0}" -ge 1 ] && [ "$bridge" = "1" ]; then
    ok "firewall: $rules forwarding rules and $input input rule in place, bridge filtering on"
  else
    fail "firewall: ${rules:-0} forwarding rules (need 7), ${input:-0} input rule (need 1), bridge filtering=$bridge (sudo bash deploy/egress-firewall.sh)"
  fi
fi

# The rules working, not just present: the analyzer must not reach the cloud metadata server.
reach="$(docker compose exec -T analyzer python - 2>&1 <<'PY'
import socket

try:
    socket.create_connection(("169.254.169.254", 80), timeout=3).close()
    print("REACHED")
except OSError:
    print("BLOCKED")
PY
)"
case "$(tail -n1 <<<"$reach")" in
  BLOCKED) ok "firewall: the analyzer cannot reach the cloud metadata server" ;;
  REACHED) fail "firewall: the analyzer REACHED the metadata server (sudo bash deploy/egress-firewall.sh)" ;;
  *) fail "firewall: the metadata probe could not run" ;;
esac

echo
if [ "$failures" -eq 0 ]; then
  echo "All checks passed."
else
  echo "$failures check(s) failed."
  exit 1
fi
