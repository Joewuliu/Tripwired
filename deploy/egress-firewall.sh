#!/usr/bin/env bash
# Tripwire egress firewall. Run once with sudo on the VM:
#
#     sudo bash deploy/egress-firewall.sh
#
# The analyzer opens hostile pages in a browser. The app already refuses private addresses, but
# it checks a hostname before the browser resolves it again (DNS rebinding) and it does not
# re-check redirects on images or scripts. This is the network-level fix for both: whatever the
# browser tries, the kernel drops packets from the analyzer container to
#   - the cloud metadata server and the other private ranges,
#   - the rest of the Docker network (gateway, Caddy),
#   - the VM itself.
# Replies to connections that the gateway and Caddy open to the analyzer still pass.
#
# Safe to run twice: it removes its own earlier rules before adding them.
# THESE RULES DO NOT SURVIVE A REBOOT: install the systemd unit from deploy/DEPLOY.md.
set -euo pipefail

SUBNET="${TRIPWIRE_SUBNET:-172.30.0.0/24}"  # must match the tripwire network in docker-compose.yml
ANALYZER="${TRIPWIRE_ANALYZER_IP:-172.30.0.10}"  # must match the analyzer's ipv4_address there
BLOCKED=(169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10)
TAG="tripwire-egress"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash $0" >&2
  exit 1
fi
if ! command -v iptables >/dev/null; then
  echo "iptables not found. Install it first: sudo apt-get install -y iptables" >&2
  exit 1
fi
if ! iptables -n -L DOCKER-USER >/dev/null 2>&1; then
  echo "The DOCKER-USER chain does not exist. Is Docker running? (sudo systemctl start docker)" >&2
  exit 1
fi

# Forwarded traffic, checked in this order (RETURN hands the packet back to Docker's own rules).
FORWARD_RULES=(
  "-s $ANALYZER -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment $TAG -j RETURN"
  "-s $ANALYZER -d $SUBNET -m comment --comment $TAG -j DROP"
)
for range in "${BLOCKED[@]}"; do
  FORWARD_RULES+=("-s $ANALYZER -d $range -m comment --comment $TAG -j DROP")
done
# Traffic to the VM's own addresses is delivered locally, never forwarded, so it needs its own rule.
INPUT_RULE="-s $ANALYZER -m conntrack --ctstate NEW -m comment --comment $TAG -j DROP"

remove_all() { # chain, then the rule: delete every copy (nothing happens if there is none)
  local chain=$1 rule=$2
  # shellcheck disable=SC2086 # the rule is deliberately split into separate arguments
  while iptables -C "$chain" $rule 2>/dev/null; do iptables -D "$chain" $rule; done
}

for rule in "${FORWARD_RULES[@]}"; do remove_all DOCKER-USER "$rule"; done
remove_all INPUT "$INPUT_RULE"

position=1
for rule in "${FORWARD_RULES[@]}"; do
  # shellcheck disable=SC2086
  iptables -I DOCKER-USER "$position" $rule
  position=$((position + 1))
done
# shellcheck disable=SC2086
iptables -I INPUT 1 $INPUT_RULE

echo "Tripwire egress rules for $ANALYZER (network $SUBNET) are in place."
echo
echo "== DOCKER-USER (forwarded traffic) =="
iptables -L DOCKER-USER -n -v --line-numbers
echo
echo "== INPUT (traffic to this VM itself), tripwire rule only =="
iptables -S INPUT | grep -- "--comment $TAG" || true
echo
echo "Not persistent: after a reboot run this again, or install the systemd unit (deploy/DEPLOY.md)."
