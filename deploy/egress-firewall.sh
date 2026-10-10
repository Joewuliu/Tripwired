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
# Precondition, which this script establishes and checks: the br_netfilter kernel module with
# net.bridge.bridge-nf-call-iptables=1. Without it, traffic between containers on the same bridge
# never reaches iptables at all, so the rules above would silently not apply to the gateway and
# Caddy (the rules for the internet and the VM would still work, which hides the problem).
#
# Safe to run twice: it removes its own earlier rules before adding them.
# The iptables rules do NOT survive a reboot: install the systemd unit from deploy/DEPLOY.md.
# The module and the sysctl do: this script writes the files that load them at boot.
set -euo pipefail

SUBNET="${TRIPWIRE_SUBNET:-172.30.0.0/24}"  # must match the tripwire network in docker-compose.yml
ANALYZER="${TRIPWIRE_ANALYZER_IP:-172.30.0.10}"  # must match the analyzer's ipv4_address there
BLOCKED=(169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10)
TAG="tripwire-egress"

BRIDGE_NF_FILE="${TRIPWIRE_BRIDGE_NF_FILE:-/proc/sys/net/bridge/bridge-nf-call-iptables}"
MODULES_LOAD_FILE="${TRIPWIRE_MODULES_LOAD_FILE:-/etc/modules-load.d/br_netfilter.conf}"
SYSCTL_FILE="${TRIPWIRE_SYSCTL_FILE:-/etc/sysctl.d/99-tripwire-egress.conf}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

ensure_bridge_filtering() {
  command -v modprobe >/dev/null || die "modprobe not found (is this a minimal image? install kmod)"
  modprobe br_netfilter || die "could not load the br_netfilter kernel module"
  sysctl -q -w net.bridge.bridge-nf-call-iptables=1 || die "could not set net.bridge.bridge-nf-call-iptables=1"

  local value
  value=$(cat "$BRIDGE_NF_FILE" 2>/dev/null || echo "missing")
  [[ "$value" == "1" ]] || die "bridge-nf-call-iptables is '$value', not 1. Container-to-container traffic would
bypass these firewall rules, so the analyzer could reach the gateway and Caddy. Not installing rules."

  # Keep it across reboots: load the module early, and set the sysctl (systemd applies sysctl.d
  # after modules-load.d, so the key exists by then).
  printf 'br_netfilter\n' >"$MODULES_LOAD_FILE"
  printf 'net.bridge.bridge-nf-call-iptables = 1\n' >"$SYSCTL_FILE"
  echo "Bridge filtering is on (br_netfilter loaded, bridge-nf-call-iptables=1, kept across reboots)."
}

remove_all() { # chain, then the rule: delete every copy (nothing happens if there is none)
  local chain=$1 rule=$2
  # shellcheck disable=SC2086 # the rule is deliberately split into separate arguments
  while iptables -C "$chain" $rule 2>/dev/null; do iptables -D "$chain" $rule; done
}

install_rules() {
  # Forwarded traffic, checked in this order (RETURN hands the packet back to Docker's own rules).
  local forward_rules=(
    "-s $ANALYZER -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment $TAG -j RETURN"
    "-s $ANALYZER -d $SUBNET -m comment --comment $TAG -j DROP"
  )
  local range rule position=1
  for range in "${BLOCKED[@]}"; do
    forward_rules+=("-s $ANALYZER -d $range -m comment --comment $TAG -j DROP")
  done
  # Traffic to the VM's own addresses is delivered locally, never forwarded, so it needs its own rule.
  local input_rule="-s $ANALYZER -m conntrack --ctstate NEW -m comment --comment $TAG -j DROP"

  for rule in "${forward_rules[@]}"; do remove_all DOCKER-USER "$rule"; done
  remove_all INPUT "$input_rule"

  for rule in "${forward_rules[@]}"; do
    # shellcheck disable=SC2086
    iptables -I DOCKER-USER "$position" $rule
    position=$((position + 1))
  done
  # shellcheck disable=SC2086
  iptables -I INPUT 1 $input_rule
}

main() {
  [[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0"
  command -v iptables >/dev/null || die "iptables not found. Install it first: sudo apt-get install -y iptables"
  iptables -n -L DOCKER-USER >/dev/null 2>&1 || die "The DOCKER-USER chain does not exist. Is Docker running? (sudo systemctl start docker)"

  ensure_bridge_filtering
  install_rules

  echo "Tripwire egress rules for $ANALYZER (network $SUBNET) are in place."
  echo
  echo "== DOCKER-USER (forwarded traffic) =="
  iptables -L DOCKER-USER -n -v --line-numbers
  echo
  echo "== INPUT (traffic to this VM itself), tripwire rule only =="
  iptables -S INPUT | grep -- "--comment $TAG" || true
  echo
  echo "Not persistent: after a reboot the rules come back through the systemd unit (deploy/DEPLOY.md)."
}

# Run only when executed, so the functions can be loaded by a test.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
