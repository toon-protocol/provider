#!/usr/bin/env bash
# The host firewall a HIDDEN provider box needs and ufw cannot give it.
# Idempotent. Run by bootstrap.sh, and at every boot after docker by
# toon-hidden-firewall.service, because iptables rules do not survive a
# reboot and docker recreates DOCKER-USER empty.
#
#   ./hidden-firewall.sh
#
# Two rules, both in DOCKER-USER, the one chain docker leaves to the operator
# and evaluates ahead of its own forwarding rules (and which ufw never sees):
#
# 1. NOTHING FROM OUTSIDE REACHES A LEASE'S PORTS. A hidden lease is reached at
#    its own `.anyone` address, which the anon daemon forwards to the lease's
#    ports on this host: the lease's ingress forwarder publishes them here, at
#    the same numbers a public lease would use. Published means reachable on
#    every address this host has, public ones included, whatever ufw says,
#    because docker DNATs them in PREROUTING and forwards them past ufw's
#    INPUT rules. A tenant who found its own workload answering at <this box's
#    IP>:<its port> would have found the box, which is the one thing it must
#    not learn. So every NEW forwarded connection whose original destination
#    is in the workload ranges is dropped here.
#
#    The daemon's own connections are not affected, and that is not an
#    exception written here: docker does not DNAT traffic that arrives from
#    one of its bridges. The daemon dials the lease at the gateway of
#    `toon-provider-hidden` (provider.toml's `anon.forward_host`), which lands
#    on docker-proxy through the host's INPUT chain, where ufw decides.
#    bootstrap.sh allows exactly the daemon's address there and nothing else,
#    so the provider's other containers cannot reach a lease either. (An
#    IPv6 connection to docker-proxy's [::] listener is INPUT too, and ufw's
#    default deny covers it while /etc/default/ufw keeps IPV6=yes, Ubuntu's
#    default.)
#
#    The ranges MUST agree with provider.toml's ssh_port_start,
#    workload_port_start and workload id range, like the public box's ufw
#    rules must; tests/deploy_bundle.rs checks that they do.
#
# 2. br_netfilter. A host with it loaded (`net.bridge.bridge-nf-call-iptables
#    = 1`) runs bridged frames through iptables, and Docker's isolation of an
#    internal network then drops everything not addressed within its subnet,
#    which is every packet a workload sends to the anon daemon to be
#    proxied: the transparent egress stops working with no error anywhere.
#    Accepting bridge-to-bridge traffic on the egress bridge puts it back
#    (provider README, "Workload egress on a Hidden Provider"). Added only when
#    the module is loaded; most hosts, the reference one included, do not load
#    it.
#
# Rule 1 and the ufw allowance were checked together on docker 28 in an
# isolated dind, with INPUT dropping by default as ufw's does: from outside, a
# lease port times out with rule 1 and answers without it; from the daemon's
# address it answers; from any other container on the network it times out.
# Rule 2 is the README's, and no host it has run on loads br_netfilter.
set -euo pipefail

EGRESS_BRIDGE=toon-hegress
# 100 workload ids: SSH forwards 40000-40099, 16-port blocks from 41000 to
# 42599. provider.toml.template.
SSH_RANGE=40000:40099
PORT_RANGE=41000:42599

# `-C` first, so a re-run adds nothing twice. `-I` so they sit ahead of the
# RETURN docker puts at the end of the chain.
rule() {
  iptables -C DOCKER-USER "$@" 2>/dev/null || iptables -I DOCKER-USER "$@"
}

if ! iptables -n -L DOCKER-USER >/dev/null 2>&1; then
  echo "hidden-firewall: DOCKER-USER does not exist yet; is docker running?" >&2
  exit 1
fi

for range in "$SSH_RANGE" "$PORT_RANGE"; do
  rule -p tcp -m conntrack --ctstate NEW --ctorigdstport "$range" \
    -m comment --comment 'toon hidden: no lease port from outside' -j DROP
done

if [ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || echo 0)" = 1 ]; then
  rule -i "$EGRESS_BRIDGE" -o "$EGRESS_BRIDGE" \
    -m comment --comment 'toon hidden: egress under br_netfilter' -j ACCEPT
  echo "hidden-firewall: br_netfilter is loaded; accepted bridged traffic on ${EGRESS_BRIDGE}"
fi

echo "hidden-firewall: workload ports ${SSH_RANGE} and ${PORT_RANGE} closed to forwarded traffic"
