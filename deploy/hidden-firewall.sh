#!/usr/bin/env bash
# The host firewall a HIDDEN provider box needs and ufw cannot give it.
# Idempotent. Run by bootstrap.sh, and at every boot after docker by
# toon-hidden-firewall.service, because iptables rules do not survive a
# reboot and docker recreates DOCKER-USER empty.
#
#   ./hidden-firewall.sh
#
# Three rules, all in DOCKER-USER, the one chain docker leaves to the operator
# and evaluates ahead of its own forwarding rules (and which ufw never sees):
#
# 0. THE DAEMON REACHES A LEASE'S PORTS, and nothing else on its network does
#    (TOON_Network#181). The daemon dials a lease at the gateway of
#    `toon-provider-hidden` (provider.toml's `anon.forward_host`), and docker
#    DNATs that to the lease's forwarder on another bridge: a FORWARDED
#    connection, which rule 1 would drop like any other, and one leaving an
#    INTERNAL network, which docker's own isolation drops too (the network is
#    internal so the connector, the provider and the publisher have no route
#    off the box but anon's SOCKS port). So the daemon's pinned address, to
#    that gateway, on the lease ranges, is accepted first, and the replies
#    back to it. Measured on docker 29 in an isolated dind: without these the
#    daemon's dial times out, from an internal network or not; with them it
#    is answered, while another container on the same network still times
#    out and still has no direct route to the internet.
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
#    The daemon's own connections are rule 0's exception, above. (This file
#    used to say docker does not DNAT traffic arriving from one of its own
#    bridges, so the daemon's dial landed on docker-proxy through INPUT,
#    where ufw decides; docker 29 DNATs it from every bridge but the
#    forwarder's own, so it is FORWARDED, and rule 1 dropped it.
#    bootstrap.sh's ufw allowance for the daemon's address stays for a docker
#    that does take the INPUT path. An IPv6 connection to docker-proxy's
#    [::] listener is INPUT, and ufw's default deny covers it while
#    /etc/default/ufw keeps IPV6=yes, Ubuntu's default.)
#
#    The ranges MUST agree with provider.toml's ssh_port_start,
#    workload_port_start and workload id range, like the public box's ufw
#    rules must, and rule 0's addresses with docker-compose.hidden.yml and
#    provider.toml's forward_host; tests/deploy_bundle.rs checks that they
#    do.
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
# On docker 29 (dind, 29.8.1) the daemon's address timed out too under rule 1
# alone, which is what rule 0 fixes; with it, the same three results hold on
# the internal network.
# Rule 2 is the README's, and no host it has run on loads br_netfilter.
set -euo pipefail

EGRESS_BRIDGE=toon-hegress
# The hidden network's bridge, the daemon's pinned address on it, and the
# network's gateway, which is provider.toml's `anon.forward_host`.
HIDDEN_BRIDGE=toon-hidden
ANON_IP=172.30.2.2
FORWARD_HOST=172.30.2.1
# 100 workload ids: SSH forwards 40000-40099, 16-port blocks from 41000 to
# 42599. provider.toml.template.
SSH_RANGE=40000:40099
PORT_RANGE=41000:42599

# `-C` first, so a re-run adds nothing twice. `-I` so they sit ahead of the
# RETURN docker puts at the end of the chain.
rule() {
  iptables -C DOCKER-USER "$@" 2>/dev/null || iptables -I DOCKER-USER "$@"
}
# At the very top, whatever is already there: taken out and put back first
# on every run, so a rule `rule` adds later can never land above it.
first() {
  while iptables -C DOCKER-USER "$@" 2>/dev/null; do iptables -D DOCKER-USER "$@"; done
  iptables -I DOCKER-USER "$@"
}

if ! iptables -n -L DOCKER-USER >/dev/null 2>&1; then
  echo "hidden-firewall: DOCKER-USER does not exist yet; is docker running?" >&2
  exit 1
fi

for range in "$SSH_RANGE" "$PORT_RANGE"; do
  rule -p tcp -m conntrack --ctstate NEW --ctorigdstport "$range" \
    -m comment --comment 'toon hidden: no lease port from outside' -j DROP
done

# 0. THE DAEMON STILL REACHES A LEASE, from its internal network. Ahead of
#    rule 1, which would otherwise drop it, and of Docker's isolation of the
#    internal `toon-provider-hidden`, which drops everything leaving that
#    bridge for an address off its subnet (TOON_Network#181). The daemon
#    dials a lease at FORWARD_HOST:<port>, which Docker DNATs to the lease's
#    forwarder on another bridge: a FORWARDED connection, and one out of an
#    internal network. So: from the daemon's address alone, to the gateway
#    alone, on the lease ranges alone; and the replies back to it. Nothing
#    else on the hidden network, the connector, the provider and the
#    publisher included, gets either.
for range in "$SSH_RANGE" "$PORT_RANGE"; do
  first -i "$HIDDEN_BRIDGE" -s "$ANON_IP" -p tcp -m conntrack --ctorigdst "$FORWARD_HOST" \
    --ctorigdstport "$range" -m comment --comment 'toon hidden: anon to lease ports' -j ACCEPT
done
first -o "$HIDDEN_BRIDGE" -d "$ANON_IP" -p tcp -m conntrack --ctstate ESTABLISHED,RELATED \
  --ctorigsrc "$ANON_IP" --ctorigdst "$FORWARD_HOST" \
  -m comment --comment 'toon hidden: lease replies to anon' -j ACCEPT

if [ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || echo 0)" = 1 ]; then
  rule -i "$EGRESS_BRIDGE" -o "$EGRESS_BRIDGE" \
    -m comment --comment 'toon hidden: egress under br_netfilter' -j ACCEPT
  echo "hidden-firewall: br_netfilter is loaded; accepted bridged traffic on ${EGRESS_BRIDGE}"
fi

echo "hidden-firewall: workload ports ${SSH_RANGE} and ${PORT_RANGE} closed to forwarded traffic"
