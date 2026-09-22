// Where a tenant's image may send this provider (spec §8.4, ADR 0022,
// TOON_Network#105, TOON_Network#107).
//
// A spawn's `image.reference` names the registry, and the provider dials it:
// `reference.example/team/app` becomes `https://reference.example/v2/...`.
// Nothing about that host is the provider's own. So without this module a
// tenant writes `127.0.0.1:9944/x/y`, or `169.254.169.254/x/y`, or a name
// that resolves to `10.0.0.5`, and the provider issues requests inside its
// operator's network on the tenant's behalf — over `availability`, which is
// free and unsigned, so the request costs nothing and leaves no payment
// trail. A registry answering 401 widens it again: the `Www-Authenticate`
// realm is a URL the registry chooses and the provider fetches, and so is a
// redirect's `Location`.
//
// The rule is therefore one rule, applied to EVERY outbound host of an image
// fetch — the registry, the token realm, and every redirect hop: the address
// dialled must be publicly routable. Not the name: the ADDRESS, because a
// name is whatever its owner's DNS says it is.
//
// Which means the check and the connection must agree about the address, or
// the check is decoration — a name resolved for the check and resolved again
// for the connection can differ between the two lookups (DNS rebinding), and
// the second answer is the one that gets dialled. So this guard IS the
// resolver: `Resolve` hands reqwest only the addresses that passed, reqwest
// connects to one of those and never looks the name up again. There is no
// second lookup to rebind. A host written as an address literal never
// reaches a resolver at all, so `check_url` refuses those before the request
// is sent.
//
// A spawn's `registry_entry.relay` is the same exposure over a different
// transport: a tenant-chosen URL this provider dials as a websocket to read
// the Image Registry entry, on the same free `availability` route. It gets
// the same rule (`check_relay`), with one difference the transport forces —
// nostr-sdk resolves and dials the name itself, so the name is resolved here
// and refused before the dial rather than resolved ONCE for both. What that
// costs is written out on `check_relay`.
//
// Two things this does NOT cover, on purpose:
//
// - A Hidden Provider's fetches leave through `anon` as `socks5h`, which
//   means the PROXY resolves every name and this process must never resolve
//   one itself (`outbound_proxy`). reqwest does not call a DNS resolver for
//   a proxied request, so on a hidden provider only address literals are
//   checked here. That is the right trade: an exit relay's idea of "private"
//   is not the operator's network, nothing an exit can reach is inside it,
//   and a local lookup to check would undo the hiding that is the point.
// - A host an operator has exempted is exempt by NAME, and a name resolves
//   wherever its owner says. That is the operator's own registry, named by
//   the operator in their own config file — the one party whose reach inside
//   their network is not a vulnerability.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use url::{Host, Url};

use crate::provider::is_private_ip;

/// How many redirects one image request may be led through before the
/// provider gives up. A registry legitimately redirects a blob pull to its
/// storage backend, occasionally twice; nothing real needs five, and each
/// hop is a fresh host this guard has to check.
pub const MAX_REDIRECTS: usize = 5;

/// Whether a packet to `ip` leaves for the public internet: NOT loopback,
/// a private range, link-local (`169.254.0.0/16`, which is where a cloud
/// instance's metadata service lives), multicast, broadcast or unspecified,
/// in v4; and NOT loopback, unique-local, link-local, multicast or
/// unspecified in v6, with an IPv4-mapped address judged as the IPv4 it
/// maps.
///
/// `is_private_ip` — the Hidden Provider's settlement-RPC rule (spec §10) —
/// is the larger half of this, and is reused rather than restated so an
/// operator has one notion of "not out there" to hold. This adds what a
/// destination rule needs beyond it: multicast and broadcast, which are not
/// "private" but are not somewhere a registry is either.
pub fn is_publicly_routable(ip: IpAddr) -> bool {
    if is_private_ip(ip) || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_broadcast(),
        IpAddr::V6(_) => true,
    }
}

/// One entry of `image_policy.exempt_registries`, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Exemption {
    /// `registry.internal` — that name, whatever port it is asked for on
    /// and whatever it resolves to.
    Host(String),
    /// `registry.internal:5000` or `10.0.0.5:5000` — that host on that port.
    /// The port is only enforced for an address literal: a NAME is exempted
    /// in the resolver, which is handed a name and no port at all.
    Authority(String, u16),
    /// `10.0.0.0/8`, or a bare `10.0.0.5` as a single address. Matched
    /// against an address literal in a URL and against every address a name
    /// resolves to.
    Net(IpAddr, u8),
}

impl Exemption {
    fn parse(entry: &str) -> Result<Self> {
        let entry = entry.trim();
        if entry.is_empty() {
            bail!("an empty entry names nothing");
        }
        if let Some((addr, prefix)) = entry.split_once('/') {
            let addr: IpAddr = addr
                .parse()
                .with_context(|| format!("{:?} is not an address", addr))?;
            let prefix: u8 = prefix
                .parse()
                .with_context(|| format!("{:?} is not a prefix length", prefix))?;
            let width = if addr.is_ipv4() { 32 } else { 128 };
            if prefix > width {
                bail!("a /{} prefix is longer than the address it masks", prefix);
            }
            return Ok(Self::Net(addr, prefix));
        }
        if let Ok(addr) = entry.parse::<IpAddr>() {
            return Ok(Self::Net(addr, if addr.is_ipv4() { 32 } else { 128 }));
        }
        // `[::1]:5000`, the bracketed form a URL writes an IPv6 authority
        // in, before the bare `host:port` one.
        if let Some(rest) = entry.strip_prefix('[') {
            let (addr, port) = rest
                .split_once("]:")
                .ok_or_else(|| anyhow!("{:?} is not [address]:port", entry))?;
            let addr: IpAddr = addr
                .parse()
                .with_context(|| format!("{:?} is not an address", addr))?;
            let port: u16 = port
                .parse()
                .with_context(|| format!("{:?} is not a port", port))?;
            return Ok(Self::Authority(addr.to_string(), port));
        }
        // A bare IPv6 address was already taken above, so a `:` left here is
        // a port — and one that will not parse is a typo, not a host name
        // with a colon in it, which no host name has.
        match entry.rsplit_once(':') {
            Some((host, port)) => {
                let port: u16 = port
                    .parse()
                    .with_context(|| format!("{:?} is not a port", port))?;
                if host.is_empty() {
                    bail!("{:?} names a port but no host", entry);
                }
                Ok(Self::Authority(host.to_ascii_lowercase(), port))
            }
            None => Ok(Self::Host(entry.to_ascii_lowercase())),
        }
    }

    /// The host part, for a name exemption; `None` for a network, which is
    /// matched on the address instead.
    fn host(&self) -> Option<&str> {
        match self {
            Self::Host(host) | Self::Authority(host, _) => Some(host),
            Self::Net(..) => None,
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let Self::Net(net, prefix) = self else {
            return false;
        };
        match (net, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                masked(&net.octets(), *prefix) == masked(&ip.octets(), *prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                masked(&net.octets(), *prefix) == masked(&ip.octets(), *prefix)
            }
            // An IPv4-mapped v6 address is the v4 address it maps, so a v4
            // network exempts it too: the packet goes to the same machine.
            (IpAddr::V4(_), IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
                Some(v4) => self.contains(IpAddr::V4(v4)),
                None => false,
            },
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

/// `octets` with everything past `prefix` bits zeroed.
fn masked<const N: usize>(octets: &[u8; N], prefix: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, byte) in octets.iter().enumerate() {
        let bits = (prefix as usize).saturating_sub(i * 8).min(8);
        out[i] = if bits == 0 {
            0
        } else {
            byte & (!0u8 << (8 - bits))
        };
    }
    out
}

/// The rule, plus what the OPERATOR has exempted from it.
///
/// Cheap to clone (a short list of parsed entries), and both a resolver and
/// a pre-send check: the same list answers both, so a host cannot be exempt
/// at one door and refused at the other.
#[derive(Debug, Clone, Default)]
pub struct OutboundGuard {
    exempt: Vec<Exemption>,
}

impl OutboundGuard {
    /// `image_policy.exempt_registries`, parsed. An entry that is neither a
    /// host, a `host:port` nor a CIDR is a refusal, not a warning: an
    /// operator who meant to let their registry through and mistyped it
    /// must hear about it at load, not discover it as a fetch failure.
    pub fn new(exempt_registries: &[String]) -> Result<Self> {
        let mut exempt = Vec::with_capacity(exempt_registries.len());
        for entry in exempt_registries {
            exempt.push(Exemption::parse(entry).with_context(|| {
                format!("image_policy.exempt_registries entry {:?} is not a host, a host:port or a CIDR", entry)
            })?);
        }
        Ok(Self { exempt })
    }

    /// Also exempt whatever `url` names, when there is one: how the URLs an
    /// OPERATOR configured — `image_policy.registry_url_override`,
    /// `gateway_url_pattern` — stay reachable without being written out a
    /// second time in `exempt_registries`. They are not tenant values; a
    /// tenant cannot reach them or change them, and a provider whose store
    /// gateway is `http://envoy:3000` on its own compose network is the
    /// normal case, not an attack.
    ///
    /// Exempt by AUTHORITY (host and port), not by host: a `{txid}`
    /// placeholder in the path is irrelevant, but `127.0.0.1:3000` being the
    /// operator's gateway must not make every other port on loopback
    /// fetchable.
    pub fn exempting(mut self, url: Option<&str>) -> Self {
        if let Some(parsed) = url.and_then(|u| Url::parse(u).ok()) {
            if let (Some(host), Some(port)) = (parsed.host_str(), parsed.port_or_known_default()) {
                self.exempt
                    .push(Exemption::Authority(host.to_ascii_lowercase(), port));
            }
        }
        self
    }

    /// Whether the operator has exempted `url`'s authority outright.
    fn exempts(&self, url: &Url) -> bool {
        let Some(host) = url.host() else {
            return false;
        };
        let port = url.port_or_known_default();
        let named = match &host {
            Host::Domain(name) => self.exempts_name(name),
            Host::Ipv4(ip) => self.exempts_host(&ip.to_string(), port),
            Host::Ipv6(ip) => self.exempts_host(&ip.to_string(), port),
        };
        named
            || match host {
                Host::Ipv4(ip) => self.exempts_addr(IpAddr::V4(ip)),
                Host::Ipv6(ip) => self.exempts_addr(IpAddr::V6(ip)),
                Host::Domain(_) => false,
            }
    }

    /// Whether `name` is exempt as a name. The port is not considered: this
    /// is also what the resolver asks, and a resolver is handed a name
    /// alone.
    fn exempts_name(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.exempt.iter().any(|e| e.host() == Some(name.as_str()))
    }

    fn exempts_host(&self, host: &str, port: Option<u16>) -> bool {
        self.exempt.iter().any(|e| match e {
            Exemption::Host(exempt) => exempt == host,
            Exemption::Authority(exempt, exempt_port) => {
                exempt == host && Some(*exempt_port) == port
            }
            Exemption::Net(..) => false,
        })
    }

    fn exempts_addr(&self, ip: IpAddr) -> bool {
        self.exempt.iter().any(|e| e.contains(ip))
    }

    /// Refuse `url` if its host is an address this provider must not dial.
    ///
    /// A NAME passes here and is judged by the resolver instead, on what it
    /// resolves to — which is the only judgement that can agree with the
    /// connection. So this is the whole check for an address literal and
    /// half of it for a name; both halves read the same exemption list.
    pub fn check_url(&self, url: &Url) -> Result<()> {
        if self.exempts(url) {
            return Ok(());
        }
        let refuse = |host: String| {
            anyhow!(
                "{} is not a publicly routable address: this provider does not fetch an image \
                 from inside its operator's own network (spec §8.4, TOON_Network#105). An \
                 operator whose registry is internal names it in image_policy.exempt_registries",
                host
            )
        };
        match url.host() {
            Some(Host::Ipv4(ip)) if !is_publicly_routable(IpAddr::V4(ip)) => {
                Err(refuse(ip.to_string()))
            }
            Some(Host::Ipv6(ip)) if !is_publicly_routable(IpAddr::V6(ip)) => {
                Err(refuse(ip.to_string()))
            }
            Some(_) => Ok(()),
            None => bail!("{} names no host to fetch from", url.scheme()),
        }
    }

    /// The same, for a bearer challenge's `realm` — the one outbound URL a
    /// REGISTRY chooses rather than the tenant. It must also be `https`: the
    /// answer to it is a credential this provider then presents, and the
    /// request carries the repository it is pulling, so a plain-http realm
    /// hands both to anyone on the path.
    ///
    /// An exempt host is exempt from the scheme too: an operator's own
    /// registry on their own network commonly speaks plain http, and the
    /// operator has already said that host is theirs.
    pub fn check_realm(&self, url: &Url) -> Result<()> {
        if self.exempts(url) {
            return Ok(());
        }
        if url.scheme() != "https" {
            bail!(
                "the bearer realm {}://{} is not https: a provider will not send a pull-token \
                 request in the clear (TOON_Network#105)",
                url.scheme(),
                url.host_str().unwrap_or("")
            );
        }
        self.check_url(url)
    }

    /// The same rule for the one outbound address a tenant names that is NOT
    /// an image fetch: the `relay` of a spawn's `registry_entry`, dialled as
    /// a websocket to read the entry (spec §6.2 step 5, TOON_Network#107).
    ///
    /// `ws` or `wss` and nothing else: a relay speaks NIP-01 over a
    /// websocket, and every other scheme a URL parser accepts is a different
    /// protocol being reached through this door.
    ///
    /// Why this is a check and not a resolver, unlike the image path: the
    /// websocket is nostr-sdk's, which resolves the name itself inside
    /// `connect` and hands the addresses to nobody. There is no seam to be
    /// the resolver of, so the name is resolved HERE and refused before
    /// `add_relay` — which leaves a window: the lookup this makes and the
    /// lookup the dial makes are two lookups, and a name whose owner answers
    /// them differently (DNS rebinding) is dialled on the second answer.
    /// Two things narrow it as far as a check can. EVERY address must pass,
    /// not merely one — the dialler tries them all (RFC 8305 happy
    /// eyeballs), so one private address among public ones is a private
    /// address that gets dialled. And a name that cannot be resolved at all
    /// is refused rather than passed on: a resolver that answers SERVFAIL
    /// once and the truth once would otherwise be a bypass that needs no
    /// race to win.
    ///
    /// `resolve_names` is false on a Hidden Provider, where the SOCKS proxy
    /// resolves every name and this process must resolve none (spec §10,
    /// ADR 0008) — the same trade `outbound_proxy` makes for image fetches,
    /// for the same reason: an exit relay's idea of "private" is not the
    /// operator's network, and a lookup here would undo the hiding that is
    /// the point. An address literal is still checked.
    pub async fn check_relay(&self, relay: &str, resolve_names: bool) -> Result<()> {
        let url = Url::parse(relay)
            .with_context(|| format!("the relay hint {:?} is not a URL", relay))?;
        if !matches!(url.scheme(), "ws" | "wss") {
            bail!(
                "the relay hint {} is not ws or wss: a provider reads an Image Registry entry \
                 over a websocket and nothing else (spec §8.4, TOON_Network#107)",
                relay
            );
        }
        let Some(host) = url.host() else {
            bail!("the relay hint {} names no relay to read from", relay);
        };
        // By AUTHORITY, not by name: an operator whose relay is at
        // `ws://relay:7100` has said that relay is theirs, not that the rest
        // of the host's ports are.
        if self.exempts_host(
            &host.to_string().to_ascii_lowercase(),
            url.port_or_known_default(),
        ) {
            return Ok(());
        }
        let refuse = || {
            anyhow!(
                "the relay hint {} is not at a publicly routable address: this provider does not \
                 read an Image Registry entry from inside its operator's own network (spec §8.4, \
                 TOON_Network#107). An operator whose relay is internal names it in relay_set",
                relay
            )
        };
        match host {
            Host::Ipv4(ip) => self
                .may_dial(IpAddr::V4(ip))
                .then_some(())
                .ok_or_else(refuse),
            Host::Ipv6(ip) => self
                .may_dial(IpAddr::V6(ip))
                .then_some(())
                .ok_or_else(refuse),
            Host::Domain(name) if resolve_names => {
                let addrs = resolve_all(name).await.map_err(|e| {
                    anyhow!(
                        "the relay hint {} could not be resolved, so this provider will not dial \
                         it (TOON_Network#107): {}",
                        relay,
                        e
                    )
                })?;
                if addrs.is_empty() || !addrs.iter().all(|addr| self.may_dial(addr.ip())) {
                    return Err(refuse());
                }
                Ok(())
            }
            Host::Domain(_) => Ok(()),
        }
    }

    /// Whether a packet to `ip` may leave: publicly routable, or somewhere
    /// the operator has exempted.
    fn may_dial(&self, ip: IpAddr) -> bool {
        is_publicly_routable(ip) || self.exempts_addr(ip)
    }

    /// The redirect policy for a client that fetches images: every hop is
    /// checked like the first request, and the chain is capped.
    pub fn redirect_policy(self: &Arc<Self>) -> reqwest::redirect::Policy {
        let guard = Arc::clone(self);
        reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                return attempt.error(anyhow!(
                    "the registry redirected more than the {} times a fetch follows",
                    MAX_REDIRECTS
                ));
            }
            match guard.check_url(attempt.url()) {
                Ok(()) => attempt.follow(),
                Err(why) => attempt.error(why),
            }
        })
    }
}

impl Resolve for OutboundGuard {
    /// Resolve `name` and hand back ONLY the addresses a fetch may dial.
    ///
    /// reqwest connects to what this returns and does not resolve the name
    /// again, so the address checked is the address dialled. A name that
    /// resolves only inward resolves, here, to nothing — and is reported as
    /// a refusal naming the NAME, never the address behind it: the tenant
    /// asked about a source, and what the operator's DNS says about it is
    /// not the tenant's to learn.
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let guard = self.clone();
        Box::pin(async move {
            if guard.exempts_name(&host) {
                return resolve_all(&host).await.map(boxed);
            }
            let addrs = resolve_all(&host).await?;
            let allowed: Vec<SocketAddr> = addrs
                .into_iter()
                .filter(|addr| is_publicly_routable(addr.ip()) || guard.exempts_addr(addr.ip()))
                .collect();
            if allowed.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "{} is not at a publicly routable address: this provider does not fetch \
                         an image from inside its operator's own network (spec §8.4, \
                         TOON_Network#105)",
                        host
                    ),
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(boxed(allowed))
        })
    }
}

fn boxed(addrs: Vec<SocketAddr>) -> Addrs {
    Box::new(addrs.into_iter())
}

/// `getaddrinfo` off the runtime thread, the way reqwest's own default
/// resolver does it. Port `0`: reqwest puts the URL's port back on whatever
/// comes out, and only the address is this module's business.
async fn resolve_all(
    host: &str,
) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    let host = host.to_string();
    let addrs = tokio::task::spawn_blocking(move || {
        (host.as_str(), 0u16)
            .to_socket_addrs()
            .map(|addrs| addrs.collect::<Vec<_>>())
    })
    .await
    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?
    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn nothing_is_exempt_by_default() {
        let guard = OutboundGuard::default();
        for written in [
            "https://127.0.0.1/v2/x/manifests/y",
            "https://169.254.169.254/v2/x/manifests/y",
            "https://10.0.0.5:5000/v2/x/manifests/y",
            "https://192.168.1.1/v2/x/manifests/y",
            "https://172.16.0.1/v2/x/manifests/y",
            "https://[::1]/v2/x/manifests/y",
            "https://[fc00::1]/v2/x/manifests/y",
            "https://[fe80::1]/v2/x/manifests/y",
            "https://[::]/v2/x/manifests/y",
            "https://0.0.0.0/v2/x/manifests/y",
            "https://224.0.0.1/v2/x/manifests/y",
            "https://[ff02::1]/v2/x/manifests/y",
            "https://255.255.255.255/v2/x/manifests/y",
            // The v4 address behind a v6 wrapper is the v4 address.
            "https://[::ffff:127.0.0.1]/v2/x/manifests/y",
        ] {
            assert!(
                guard.check_url(&url(written)).is_err(),
                "{} must be refused",
                written
            );
        }
    }

    #[test]
    fn a_public_registry_is_not_refused() {
        let guard = OutboundGuard::default();
        for written in [
            "https://registry-1.docker.io/v2/library/alpine/manifests/x",
            "https://203.0.113.7/v2/x/manifests/y",
            "https://[2001:db8::1]/v2/x/manifests/y",
        ] {
            assert!(guard.check_url(&url(written)).is_ok(), "{}", written);
        }
    }

    #[test]
    fn an_operator_exempts_a_host_or_a_cidr() {
        let guard = OutboundGuard::new(&[
            "registry.internal".to_string(),
            "10.0.0.0/8".to_string(),
            "192.168.1.9:5000".to_string(),
        ])
        .unwrap();
        assert!(guard.check_url(&url("http://10.1.2.3:5000/v2/")).is_ok());
        assert!(guard.check_url(&url("http://192.168.1.9:5000/v2/")).is_ok());
        assert!(guard.exempts_name("registry.internal"));
        assert!(guard.exempts_name("REGISTRY.INTERNAL"));
        // The port is part of an authority exemption, for an address.
        assert!(guard
            .check_url(&url("http://192.168.1.9:5001/v2/"))
            .is_err());
        // And nothing else moved.
        assert!(guard.check_url(&url("http://127.0.0.1:5000/v2/")).is_err());
        assert!(guard.check_url(&url("http://172.16.0.1/v2/")).is_err());
    }

    #[test]
    fn an_operators_own_url_is_exempt_by_authority() {
        let guard = OutboundGuard::default().exempting(Some("http://127.0.0.1:3000/raw/{txid}"));
        assert!(guard
            .check_url(&url("http://127.0.0.1:3000/raw/abc"))
            .is_ok());
        assert!(guard.check_url(&url("http://127.0.0.1:9944/v2/")).is_err());
    }

    #[test]
    fn an_entry_that_is_neither_a_host_nor_a_cidr_is_refused_at_load() {
        for written in [
            "",
            "10.0.0.0/99",
            "10.0.0.0/notaprefix",
            "1.2.3.4/",
            // A port that is not one: a typo an operator must hear about,
            // not a host name nothing will ever match.
            "registry.internal:http",
            ":5000",
        ] {
            assert!(
                OutboundGuard::new(&[written.to_string()]).is_err(),
                "{:?} must be refused",
                written
            );
        }
    }

    #[test]
    fn a_realm_must_be_https_unless_the_operator_owns_it() {
        let guard = OutboundGuard::new(&["registry.internal".to_string()]).unwrap();
        assert!(guard
            .check_realm(&url("https://auth.example/token"))
            .is_ok());
        assert!(guard
            .check_realm(&url("http://auth.example/token"))
            .is_err());
        assert!(guard
            .check_realm(&url("http://registry.internal/token"))
            .is_ok());
        // https is not enough on its own.
        assert!(guard.check_realm(&url("https://127.0.0.1/token")).is_err());
    }

    #[tokio::test]
    async fn a_relay_hint_is_ws_or_wss_and_nothing_else() {
        let guard = OutboundGuard::default();
        for written in [
            "http://relay.example",
            "https://relay.example",
            "socks5h://relay.example",
            "file:///etc/passwd",
            "redis://203.0.113.7:6379",
        ] {
            let why = guard
                .check_relay(written, true)
                .await
                .expect_err(written)
                .to_string();
            assert!(why.contains("ws or wss"), "{}: {}", written, why);
        }
    }

    #[tokio::test]
    async fn a_relay_hint_at_the_operators_own_network_is_refused() {
        let guard = OutboundGuard::default();
        for written in [
            "ws://127.0.0.1:7100",
            "wss://169.254.169.254",
            "ws://10.0.0.5:7100",
            "ws://[::1]:7100",
            "ws://[::ffff:127.0.0.1]:7100",
            // A name is judged on what it resolves to, and the refusal
            // names the NAME.
            "ws://localhost:7100",
        ] {
            let why = guard
                .check_relay(written, true)
                .await
                .expect_err(written)
                .to_string();
            assert!(why.contains(written), "{}: {}", written, why);
        }
        assert!(guard.check_relay("wss://203.0.113.7", true).await.is_ok());
        assert!(guard
            .check_relay("ws://[2001:db8::1]:7100", true)
            .await
            .is_ok());
    }

    /// The refusal is about the source the tenant named. What the operator's
    /// DNS says about it is not the tenant's to learn.
    #[tokio::test]
    async fn a_refused_relay_hint_never_names_the_address_it_resolved_to() {
        let why = OutboundGuard::default()
            .check_relay("ws://localhost:7100", true)
            .await
            .expect_err("localhost resolves inward")
            .to_string();
        assert!(why.contains("ws://localhost:7100"), "{}", why);
        assert!(
            !why.contains("127.0.0.1") && !why.contains("::1"),
            "{}",
            why
        );
    }

    /// A name nobody answers for is refused rather than dialled: a resolver
    /// that fails once and answers the truth once would otherwise be a
    /// bypass that needs no race to win.
    #[tokio::test]
    async fn a_relay_hint_that_does_not_resolve_is_refused() {
        assert!(OutboundGuard::default()
            .check_relay("ws://relay.invalid:7100", true)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn the_operators_own_relay_is_exempt_by_authority() {
        let guard = OutboundGuard::default().exempting(Some("ws://relay:7100"));
        assert!(guard.check_relay("ws://relay:7100", true).await.is_ok());
        // The rest of that host is not the operator's relay.
        assert!(guard.check_relay("ws://relay:9944", true).await.is_err());
        // And the scheme rule still applies to it.
        assert!(guard.check_relay("http://relay:7100", true).await.is_err());
    }

    /// A Hidden Provider resolves no name itself — the `anon` SOCKS proxy
    /// does (spec §10, ADR 0008) — so a name passes and a literal is still
    /// checked.
    #[tokio::test]
    async fn a_hidden_provider_checks_literals_and_leaves_names_to_the_proxy() {
        let guard = OutboundGuard::default();
        assert!(guard
            .check_relay("ws://ykjcp2i3ur4bnkmcrt5x.anyone:7100", false)
            .await
            .is_ok());
        assert!(guard
            .check_relay("ws://localhost:7100", false)
            .await
            .is_ok());
        assert!(guard
            .check_relay("ws://127.0.0.1:7100", false)
            .await
            .is_err());
    }

    #[test]
    fn a_cidr_masks_on_bit_boundaries_that_are_not_bytes() {
        let guard = OutboundGuard::new(&["10.0.0.0/12".to_string()]).unwrap();
        assert!(guard.exempts_addr("10.15.255.255".parse().unwrap()));
        assert!(!guard.exempts_addr("10.16.0.0".parse().unwrap()));
    }
}
