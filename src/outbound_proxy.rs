// Where a Hidden Provider's OWN outbound goes (spec §10, ADR 0008).
//
// Hiding the workloads is not enough. A provider whose process dials relays,
// gateways and registries from its real address has published its location to
// every relay operator it reads from, whatever its Profile says. So with
// `hidden = true` every connection this process opens for itself leaves
// through the `anon` daemon's SOCKS port, named by `anon.socks_proxy`:
//
// - the relay websockets — Liveness watching, Profile lookups, Takeover and
//   Blob Record queries (`directory`);
// - the TOON store gateway, the upstream OCI registries and the anonymous
//   pull-token exchange they challenge with (`provider::fetcher`,
//   `provider::oci`);
// - the publish request to the directory publisher, when that publisher is
//   not on this host's loopback (`directory::ConnectorDirectory`).
//
// The scheme is `socks5h`, never `socks5`, and the config gate already
// refuses anything else: the `h` is what makes the PROXY resolve the name. A
// `socks5` client resolves `<base32>.anyone` — or a relay's hostname — with
// this host's resolver first, which is the one lookup a hidden provider must
// never make.
//
// The PROXY'S OWN host is resolved here, locally and once, because it has to
// be: nostr-sdk's SOCKS connection mode takes a `SocketAddr`, and a name that
// only the proxy could resolve cannot name the proxy itself. That leaks
// nothing — it is a lookup of the daemon beside this process (`127.0.0.1`, or
// `anon` on a compose network), not of anywhere this provider is about to
// talk to.

use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::{anyhow, bail, Context, Result};
use url::Url;

/// A resolved `socks5h://<host>:<port>`: the URL reqwest is handed, and the
/// address nostr-sdk's connection mode needs.
///
/// Cheap to clone, and built once at startup (`AppState::new`) so the DNS
/// lookup for the daemon happens once rather than per connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundProxy {
    url: String,
    addr: SocketAddr,
}

impl OutboundProxy {
    /// Parse and resolve `anon.socks_proxy`.
    ///
    /// The shape is checked again here rather than trusted from
    /// `ProviderConfig::validate`: this is also the door a test and a future
    /// caller come in by, and a `socks5://` URL that reached the clients
    /// below would resolve every destination name on this host — the one
    /// failure that hiding cannot survive and that nothing downstream would
    /// report.
    pub fn resolve(socks_proxy: &str) -> Result<Self> {
        let url = Url::parse(socks_proxy)
            .with_context(|| format!("anon.socks_proxy {:?} is not a URL", socks_proxy))?;
        if url.scheme() != "socks5h" {
            bail!(
                "anon.socks_proxy {:?} must be socks5h://<host>:<port>: only a socks5h proxy \
                 resolves the destination's name itself, and a Hidden Provider must never \
                 resolve one here (spec §10)",
                socks_proxy
            );
        }
        let (Some(host), Some(port)) = (url.host_str(), url.port()) else {
            bail!(
                "anon.socks_proxy {:?} must name both a host and a port",
                socks_proxy
            );
        };
        let addr = (host, port)
            .to_socket_addrs()
            .with_context(|| {
                format!(
                    "anon.socks_proxy {:?} names {}, which does not resolve here — is the anon \
                     daemon's SOCKS port reachable from this process?",
                    socks_proxy, host
                )
            })?
            .next()
            .ok_or_else(|| {
                anyhow!(
                    "anon.socks_proxy {:?} names {}, which resolves to no address",
                    socks_proxy,
                    host
                )
            })?;
        Ok(Self {
            url: socks_proxy.to_string(),
            addr,
        })
    }

    /// The `socks5h://…` URL, as reqwest and the directory publisher take it.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The proxy's own address, as nostr-sdk's connection mode takes it.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every request `builder` makes leaves through this proxy, names
    /// included.
    pub fn apply(&self, builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
        let proxy = reqwest::Proxy::all(&self.url)
            .with_context(|| format!("{} is not a proxy reqwest can use", self.url))?;
        Ok(builder.proxy(proxy))
    }
}

/// Whether `url` names a host on this machine's loopback.
///
/// The one place a hidden provider dials directly: its own directory
/// publisher, one process over on `127.0.0.1`. Sending that request through
/// `anon` would ask the daemon to build a circuit back to the host it started
/// on — which it refuses — and would hide nothing, because a loopback packet
/// never leaves this box. The publisher is handed the proxy IN the request
/// instead, and rides it for the connector hop that does leave.
pub fn is_loopback_url(url: &str) -> bool {
    let Ok(url) = Url::parse(url) else {
        return false;
    };
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socks5h_proxy_on_loopback_resolves() {
        let proxy = OutboundProxy::resolve("socks5h://127.0.0.1:9050").unwrap();
        assert_eq!(proxy.url(), "socks5h://127.0.0.1:9050");
        assert_eq!(proxy.addr().port(), 9050);
        assert!(proxy.addr().ip().is_loopback());
    }

    #[test]
    fn a_socks5_proxy_is_refused_by_scheme() {
        let refused = OutboundProxy::resolve("socks5://127.0.0.1:9050").unwrap_err();
        let why = format!("{refused:#}");
        assert!(why.contains("socks5h"), "{why}");
        assert!(why.contains("resolves the destination's name"), "{why}");
    }

    #[test]
    fn a_proxy_without_a_port_is_refused() {
        let refused = OutboundProxy::resolve("socks5h://127.0.0.1").unwrap_err();
        assert!(format!("{refused:#}").contains("host and a port"));
    }

    #[test]
    fn loopback_is_told_from_everywhere_else() {
        assert!(is_loopback_url("http://127.0.0.1:8081/publish"));
        assert!(is_loopback_url("http://localhost:8081/publish"));
        assert!(is_loopback_url("http://[::1]:8081/publish"));
        assert!(!is_loopback_url("http://publisher:8081/publish"));
        assert!(!is_loopback_url("http://10.0.0.4:8081/publish"));
        assert!(!is_loopback_url("not a url"));
    }
}
