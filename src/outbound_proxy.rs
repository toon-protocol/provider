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
//   not on this host or its own private network
//   (`directory::ConnectorDirectory`).
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
//
// Once, and therefore PINNED: a daemon container that restarts onto a new
// address is dialled stale by the relay clients until this provider restarts
// too. The HTTP clients are given the URL and re-resolve it per connection;
// only nostr-sdk's `SocketAddr` cannot. Living with it is deliberate — the
// alternative is a lookup on the path of every relay read — and a provider
// whose daemon moved has to be restarted to re-read its cookie anyway.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use url::Url;

use crate::provider::is_private_ip;

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
        // Word for word what `AnonConfig::validate_shape` says of the same
        // key: an operator who meets this message through either door reads
        // the same sentence.
        let malformed = || {
            anyhow!(
                "anon.socks_proxy {:?} must be socks5h://<host>:<port>: only a socks5h proxy \
                 resolves names on the far side, so no lookup leaves this provider",
                socks_proxy
            )
        };
        if url.scheme() != "socks5h" {
            return Err(malformed());
        }
        let (Some(host), Some(port)) = (url.host_str(), url.port()) else {
            return Err(malformed());
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
    fn apply(&self, builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
        let proxy = reqwest::Proxy::all(&self.url)
            .with_context(|| format!("{} is not a proxy reqwest can use", self.url))?;
        Ok(builder.proxy(proxy))
    }
}

/// An HTTP client with `timeout` per request, through `proxy` when there is
/// one. `what` names the caller in the error, because a provider that cannot
/// build a client is told which of its two it was.
///
/// Both of this crate's reqwest clients — the publish request's and the image
/// fetcher's — are built here, so neither can acquire a proxy the other
/// lacks: on a Hidden Provider the whole of a process's outbound is hidden or
/// none of it is.
pub fn http_client(
    proxy: Option<&OutboundProxy>,
    timeout: Duration,
    what: &str,
) -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder().timeout(timeout);
    let builder = match proxy {
        Some(proxy) => proxy.apply(builder)?,
        None => builder,
    };
    builder
        .build()
        .with_context(|| format!("building the HTTP client for {}", what))
}

/// Whether reaching `url` takes no packet off this host or its own private
/// network: a loopback address, a private or link-local one, `localhost`, or
/// a name that resolves ONLY to such addresses.
///
/// The one place a hidden provider dials directly: its own directory
/// publisher, one process over on `127.0.0.1` or one container over on a
/// compose network. Routing that through `anon` would ask the daemon for a
/// circuit to an address no exit can reach — it would simply fail — and it
/// would hide nothing, because such a packet never crosses a network anyone
/// outside can watch. The publisher is handed the proxy IN the request
/// instead, and rides it for the connector hop that does leave.
///
/// The same rule the settlement-RPC gate applies (`is_private_ip`, spec §10),
/// for the same reason and so an operator has one notion of "near" to hold. A
/// name that does not resolve here is NOT private: the safe way to be wrong
/// about a publisher's whereabouts is to proxy the request.
pub fn is_private_url(url: &str) -> bool {
    let Ok(url) = Url::parse(url) else {
        return false;
    };
    match url.host() {
        Some(url::Host::Ipv4(ip)) => is_private_ip(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => is_private_ip(IpAddr::V6(ip)),
        Some(url::Host::Domain(name)) if name.eq_ignore_ascii_case("localhost") => true,
        Some(url::Host::Domain(name)) => {
            let port = url.port_or_known_default().unwrap_or(80);
            match (name, port).to_socket_addrs() {
                Ok(addrs) => {
                    let mut any = false;
                    for addr in addrs {
                        any = true;
                        if !is_private_ip(addr.ip()) {
                            return false;
                        }
                    }
                    any
                }
                Err(_) => false,
            }
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A URL that will not parse at all says so, naming the key.
    #[test]
    fn a_proxy_that_is_not_a_url_is_refused() {
        let why = format!(
            "{:#}",
            OutboundProxy::resolve("socks5h://:9050").unwrap_err()
        );
        assert!(why.contains("anon.socks_proxy"), "{why}");
        assert!(why.contains("is not a URL"), "{why}");
    }

    #[test]
    fn a_socks5h_proxy_on_loopback_resolves() {
        let proxy = OutboundProxy::resolve("socks5h://127.0.0.1:9050").unwrap();
        assert_eq!(proxy.url(), "socks5h://127.0.0.1:9050");
        assert_eq!(proxy.addr().port(), 9050);
        assert!(proxy.addr().ip().is_loopback());
    }

    /// The scheme and the missing port are one refusal, in the words
    /// `AnonConfig::validate_shape` uses of the same key: an operator meets
    /// the same sentence through either door.
    #[test]
    fn anything_but_a_socks5h_host_and_port_is_refused() {
        for written in [
            "socks5://127.0.0.1:9050",
            "http://127.0.0.1:9050",
            "socks5h://127.0.0.1",
        ] {
            let why = format!("{:#}", OutboundProxy::resolve(written).unwrap_err());
            assert!(why.contains("must be socks5h://<host>:<port>"), "{why}");
            assert!(why.contains("resolves names on the far side"), "{why}");
        }
    }

    #[test]
    fn a_publisher_on_this_host_or_its_own_network_is_near() {
        assert!(is_private_url("http://127.0.0.1:8081/publish"));
        assert!(is_private_url("http://localhost:8081/publish"));
        assert!(is_private_url("http://[::1]:8081/publish"));
        // A sidecar container on a compose network: the packet never leaves
        // the bridge, and no `anon` exit could reach it.
        assert!(is_private_url("http://10.0.0.4:8081/publish"));
        assert!(is_private_url("http://172.18.0.9:8081/publish"));
    }

    #[test]
    fn a_publisher_anywhere_else_is_not() {
        assert!(!is_private_url("http://203.0.113.7:8081/publish"));
        // A name nothing here resolves: proxied, which is the safe way to be
        // wrong about where a publisher is.
        assert!(!is_private_url("http://publisher.invalid:8081/publish"));
        assert!(!is_private_url("not a url"));
    }
}
