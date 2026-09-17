//! A stub SOCKS5 proxy, so a Hidden Provider's own outbound can be tested
//! against a proxy the test controls rather than an `anon` daemon (spec §10).
//!
//! It speaks exactly as much of RFC 1928 as the three clients that ride it
//! need: the greeting, the no-authentication method, and `CONNECT` to a
//! `DOMAINNAME` or an `IPv4` address. Once connected it is a pipe.
//!
//! What makes it a TEST and not just a hop: a destination is named to it, and
//! it alone knows where that name really is. A stub is started with a routing
//! table of `("relay.anyone", <the stub relay's real address>)` pairs and the
//! provider is configured with the NAME. Nothing resolves `relay.anyone` on
//! this host, so a provider that dialled directly could not reach the relay
//! at all — which is why `destinations()` recording the name is proof the
//! read went through the proxy, and why `socks5h` (the proxy resolves) rather
//! than `socks5` (the client resolves) is what the provider must be using.
//!
//! `outgoing()` closes the other half: every connection the stub makes on the
//! provider's behalf leaves from a local address recorded here, so a stub
//! backend that records its peers can assert that EVERY connection it saw came
//! from this proxy and none from anywhere else.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

#[derive(Default)]
struct Seen {
    /// `<host>:<port>` exactly as each `CONNECT` named it, in order.
    destinations: Vec<String>,
    /// The local address of every connection this proxy opened onward.
    outgoing: Vec<SocketAddr>,
}

pub struct SocksStub {
    addr: SocketAddr,
    seen: Arc<Mutex<Seen>>,
    accept_loop: JoinHandle<()>,
}

impl SocksStub {
    /// A proxy on a free loopback port that resolves each name in `routes`
    /// to the address beside it. A `CONNECT` to an IPv4 literal is dialled
    /// as given; a name that is in no route is refused, the way a daemon
    /// with no circuit to a host would.
    pub async fn start(routes: &[(&str, SocketAddr)]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let routes: HashMap<String, SocketAddr> = routes
            .iter()
            .map(|(name, addr)| (name.to_ascii_lowercase(), *addr))
            .collect();
        let seen: Arc<Mutex<Seen>> = Default::default();

        let accept_loop = {
            let (routes, seen) = (Arc::new(routes), seen.clone());
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(serve(stream, routes.clone(), seen.clone()));
                }
            })
        };

        Self {
            addr,
            seen,
            accept_loop,
        }
    }

    /// `socks5h://127.0.0.1:<port>`, as `anon.socks_proxy` names it.
    pub fn url(&self) -> String {
        format!("socks5h://{}", self.addr)
    }

    /// Every `<host>:<port>` a client asked this proxy to connect to.
    pub fn destinations(&self) -> Vec<String> {
        self.seen.lock().unwrap().destinations.clone()
    }

    /// Whether some client asked for `destination` (`<host>:<port>`).
    pub fn asked_for(&self, destination: &str) -> bool {
        self.destinations().iter().any(|d| d == destination)
    }

    /// The local address of every onward connection this proxy opened: what
    /// a stub backend sees as the peer of a proxied connection.
    pub fn outgoing(&self) -> Vec<SocketAddr> {
        self.seen.lock().unwrap().outgoing.clone()
    }
}

impl Drop for SocksStub {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

async fn serve(
    mut client: TcpStream,
    routes: Arc<HashMap<String, SocketAddr>>,
    seen: Arc<Mutex<Seen>>,
) {
    if greet(&mut client).await.is_none() {
        return;
    }
    let Some((host, port)) = request(&mut client).await else {
        return;
    };
    seen.lock()
        .unwrap()
        .destinations
        .push(format!("{host}:{port}"));

    let target = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => Some(SocketAddr::new(ip, port)),
        Err(_) => routes.get(&host.to_ascii_lowercase()).copied(),
    };
    let Some(target) = target else {
        // 0x04 "host unreachable": no route to that name, which is what a
        // daemon asked for a hidden service it cannot reach answers.
        let _ = client.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return;
    };
    let Ok(mut upstream) = TcpStream::connect(target).await else {
        let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return;
    };
    if let Ok(local) = upstream.local_addr() {
        seen.lock().unwrap().outgoing.push(local);
    }
    // Success. The bound address a real proxy reports is not one any client
    // here looks at, so it is reported as `0.0.0.0:0`.
    if client
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .is_err()
    {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

/// The greeting: the client's method list in, "no authentication" out.
async fn greet(client: &mut TcpStream) -> Option<()> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await.ok()?;
    if head[0] != 5 {
        return None;
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods).await.ok()?;
    client.write_all(&[5, 0]).await.ok()?;
    Some(())
}

/// One `CONNECT` request, as the host and port it named.
async fn request(client: &mut TcpStream) -> Option<(String, u16)> {
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await.ok()?;
    // ver 5, cmd 1 (CONNECT). Nothing here binds or associates UDP.
    if head[0] != 5 || head[1] != 1 {
        return None;
    }
    let host = match head[3] {
        1 => {
            let mut octets = [0u8; 4];
            client.read_exact(&mut octets).await.ok()?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await.ok()?;
            let mut name = vec![0u8; len[0] as usize];
            client.read_exact(&mut name).await.ok()?;
            String::from_utf8(name).ok()?
        }
        4 => {
            let mut octets = [0u8; 16];
            client.read_exact(&mut octets).await.ok()?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await.ok()?;
    Some((host, u16::from_be_bytes(port)))
}

/// A TCP pipe in front of a server that cannot report its own callers.
///
/// `wiremock`'s gateway and registry answer HTTP and record requests, but not
/// the peer address each arrived on — so, unlike `StubRelay`, they cannot say
/// on their own that nothing reached them directly. A tap in front of one
/// records the peer of every connection and forwards the bytes unchanged, and
/// a test then asserts what it asserts of the relay: every caller was the
/// SOCKS stub.
pub struct PeerTap {
    addr: SocketAddr,
    peers: Arc<Mutex<Vec<SocketAddr>>>,
    accept_loop: JoinHandle<()>,
}

impl PeerTap {
    /// A tap on a free loopback port forwarding to `target`.
    pub async fn infront_of(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peers: Arc<Mutex<Vec<SocketAddr>>> = Default::default();

        let accept_loop = {
            let peers = peers.clone();
            tokio::spawn(async move {
                while let Ok((mut stream, peer)) = listener.accept().await {
                    peers.lock().unwrap().push(peer);
                    tokio::spawn(async move {
                        let Ok(mut upstream) = TcpStream::connect(target).await else {
                            return;
                        };
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                    });
                }
            })
        };

        Self {
            addr,
            peers,
            accept_loop,
        }
    }

    /// Where the tap listens: what a SOCKS stub's routing table points at.
    pub fn socket_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The remote address of every connection the tap has accepted.
    pub fn peers(&self) -> Vec<SocketAddr> {
        self.peers.lock().unwrap().clone()
    }
}

impl Drop for PeerTap {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}
