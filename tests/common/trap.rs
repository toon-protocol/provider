//! A listener on loopback that accepts and counts, so that "the guard runs
//! BEFORE the dial" is proven rather than assumed.
//!
//! Every URL these tests point at a trap is one the provider must refuse.
//! Nothing is served: the point is the count, and a provider that got this
//! far has already lost — the operator's real service on such a port would
//! have answered. A guard that were removed makes the count one, which is
//! how these tests are kept from being vacuous.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub struct Trap {
    pub addr: SocketAddr,
    connections: Arc<AtomicUsize>,
}

impl Trap {
    pub async fn set() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        Self { addr, connections }
    }

    /// The relay URL somebody would write to reach this trap.
    pub fn relay_url(&self) -> String {
        format!("ws://127.0.0.1:{}", self.addr.port())
    }

    /// The same by NAME, so the check has to be on what it resolves to.
    pub fn relay_url_as(&self, host: &str) -> String {
        format!("ws://{}:{}", host, self.addr.port())
    }

    pub fn reached(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}
