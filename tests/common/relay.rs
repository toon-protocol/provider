//! A stub NIP-01 relay, so the relay-backed `Directory` can be tested against
//! a relay the test controls rather than a fake of the port.
//!
//! It speaks exactly as much of NIP-01 as the provider's reads and the
//! publisher's writes need: `REQ` is answered with every held event the
//! filter matches, newest first and cut at `limit`, then `EOSE`; `EVENT` is
//! stored and answered `OK`; `CLOSE` is ignored. It never drops an expired
//! event on its own, on purpose — NIP-40 says a relay SHOULD, and the
//! provider must not depend on it.
//!
//! One relay per instance, each on its own port: a test that wants a Relay
//! Set of three starts three, and can then see which of them was asked
//! (`requests`) and which took a write (`received`).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use nostr_sdk::filter::MatchEventOptions;
use nostr_sdk::{ClientMessage, Event, Filter, JsonUtil, RelayMessage};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

pub struct StubRelay {
    url: String,
    host: String,
    held: Arc<Mutex<Vec<Event>>>,
    requests: Arc<Mutex<Vec<Filter>>>,
    received: Arc<Mutex<Vec<Event>>>,
    /// The remote address of every connection this relay has accepted —
    /// what a Hidden Provider's tests read to prove that no client reached
    /// it other than through the SOCKS stub (spec §10).
    peers: Arc<Mutex<Vec<SocketAddr>>>,
    accept_loop: JoinHandle<()>,
}

impl StubRelay {
    /// A relay listening on a free loopback port, holding nothing yet.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("ws://{}", addr);
        let held: Arc<Mutex<Vec<Event>>> = Default::default();
        let requests: Arc<Mutex<Vec<Filter>>> = Default::default();
        let received: Arc<Mutex<Vec<Event>>> = Default::default();
        let peers: Arc<Mutex<Vec<SocketAddr>>> = Default::default();

        let accept_loop = {
            let (held, requests, received, peers) = (
                held.clone(),
                requests.clone(),
                received.clone(),
                peers.clone(),
            );
            tokio::spawn(async move {
                while let Ok((stream, peer)) = listener.accept().await {
                    peers.lock().unwrap().push(peer);
                    tokio::spawn(serve(
                        stream,
                        held.clone(),
                        requests.clone(),
                        received.clone(),
                    ));
                }
            })
        };

        Self {
            url,
            host: addr.to_string(),
            held,
            requests,
            received,
            peers,
            accept_loop,
        }
    }

    /// `ws://127.0.0.1:<port>`, the URL a Relay Set names this relay by.
    pub fn url(&self) -> String {
        self.url.clone()
    }

    /// This relay holds `event` from now on, as if it had been published
    /// here. Replaceable and addressable semantics are NOT applied: what a
    /// test seeds is exactly what the relay serves.
    pub fn hold(&self, event: Event) {
        self.held.lock().unwrap().push(event);
    }

    /// Every filter a client has asked this relay for, in order.
    pub fn requests(&self) -> Vec<Filter> {
        self.requests.lock().unwrap().clone()
    }

    /// Every event a client has published to this relay, in order.
    pub fn received(&self) -> Vec<Event> {
        self.received.lock().unwrap().clone()
    }

    /// `127.0.0.1:<port>`: where this relay really is, for a SOCKS stub's
    /// routing table to point a made-up `.anyone` name at.
    pub fn socket_addr(&self) -> SocketAddr {
        self.host.parse().unwrap()
    }

    /// A relay URL under `host` that only a proxy holding the route can
    /// reach: `ws://<host>:<this relay's port>`. Nothing resolves it here.
    pub fn url_as(&self, host: &str) -> String {
        format!("ws://{}:{}", host, self.socket_addr().port())
    }

    /// The remote address of every connection this relay has accepted.
    pub fn peers(&self) -> Vec<SocketAddr> {
        self.peers.lock().unwrap().clone()
    }
}

impl Drop for StubRelay {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

async fn serve(
    stream: TcpStream,
    held: Arc<Mutex<Vec<Event>>>,
    requests: Arc<Mutex<Vec<Filter>>>,
    received: Arc<Mutex<Vec<Event>>>,
) {
    let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await else {
        return;
    };
    while let Some(Ok(message)) = socket.next().await {
        let Ok(text) = message.to_text() else {
            continue;
        };
        let Ok(message) = ClientMessage::from_json(text) else {
            continue;
        };
        let answers: Vec<String> = match message {
            ClientMessage::Req {
                subscription_id,
                filter,
            } => {
                let filter = filter.into_owned();
                requests.lock().unwrap().push(filter.clone());
                let mut matching: Vec<Event> = held
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|e| filter.match_event(e, MatchEventOptions::new()))
                    .cloned()
                    .collect();
                // Newest first, cut at `limit`: what a relay does with one.
                matching.sort_by_key(|e| std::cmp::Reverse(e.created_at));
                if let Some(limit) = filter.limit {
                    matching.truncate(limit);
                }
                let subscription_id = subscription_id.into_owned();
                let mut answers: Vec<String> = matching
                    .into_iter()
                    .map(|e| RelayMessage::event(subscription_id.clone(), e).as_json())
                    .collect();
                answers.push(RelayMessage::eose(subscription_id).as_json());
                answers
            }
            ClientMessage::Event(event) => {
                let event = event.into_owned();
                let id = event.id;
                received.lock().unwrap().push(event);
                vec![RelayMessage::ok(id, true, "").as_json()]
            }
            _ => Vec::new(),
        };
        for answer in answers {
            if socket.send(Message::text(answer)).await.is_err() {
                return;
            }
        }
    }
}
