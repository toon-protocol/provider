// `toon-provider dns-shim` (TOON_Network#166): the fix for the one name a
// Hidden Provider's own `anon` daemon cannot resolve for a musl workload.
//
// THE BUG. A hidden lease's DNS goes to `anon`'s `DNSPort` through the
// transparent egress (README § "Workload egress on a Hidden Provider"). That
// port answers an AAAA query with NXDOMAIN — confirmed here against a real
// `anon` v0.4.10.2-live daemon, over the real Anyone network, for a name
// (`example.com`) that resolves fine on A: `anon`'s own DNS resolution never
// carries a real IPv6 answer back, so every AAAA query it is asked gets the
// same NXDOMAIN, whether or not the name really has no AAAA record. musl's
// `getaddrinfo` (Alpine's libc) sends the A and the AAAA query in parallel and
// treats an NXDOMAIN on EITHER as "this name does not exist", discarding the
// A answer it already has (musl commit 5cf1ac2443, following RFC 8020) —
// which is the well-known Tor DNSPort/Alpine bug
// (gitlab.torproject.org/tpo/core/tor/-/issues/40248). No `anonrc` option
// changes it: `DNSPort` takes only the `SocksPort`-style isolation flags
// (`IsolateClientAddr` and siblings), and `ClientUseIPv6` /
// `ClientPreferIPv6ORPort` govern this daemon's OWN connections to relays and
// directories, not what its `DNSPort` answers a client that asks it something
// (Tor's manual; there is no third option that touches this). It is a fix
// that belongs in `anon` (see the deploy README's note on filing it
// upstream), and this shim is the workaround until it lands there.
//
// WHY NOT JUST A DNSMASQ SIDECAR. `dnsmasq --filter-AAAA` looks like exactly
// this fix, and for a NAME IT HAS ALREADY SEEN (any earlier A or AAAA query)
// it is: it answers a later AAAA query out of its own cache without asking
// upstream at all. But confirmed here against a real `dnsmasq` 2.90: the
// FIRST query for a name, if it happens to be the AAAA one — which is
// exactly the race musl's parallel A+AAAA lookup can produce — is still
// forwarded upstream, and whatever `anon` answers (NXDOMAIN) comes straight
// back. `--filter-AAAA` filters RECORDS out of a forwarded answer; it does
// not stop dnsmasq from asking in the first place. That is not "answers AAAA
// with NOERROR and no records" — it is "usually does, if something already
// asked about this name" — so it does not close the bug it looks like it
// closes. This shim instead decides by QUERY TYPE ALONE, before anything is
// forwarded anywhere: an AAAA question is answered locally, unconditionally,
// every time; an A (or anything else — PTR included) is forwarded to `anon`'s
// `DNSPort` verbatim and its answer relayed back unchanged, so a real name
// still resolves exactly as `anon` resolves it, over Anyone, the same as
// today.
//
// THE ANSWER ITSELF. NOERROR with zero records (RFC 1035 §4.1.1 "NODATA"),
// never NXDOMAIN: the difference RFC 8020 draws, and the one musl acts on. A
// resolver that got a real A answer a moment before or after does not throw
// it away over an AAAA reply that correctly says "nothing here", the way it
// does over one that says "no such name". The reply is byte-for-byte the
// query's own header and question — same ID, same name, same class — with
// `QR` set, `RA` set, `RCODE` NOERROR and every count but `QDCOUNT` zeroed:
// deliberately never an OPT record or anything else past the question,
// because there is nothing to attach one to.
//
// WHERE THIS RUNS. `docker-compose.hidden.yml` puts one instance of this
// binary — the provider's own image, pinned by digest for this use, not the
// floating `sha-<short>` tag the provider service runs (module doc there
// says why) — on the egress network ALONE, no other network, so it has no
// path to the clearnet at all; `anon`'s own NAT rule, which used to redirect
// port 53 to its `DNSPort` directly, now redirects it here instead, and this
// shim's only egress-network peer is `anon`'s `DNSPort` on the same subnet.
// Every A query still leaves through Anyone exactly as before; every AAAA
// query never leaves the box.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{info, warn};

/// RFC 1035 §3.2.2: the QTYPE this shim answers itself rather than asking
/// `anon`.
const TYPE_AAAA: u16 = 28;

/// How long a forwarded query waits for `anon`'s `DNSPort` before this shim
/// gives up on it. A circuit through Anyone can be slower than a resolver's
/// own retry budget; this only bounds how long one query holds a socket —
/// the workload's own resolver is what decides whether to retry.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest DNS-over-UDP message this shim reads. 512 is the classic
/// ceiling (RFC 1035 §2.3.4); 4096 leaves room for the EDNS0 requests a
/// modern resolver sends without ever being the limiting factor.
const MAX_UDP_MESSAGE: usize = 4096;

/// `toon-provider dns-shim`'s flags. Both addresses are committed, fixed
/// values on the hidden overlay's egress network — `docker-compose.hidden.yml`
/// names them, the same way `anon/anonrc`'s own addresses are committed
/// rather than templated (tests/deploy_bundle.rs checks the two files agree)
/// — so there is nothing for an operator to fill in here.
#[derive(Debug, Clone, clap::Args)]
pub struct DnsShimArgs {
    /// Where this shim listens for UDP and TCP queries: the egress network's
    /// address `anon`'s NAT rule now redirects port 53 to, in place of
    /// `anon`'s own `DNSPort`.
    #[arg(long, env = "TOON_DNS_SHIM_LISTEN")]
    pub listen: SocketAddr,

    /// `anon`'s real `DNSPort`, on the same egress network, that every A (and
    /// any non-AAAA) query is forwarded to unchanged.
    #[arg(long, env = "TOON_DNS_SHIM_UPSTREAM")]
    pub upstream: SocketAddr,
}

/// Binds both a UDP and a TCP listener on `args.listen` and serves forever.
/// Either transport failing to bind, or its accept/receive loop erroring
/// outright, ends the process — matching `anon` itself, which does not run
/// half-started.
pub async fn run(args: &DnsShimArgs) -> Result<()> {
    info!(
        listen = %args.listen,
        upstream = %args.upstream,
        "dns shim: A/PTR forwarded to anon's DNSPort, AAAA answered locally with NOERROR and no records"
    );
    let udp = UdpSocket::bind(args.listen)
        .await
        .with_context(|| format!("binding the DNS shim's UDP listener on {}", args.listen))?;
    let tcp = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("binding the DNS shim's TCP listener on {}", args.listen))?;
    let upstream = args.upstream;
    let udp_task = tokio::spawn(serve_udp(Arc::new(udp), upstream));
    let tcp_task = tokio::spawn(serve_tcp(tcp, upstream));
    tokio::select! {
        res = udp_task => res.context("the DNS shim's UDP listener task panicked")?,
        res = tcp_task => res.context("the DNS shim's TCP listener task panicked")?,
    }
}

/// One query, decided by type alone: an AAAA question never leaves this
/// process; anything else is forwarded to `upstream` and its answer, or the
/// lack of one, is what comes back.
async fn answer(query: &[u8], upstream: SocketAddr, forward: impl Forward) -> Option<Vec<u8>> {
    if let Some(question_end) = wants_local_aaaa_answer(query) {
        return Some(nodata_reply(query, question_end));
    }
    match forward.forward(upstream, query).await {
        Ok(reply) => Some(reply),
        Err(e) => {
            warn!(error = %e, "forwarding a query to anon's DNSPort");
            None
        }
    }
}

/// The two transports' forwarders, so `answer` above does not care which one
/// it is running over.
trait Forward {
    async fn forward(&self, upstream: SocketAddr, query: &[u8]) -> Result<Vec<u8>>;
}

struct ForwardUdp;
impl Forward for ForwardUdp {
    async fn forward(&self, upstream: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
        forward_udp(upstream, query).await
    }
}

struct ForwardTcp;
impl Forward for ForwardTcp {
    async fn forward(&self, upstream: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
        forward_tcp(upstream, query).await
    }
}

async fn serve_udp(socket: Arc<UdpSocket>, upstream: SocketAddr) -> Result<()> {
    let mut buf = [0u8; MAX_UDP_MESSAGE];
    loop {
        let (len, from) = socket
            .recv_from(&mut buf)
            .await
            .context("reading a UDP DNS query")?;
        let query = buf[..len].to_vec();
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            if let Some(reply) = answer(&query, upstream, ForwardUdp).await {
                if let Err(e) = socket.send_to(&reply, from).await {
                    warn!(error = %e, to = %from, "answering a UDP DNS query");
                }
            }
        });
    }
}

async fn forward_udp(upstream: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let bind_addr = if upstream.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .context("binding an ephemeral UDP socket toward anon's DNSPort")?;
    socket
        .connect(upstream)
        .await
        .context("connecting to anon's DNSPort")?;
    socket
        .send(query)
        .await
        .context("sending the query to anon's DNSPort")?;
    let mut buf = [0u8; MAX_UDP_MESSAGE];
    let len = timeout(UPSTREAM_TIMEOUT, socket.recv(&mut buf))
        .await
        .context("anon's DNSPort did not answer in time")?
        .context("reading anon's DNSPort's answer")?;
    Ok(buf[..len].to_vec())
}

async fn serve_tcp(listener: TcpListener, upstream: SocketAddr) -> Result<()> {
    loop {
        let (stream, from) = listener
            .accept()
            .await
            .context("accepting a TCP DNS connection")?;
        tokio::spawn(async move {
            if let Err(e) = serve_tcp_connection(stream, upstream).await {
                warn!(error = %e, from = %from, "serving a TCP DNS connection");
            }
        });
    }
}

/// DNS-over-TCP frames each message with a 2-byte length (RFC 1035 §4.2.2).
/// One connection can carry more than one query; this serves each in turn
/// until the client closes it.
async fn serve_tcp_connection(mut stream: TcpStream, upstream: SocketAddr) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            // The client closed the connection; nothing left to answer.
            return Ok(());
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut query = vec![0u8; len];
        stream
            .read_exact(&mut query)
            .await
            .context("reading a TCP DNS query body")?;
        let Some(reply) = answer(&query, upstream, ForwardTcp).await else {
            // Forwarding failed (anon's DNSPort did not answer in time);
            // nothing to send back, but the connection can still carry the
            // client's next query.
            continue;
        };
        let reply_len = u16::try_from(reply.len())
            .context("anon's DNSPort answered a message too large for DNS-over-TCP")?;
        stream
            .write_all(&reply_len.to_be_bytes())
            .await
            .context("writing the TCP reply length")?;
        stream
            .write_all(&reply)
            .await
            .context("writing the TCP reply body")?;
    }
}

async fn forward_tcp(upstream: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let mut stream = timeout(UPSTREAM_TIMEOUT, TcpStream::connect(upstream))
        .await
        .context("connecting to anon's DNSPort timed out")?
        .context("connecting to anon's DNSPort")?;
    let len = u16::try_from(query.len()).context("a TCP query longer than DNS-over-TCP allows")?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .context("writing the query length to anon's DNSPort")?;
    stream
        .write_all(query)
        .await
        .context("writing the query to anon's DNSPort")?;
    let mut len_buf = [0u8; 2];
    timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .context("anon's DNSPort did not answer in time")?
        .context("reading anon's DNSPort's reply length")?;
    let reply_len = u16::from_be_bytes(len_buf) as usize;
    let mut reply = vec![0u8; reply_len];
    stream
        .read_exact(&mut reply)
        .await
        .context("reading anon's DNSPort's reply body")?;
    Ok(reply)
}

// ── The pure wire logic: no sockets, easy to get right and to test ─────────

/// `Some(question_end)` when `message` is exactly one well-formed question
/// asking for AAAA — the one shape this shim answers itself — where
/// `question_end` is the offset one past the question's `QCLASS`. Anything
/// else (a different QTYPE, more or fewer than one question, or a QNAME this
/// tiny parser does not follow, such as one using compression — never needed
/// in a query, since nothing before it to point at) is `None`, and the
/// caller forwards the message unexamined rather than guess at it.
fn wants_local_aaaa_answer(message: &[u8]) -> Option<usize> {
    let (qtype, question_end) = parse_single_question(message)?;
    (qtype == TYPE_AAAA).then_some(question_end)
}

/// The `(QTYPE, question_end)` of `message`'s one question, or `None` if
/// `message` is not shaped that way. `question_end` is the offset
/// immediately after `QCLASS` — the end of the question section, and so of
/// everything this shim ever echoes back.
fn parse_single_question(message: &[u8]) -> Option<(u16, usize)> {
    if message.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([message[4], message[5]]);
    if qdcount != 1 {
        return None;
    }
    let mut pos = 12usize;
    loop {
        let len = *message.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        // The top two bits mark a compression pointer (RFC 1035 §4.1.4). A
        // query never needs one — there is nothing earlier in the message
        // for it to point at — so one here is not a shape this parser
        // follows; the caller forwards the message as it is instead.
        if len & 0xc0 != 0 {
            return None;
        }
        pos = pos.checked_add(len)?;
        if pos > message.len() {
            return None;
        }
    }
    let question_end = pos.checked_add(4)?; // QTYPE (2) + QCLASS (2)
    if question_end > message.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([message[pos], message[pos + 1]]);
    Some((qtype, question_end))
}

/// A NOERROR, zero-record answer to `query`, whose question ends at
/// `question_end` (as `parse_single_question` found it): `query`'s own
/// header and question, byte for byte, with the header turned into an
/// answer's. `QR` is set, `AA`/`TC` are cleared (this shim is not
/// authoritative and never truncates), `RD` is copied from the query, `RA`
/// is set (recursion — such as it is — was in fact attempted, at `anon`),
/// `RCODE` is NOERROR, and `QDCOUNT` is the only count left standing:
/// `ANCOUNT`, `NSCOUNT` and `ARCOUNT` are all zero. Nothing past the
/// question is ever carried over, so a query with an EDNS0 OPT record gets
/// an answer with none.
fn nodata_reply(query: &[u8], question_end: usize) -> Vec<u8> {
    let mut reply = query[..question_end].to_vec();
    const QR: u8 = 0x80;
    const OPCODE_MASK: u8 = 0x78;
    const RD: u8 = 0x01;
    const RA: u8 = 0x80;
    reply[2] = QR | (query[2] & OPCODE_MASK) | (query[2] & RD);
    reply[3] = RA; // Z = 0, RCODE = 0 (NOERROR)
    reply[6] = 0;
    reply[7] = 0; // ANCOUNT
    reply[8] = 0;
    reply[9] = 0; // NSCOUNT
    reply[10] = 0;
    reply[11] = 0; // ARCOUNT
    reply
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, well-formed query: a random ID, `RD` as given, one
    /// question of `qtype`/`IN` for `name`, and nothing past it.
    fn query(id: u16, rd: bool, qtype: u16, name: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes());
        msg.push(if rd { 0x01 } else { 0x00 }); // QR=0 OPCODE=0 AA=0 TC=0 RD=?
        msg.push(0x00); // RA=0 Z=0 RCODE=0
        msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0x00); // the root label
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        msg
    }

    #[test]
    fn a_pure_aaaa_query_is_answered_locally() {
        let msg = query(0x1234, true, TYPE_AAAA, "example.com");
        assert!(wants_local_aaaa_answer(&msg).is_some());
    }

    #[test]
    fn an_a_query_is_forwarded_not_answered_locally() {
        let msg = query(0x1234, true, 1 /* A */, "example.com");
        assert_eq!(wants_local_aaaa_answer(&msg), None);
    }

    #[test]
    fn a_ptr_query_is_forwarded_not_answered_locally() {
        let msg = query(0x1234, true, 12 /* PTR */, "7.0.0.10.in-addr.arpa");
        assert_eq!(wants_local_aaaa_answer(&msg), None);
    }

    #[test]
    fn two_questions_is_forwarded_rather_than_guessed_at() {
        let mut msg = query(1, false, TYPE_AAAA, "example.com");
        msg[4..6].copy_from_slice(&2u16.to_be_bytes()); // QDCOUNT = 2, no second question added
        assert_eq!(wants_local_aaaa_answer(&msg), None);
    }

    #[test]
    fn a_compressed_name_is_forwarded_rather_than_followed() {
        // A query never legitimately needs a compression pointer (nothing
        // precedes it to point at); this shim does not chase one.
        let mut msg = vec![0u8; 12];
        msg[5] = 1; // QDCOUNT = 1
        msg.extend_from_slice(&[0xc0, 0x00]); // a pointer to offset 0
        msg.extend_from_slice(&TYPE_AAAA.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(wants_local_aaaa_answer(&msg), None);
    }

    #[test]
    fn a_truncated_message_is_forwarded_rather_than_panicked_on() {
        let full = query(1, false, TYPE_AAAA, "example.com");
        for cut in 0..full.len() {
            assert_eq!(
                wants_local_aaaa_answer(&full[..cut]),
                None,
                "a message truncated to {cut} bytes must not be read past its end"
            );
        }
    }

    #[test]
    fn the_nodata_reply_is_noerror_with_the_same_id_and_question_and_rd_copied() {
        for rd in [true, false] {
            let q = query(0xbeef, rd, TYPE_AAAA, "example.com");
            let (_, question_end) = parse_single_question(&q).unwrap();
            let reply = nodata_reply(&q, question_end);

            assert_eq!(&reply[0..2], &q[0..2], "the id is unchanged");
            assert_eq!(reply[2] & 0x80, 0x80, "QR is set");
            assert_eq!(reply[2] & 0x78, q[2] & 0x78, "the opcode is copied");
            assert_eq!(reply[2] & 0x04, 0, "AA is not set");
            assert_eq!(reply[2] & 0x02, 0, "TC is not set");
            assert_eq!(reply[2] & 0x01, if rd { 0x01 } else { 0 }, "RD is copied");
            assert_eq!(reply[3] & 0x80, 0x80, "RA is set");
            assert_eq!(reply[3] & 0x0f, 0, "RCODE is NOERROR");
            assert_eq!(&reply[4..6], &1u16.to_be_bytes(), "QDCOUNT is still 1");
            assert_eq!(&reply[6..8], &0u16.to_be_bytes(), "ANCOUNT is 0");
            assert_eq!(&reply[8..10], &0u16.to_be_bytes(), "NSCOUNT is 0");
            assert_eq!(&reply[10..12], &0u16.to_be_bytes(), "ARCOUNT is 0");
            assert_eq!(
                &reply[12..],
                &q[12..question_end],
                "the question is echoed verbatim"
            );
            assert_eq!(reply.len(), question_end, "nothing follows the question");
        }
    }

    #[tokio::test]
    async fn an_aaaa_query_never_reaches_the_forwarder() {
        struct PanicsIfCalled;
        impl Forward for PanicsIfCalled {
            async fn forward(&self, _upstream: SocketAddr, _query: &[u8]) -> Result<Vec<u8>> {
                panic!("an AAAA query must never be forwarded");
            }
        }
        let msg = query(1, true, TYPE_AAAA, "example.com");
        let upstream: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let reply = answer(&msg, upstream, PanicsIfCalled).await.unwrap();
        assert_eq!(&reply[0..2], &msg[0..2]);
        assert_eq!(&reply[6..12], &[0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn an_a_query_is_handed_to_the_forwarder_unchanged() {
        struct Echo;
        impl Forward for Echo {
            async fn forward(&self, _upstream: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
                Ok(query.to_vec())
            }
        }
        let msg = query(1, true, 1 /* A */, "example.com");
        let upstream: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let reply = answer(&msg, upstream, Echo).await.unwrap();
        assert_eq!(reply, msg, "an A query is forwarded byte for byte");
    }
}
