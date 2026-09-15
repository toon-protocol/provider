// Nostr layer.
//
// Paygress carried its requests as NIP-04/NIP-17 direct messages and published
// offers and heartbeats under its own event kinds. Both are gone: requests
// arrive as ordinary HTTP through the provider's TOON connector, carrying a
// tenant-signed Lease Request (`lease_request`), and the directory events of
// the TOON Network spec are named in `kinds` and built in `directory_events`.

pub mod directory_events;
mod identity;
pub mod kinds;
pub mod lease_request;
pub mod wire;

pub use identity::*;
