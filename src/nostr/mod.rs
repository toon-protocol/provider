// Nostr layer.
//
// Paygress carried its requests as NIP-04/NIP-17 direct messages and published
// offers and heartbeats under its own event kinds. Both are gone: requests
// arrive as ordinary HTTP through the provider's TOON connector, carrying a
// Lease Request (`lease_request`) that is signed by nobody and authenticated
// by a Continuation Token (`continuation`), and the directory events of the
// TOON Network spec are named in `kinds` and built in `directory_events`.
//
// So this module holds no tenant identity at all any more: every event named
// here is signed by a PROVIDER or by a PUBLISHER.

pub mod continuation;
pub mod directory_events;
pub mod image_events;
pub mod kinds;
pub mod lease_request;
pub mod wire;
