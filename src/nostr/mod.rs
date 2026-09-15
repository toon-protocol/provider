// Nostr layer.
//
// Paygress carried its requests as NIP-04/NIP-17 direct messages and published
// offers and heartbeats under its own event kinds. Both are gone: requests
// arrive as ordinary HTTP through the provider's TOON connector, and the
// directory events of the TOON Network spec have not been written yet.
//
// What is left is npub canonicalization and the checks built on it.

mod identity;

pub use identity::*;
