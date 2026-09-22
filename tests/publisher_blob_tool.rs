//! The Node publisher tool's blob planner, run as a real process and read
//! back by this provider's own fetcher (`tools/publisher/blob.mjs`;
//! TOON_Network #73; spec §8.2, §11 item 2).
//!
//! `blob.mjs` decides whether a blob's Blob Record carries inline `parts`
//! or paged `pages`, and prints its plan as JSON with no network and no
//! identity of its own (see its doc comment). This drives it through
//! `blob-cli.mjs`, on both sides of its threshold, SIGNS what it planned
//! into a real Blob Record event here — Node holds no key, Rust does,
//! exactly as `tools/publisher/publish.mjs`'s README draws that line for the
//! relay payer — mounts the tool's own uploads on a fake TOON store, and
//! asks `BlobFetcher` to resolve the blob. The tool's output and the
//! provider's reader agreeing on the same bytes, whichever shape the record
//! took, is the whole of what "a round trip from the tool's output to the
//! provider's reader" (the ticket's words) means.
//!
//! Prior art for running a Node tool as a subprocess from this suite:
//! `tests/gateway_handover.rs` drives `tools/grant/seal.mjs` the same way.
//! Node is therefore required to run this file, as it already is there.

mod common;

use std::path::PathBuf;

use nostr_sdk::Keys;
use serde::Deserialize;

use common::store::mount_raw;
use common::FakeDirectory;
use toon_provider::nostr::image_events::{
    blob_record_event, BlobPage, BlobPart, BlobRecordContent,
};
use toon_provider::provider::fetcher::BlobSources;
use toon_provider::provider::{BlobCache, BlobFetcher};

fn blob_cli_mjs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/publisher/blob-cli.mjs")
}

#[derive(Deserialize)]
struct PlanUpload {
    txid: String,
    bytes_hex: String,
}

#[derive(Deserialize)]
struct PlanPart {
    txid: String,
    sha256: String,
    size: u64,
}

#[derive(Deserialize)]
struct PlanPage {
    txid: String,
    sha256: String,
    parts: u64,
}

#[derive(Deserialize)]
struct Plan {
    digest: String,
    size: u64,
    part_size: u64,
    parts: Option<Vec<PlanPart>>,
    pages: Option<Vec<PlanPage>>,
    uploads: Vec<PlanUpload>,
}

/// Bare hex, no dependency: every byte string the tool prints is two hex
/// digits, produced by Node's own `Buffer#toString('hex')`.
fn hex_decode(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "a hex string has an even length: {}", hex);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// One run of the tool: the JSON plan it prints for `bytes` on `PATH`,
/// given by a temp file since the tool reads a file, not stdin.
async fn plan(bytes: &[u8], args: &[&str]) -> Plan {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), bytes).unwrap();
    let output = tokio::process::Command::new("node")
        .arg(blob_cli_mjs())
        .arg("plan")
        .arg(file.path())
        .args(args)
        .output()
        .await
        .expect(
            "run `node tools/publisher/blob-cli.mjs`: this suite drives the publisher tool, \
             so Node must be on PATH",
        );
    assert!(
        output.status.success(),
        "the tool refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("the tool prints one JSON plan on stdout")
}

/// The Blob Record content the plan describes, in exactly the shape
/// `toon_provider::nostr::image_events` reads (§8.2's one-of rule: exactly
/// one of `parts`/`pages`, which the tool already enforced by construction).
fn content_of(plan: &Plan) -> BlobRecordContent {
    BlobRecordContent {
        digest: plan.digest.clone(),
        size: plan.size,
        part_size: plan.part_size,
        parts: plan.parts.as_ref().map(|parts| {
            parts
                .iter()
                .map(|p| BlobPart {
                    txid: p.txid.clone(),
                    sha256: p.sha256.clone(),
                    size: p.size,
                })
                .collect()
        }),
        pages: plan.pages.as_ref().map(|pages| {
            pages
                .iter()
                .map(|p| BlobPage {
                    txid: p.txid.clone(),
                    sha256: p.sha256.clone(),
                    parts: p.parts,
                })
                .collect()
        }),
    }
}

/// Sign the plan's content (as whoever uploaded the parts would, spec
/// §8.2), seed it on a fake Relay Set, mount every one of the tool's own
/// uploads on a fake TOON store gateway, and ask this provider's real
/// `BlobFetcher` to resolve the blob — the same §8.4 step 3 path a bare
/// `{ digest }` spawn takes.
async fn resolves_to(plan: &Plan, original: &[u8]) {
    let directory = FakeDirectory::new();
    let gateway = wiremock::MockServer::start().await;
    for upload in &plan.uploads {
        mount_raw(&gateway, &upload.txid, hex_decode(&upload.bytes_hex)).await;
    }

    let event = blob_record_event(&content_of(plan), &Keys::generate(), 1_700_000_000).unwrap();
    directory.seed_blob_record(event);

    let cache = BlobCache::open(tempfile::tempdir().unwrap().keep(), None).unwrap();
    let fetcher = BlobFetcher::new(
        Some(format!("{}/raw/{{txid}}", gateway.uri())),
        None,
        &[],
        None,
        cache,
    )
    .unwrap();
    let sources = BlobSources::relay_set(directory);

    let bytes = fetcher
        .fetch(&plan.digest, &sources)
        .await
        .expect("the provider resolves exactly what the tool planned");
    assert_eq!(bytes.as_ref(), original);
}

#[tokio::test]
async fn the_tool_stays_inline_below_its_threshold_and_the_provider_reads_it() {
    let bytes: Vec<u8> = "a small blob the tool keeps inline, part by part\n"
        .repeat(4)
        .into_bytes();
    let p = plan(&bytes, &["--part-size", "16", "--data-item-max", "100000"]).await;

    assert!(
        p.parts.is_some(),
        "under a generous threshold the tool stays inline"
    );
    assert!(p.pages.is_none());
    resolves_to(&p, &bytes).await;
}

#[tokio::test]
async fn the_tool_pages_above_its_threshold_and_the_provider_reads_it() {
    let bytes: Vec<u8> =
        "a blob the tool must page because its record would not fit one data item\n"
            .repeat(40)
            .into_bytes();
    let p = plan(&bytes, &["--part-size", "16", "--data-item-max", "300"]).await;

    assert!(p.pages.is_some(), "over a tight threshold the tool pages");
    assert!(p.parts.is_none());
    assert!(
        p.pages.as_ref().unwrap().len() > 1,
        "more than one page, so page order is really exercised: {}",
        p.pages.as_ref().unwrap().len()
    );
    resolves_to(&p, &bytes).await;
}

#[tokio::test]
async fn a_page_the_tool_planned_but_never_uploaded_is_refused_image_not_a_crash() {
    // The provider's own robustness, proven over the tool's real shapes: a
    // page the store lost (never mounted here) fails that source exactly
    // as any other unreachable upload does (§8.4) — not a panic.
    let bytes: Vec<u8> = "one more blob, paged, with a missing page\n"
        .repeat(40)
        .into_bytes();
    let p = plan(&bytes, &["--part-size", "16", "--data-item-max", "300"]).await;
    assert!(
        p.pages.is_some(),
        "this test needs a paged plan to drop a page from"
    );

    let directory = FakeDirectory::new();
    let gateway = wiremock::MockServer::start().await;
    // Every upload EXCEPT the last page: dropped, as if the store had lost it.
    let last_page_txid = p.pages.as_ref().unwrap().last().unwrap().txid.clone();
    for upload in p.uploads.iter().filter(|u| u.txid != last_page_txid) {
        mount_raw(&gateway, &upload.txid, hex_decode(&upload.bytes_hex)).await;
    }
    let event = blob_record_event(&content_of(&p), &Keys::generate(), 1_700_000_000).unwrap();
    directory.seed_blob_record(event);

    let cache = BlobCache::open(tempfile::tempdir().unwrap().keep(), None).unwrap();
    let fetcher = BlobFetcher::new(
        Some(format!("{}/raw/{{txid}}", gateway.uri())),
        None,
        &[],
        None,
        cache,
    )
    .unwrap();
    let sources = BlobSources::relay_set(directory);

    let err = fetcher
        .fetch(&p.digest, &sources)
        .await
        .expect_err("a missing page fails this source; there is no other, so the fetch refuses");
    assert_eq!(
        err.error,
        toon_provider::nostr::wire::ErrorCode::RefusedImage
    );
}
