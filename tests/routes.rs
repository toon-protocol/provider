//! `toon-provider routes` prints the connector route rows this provider
//! expects: one spawn and one extend row per LIVE listing version at that
//! version's price, plus the four free provider-wide rows.
//!
//! "Live" is the version on sale plus every retired version that still has a
//! running lease (ADR 0009), so the table is a function of the config AND the
//! lease table — which is why every assertion here hands it both.

use toon_provider::nostr::continuation::ContinuationToken;
use toon_provider::nostr::wire::{LeaseState, Resources, Role};
use toon_provider::provider::{render_routes, LeaseRecord, Listing, ProviderConfig};

fn listing(name: &str, version: u32, price: u64) -> Listing {
    Listing {
        name: name.to_string(),
        version,
        resources: Resources {
            cpu_millicores: 500,
            memory_mb: 256,
            storage_gb: 1,
            gpu: None,
        },
        arch: "amd64".to_string(),
        lease_interval_s: 3600,
        price,
        standby_price: None,
        capabilities: vec![],
        capacity: 2,
    }
}

/// The same tier, priced for Warm Standbys too.
fn selling_standbys(name: &str, version: u32, price: u64, standby_price: u64) -> Listing {
    Listing {
        standby_price: Some(standby_price),
        ..listing(name, version, price)
    }
}

fn config() -> ProviderConfig {
    ProviderConfig {
        ilp_address: "g.acme".to_string(),
        handler_base_url: "http://provider:8080".to_string(),
        listings: vec![
            listing("basic", 1, 1000),
            listing("basic", 2, 1500),
            listing("gpu", 1, 9000),
        ],
        ..ProviderConfig::default()
    }
}

/// A running lease on `listing` v`version`, as the persisted table holds one.
fn live_lease(id: u32, listing: &str, version: u32) -> LeaseRecord {
    LeaseRecord {
        id,
        workload_id: format!("{:02x}", id as u8).repeat(32),
        continuation: ContinuationToken::from_hex(&"00".repeat(32)).unwrap(),
        listing: listing.to_string(),
        listing_version: version,
        role: Role::Standalone,
        state: LeaseState::Running,
        standby_set: None,
        reserved_spawn: None,
        takeover: None,
        settled: None,
        taken_over: false,
        created_at: 1_700_000_000,
        expires_at: 1_700_003_600,
        ended_at: None,
        destroyed: false,
        template: None,
        ssh_port: 40000,
        ports: vec![],
        hidden_address: None,
        paid_intervals: None,
    }
}

/// The rows as the connector would read them: `(prefix, handler_url, price)`.
fn rows(rendered: &str) -> Vec<(String, String, u64)> {
    #[derive(serde::Deserialize)]
    struct Row {
        prefix: String,
        handler_url: String,
        price: u64,
    }
    #[derive(serde::Deserialize)]
    struct Table {
        routes: Vec<Row>,
    }
    let table: Table = toml::from_str(rendered).expect("the output is TOML the connector can load");
    table
        .routes
        .into_iter()
        .map(|r| (r.prefix, r.handler_url, r.price))
        .collect()
}

#[test]
fn one_spawn_and_one_extend_row_per_live_listing_version_at_that_versions_price() {
    // basic v1 is retired but still holds a lease, so it keeps both rows at
    // the price it was sold at.
    let rows = rows(&render_routes(&config(), &[live_lease(1000, "basic", 1)]));
    assert!(rows.contains(&(
        "g.acme.basic.v1.spawn".to_string(),
        "http://provider:8080/listings/basic/v1/spawn".to_string(),
        1000
    )));
    assert!(rows.contains(&(
        "g.acme.basic.v1.extend".to_string(),
        "http://provider:8080/listings/basic/v1/extend".to_string(),
        1000
    )));
    // A price change is a new version with its own routes (ADR 0009).
    assert!(rows.contains(&(
        "g.acme.basic.v2.spawn".to_string(),
        "http://provider:8080/listings/basic/v2/spawn".to_string(),
        1500
    )));
    assert!(rows.contains(&(
        "g.acme.gpu.v1.extend".to_string(),
        "http://provider:8080/listings/gpu/v1/extend".to_string(),
        9000
    )));
}

#[test]
fn a_retired_version_with_no_live_lease_is_dropped_from_the_table() {
    // Nothing is running anywhere: basic v1 has been superseded by v2 and
    // has no lease left to extend, so its rows come out of the connector
    // config at the next restart.
    let rows = rows(&render_routes(&config(), &[]));
    let prefixes: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    assert!(!prefixes.contains(&"g.acme.basic.v1.spawn"));
    assert!(!prefixes.contains(&"g.acme.basic.v1.extend"));
    assert!(prefixes.contains(&"g.acme.basic.v2.spawn"));
    assert!(prefixes.contains(&"g.acme.gpu.v1.spawn"));
}

#[test]
fn an_ended_lease_does_not_keep_a_retired_version_alive() {
    use toon_provider::nostr::wire::LeaseEnd;
    let mut ended = live_lease(1000, "basic", 1);
    ended.state = LeaseState::Ended(LeaseEnd::Expiry);
    ended.ended_at = Some(1_700_003_600);
    let prefixes: Vec<String> = rows(&render_routes(&config(), &[ended]))
        .into_iter()
        .map(|r| r.0)
        .collect();
    assert!(!prefixes.contains(&"g.acme.basic.v1.spawn".to_string()));
}

/// A config whose `warm` tier sells standbys and whose `basic` tier does
/// not, in two live versions each: what the two standby rows must and must
/// not appear for.
fn config_with_standbys() -> ProviderConfig {
    ProviderConfig {
        ilp_address: "g.acme".to_string(),
        handler_base_url: "http://provider:8080".to_string(),
        listings: vec![
            listing("basic", 1, 1000),
            selling_standbys("warm", 1, 1000, 400),
            selling_standbys("warm", 2, 1500, 600),
        ],
        ..ProviderConfig::default()
    }
}

#[test]
fn a_listing_that_prices_standbys_gets_both_standby_rows_at_the_standby_price() {
    // warm v1 is retired but still holds a lease, so both of its standby
    // rows stay at the standby price it was sold at, exactly as `.spawn` and
    // `.extend` do (ADR 0009).
    let rows = rows(&render_routes(
        &config_with_standbys(),
        &[live_lease(1000, "warm", 1)],
    ));
    for (version, price) in [(1, 400), (2, 600)] {
        assert!(
            rows.contains(&(
                format!("g.acme.warm.v{}.standby", version),
                format!("http://provider:8080/listings/warm/v{}/standby", version),
                price
            )),
            "missing .standby for warm v{} in {:?}",
            version,
            rows
        );
        assert!(
            rows.contains(&(
                format!("g.acme.warm.v{}.standby.extend", version),
                format!(
                    "http://provider:8080/listings/warm/v{}/standby/extend",
                    version
                ),
                price
            )),
            "missing .standby.extend for warm v{} in {:?}",
            version,
            rows
        );
    }
}

#[test]
fn a_listing_that_prices_no_standby_gets_no_standby_rows() {
    // Nothing extra for `basic`: the connector must never terminate a route
    // the provider did not price.
    let rows = rows(&render_routes(
        &config_with_standbys(),
        &[live_lease(1000, "warm", 1)],
    ));
    let prefixes: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    assert!(prefixes.contains(&"g.acme.basic.v1.spawn"));
    assert!(!prefixes
        .iter()
        .any(|p| p.starts_with("g.acme.basic.v1.standby")));

    // And the count is exact: two rows for basic v1, four for each live
    // `warm` version, then the four free rows.
    assert_eq!(rows.len(), 2 + 4 + 4 + 4);
}

#[test]
fn a_retired_standby_version_with_no_live_lease_loses_its_standby_rows_too() {
    let prefixes: Vec<String> = rows(&render_routes(&config_with_standbys(), &[]))
        .into_iter()
        .map(|r| r.0)
        .collect();
    assert!(!prefixes.iter().any(|p| p.starts_with("g.acme.warm.v1.")));
    assert!(prefixes.contains(&"g.acme.warm.v2.standby".to_string()));
}

#[test]
fn the_four_free_rows_are_provider_wide_at_price_zero() {
    let rows = rows(&render_routes(&config(), &[]));
    for (route, path) in [
        ("availability", "/availability"),
        ("status", "/status"),
        ("terminate", "/terminate"),
        ("rotate", "/rotate"),
    ] {
        assert!(
            rows.contains(&(
                format!("g.acme.{}", route),
                format!("http://provider:8080{}", path),
                0
            )),
            "missing free row for {}",
            route
        );
    }
}

#[test]
fn exactly_two_rows_per_live_version_plus_four() {
    let with_v1_lease = rows(&render_routes(&config(), &[live_lease(1000, "basic", 1)]));
    assert_eq!(with_v1_lease.len(), 3 * 2 + 4);
    let mut prefixes: Vec<&str> = with_v1_lease.iter().map(|r| r.0.as_str()).collect();
    prefixes.sort_unstable();
    prefixes.dedup();
    assert_eq!(
        prefixes.len(),
        with_v1_lease.len(),
        "every prefix is distinct"
    );

    // Without the lease, basic v1's two rows are gone.
    assert_eq!(rows(&render_routes(&config(), &[])).len(), 2 * 2 + 4);
}

#[test]
fn a_provider_with_no_listings_still_prints_the_free_rows() {
    let rows = rows(&render_routes(
        &ProviderConfig {
            ilp_address: "g.acme".to_string(),
            listings: vec![],
            ..ProviderConfig::default()
        },
        &[],
    ));
    assert_eq!(rows.len(), 4);
}
