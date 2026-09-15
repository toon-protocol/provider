// The routes this provider expects its connector to carry, and the HTTP paths
// the connector forwards each of them to.
//
// The connector terminates payment and forwards a plain POST to `handler_url`;
// this module is the one place that says which ILP prefix maps to which path,
// so `toon-provider routes` and the axum router cannot disagree.

use std::fmt::Write;

use super::config::ProviderConfig;

/// HTTP path the connector forwards `<addr>.<listing>.v<n>.spawn` to.
pub fn spawn_path(listing: &str, version: u32) -> String {
    format!("/listings/{}/v{}/spawn", listing, version)
}

/// HTTP path the connector forwards `<addr>.<listing>.v<n>.extend` to.
pub fn extend_path(listing: &str, version: u32) -> String {
    format!("/listings/{}/v{}/extend", listing, version)
}

pub const AVAILABILITY_PATH: &str = "/availability";
pub const STATUS_PATH: &str = "/status";
pub const TERMINATE_PATH: &str = "/terminate";

/// One connector route row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRow {
    pub prefix: String,
    pub handler_url: String,
    /// µUSDC. 0 for the free provider-wide routes.
    pub price: u64,
}

/// Every route this provider serves: one spawn and one extend row per listing
/// version at the listing price, then the three free provider-wide rows.
pub fn route_table(config: &ProviderConfig) -> Vec<RouteRow> {
    let base = config.handler_base_url.trim_end_matches('/');
    let addr = &config.ilp_address;
    let mut rows = Vec::with_capacity(config.listings.len() * 2 + 3);
    for listing in &config.listings {
        rows.push(RouteRow {
            prefix: format!("{}.{}.v{}.spawn", addr, listing.name, listing.version),
            handler_url: format!("{}{}", base, spawn_path(&listing.name, listing.version)),
            price: listing.price,
        });
        rows.push(RouteRow {
            prefix: format!("{}.{}.v{}.extend", addr, listing.name, listing.version),
            handler_url: format!("{}{}", base, extend_path(&listing.name, listing.version)),
            price: listing.price,
        });
    }
    for (route, path) in [
        ("availability", AVAILABILITY_PATH),
        ("status", STATUS_PATH),
        ("terminate", TERMINATE_PATH),
    ] {
        rows.push(RouteRow {
            prefix: format!("{}.{}", addr, route),
            handler_url: format!("{}{}", base, path),
            price: 0,
        });
    }
    rows
}

/// The route table as `[[routes]]` TOML blocks, ready to paste into the
/// connector's config.
pub fn render_routes(config: &ProviderConfig) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Connector routes for provider {:?} ({}). One spawn and one extend row\n\
         # per listing version at the listing price; availability, status and\n\
         # terminate are free. Regenerate with `toon-provider routes`.",
        config.provider_name, config.ilp_address
    );
    for row in route_table(config) {
        let _ = write!(
            out,
            "\n[[routes]]\nprefix = {:?}\nhandler_url = {:?}\nprice = {}\n",
            row.prefix, row.handler_url, row.price
        );
    }
    out
}
