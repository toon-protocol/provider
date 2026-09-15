// The routes this provider expects its connector to carry, and the HTTP paths
// the connector forwards each of them to.
//
// The connector terminates payment and forwards a plain POST to `handler_url`;
// this module is the one place that says which ILP prefix maps to which path,
// so `toon-provider routes` and the axum router cannot disagree.

use std::fmt::Write;

use super::config::ProviderConfig;

/// The axum route pattern every per-listing path is an instance of: the
/// router registers these, and `spawn_path` / `extend_path` fill them in.
pub const SPAWN_PATTERN: &str = "/listings/:listing/:version/spawn";
pub const EXTEND_PATTERN: &str = "/listings/:listing/:version/extend";

fn fill(pattern: &str, listing: &str, version: u32) -> String {
    pattern
        .replace(":listing", listing)
        .replace(":version", &format!("v{}", version))
}

/// HTTP path the connector forwards `<addr>.<listing>.v<n>.spawn` to.
pub fn spawn_path(listing: &str, version: u32) -> String {
    fill(SPAWN_PATTERN, listing, version)
}

/// HTTP path the connector forwards `<addr>.<listing>.v<n>.extend` to.
pub fn extend_path(listing: &str, version: u32) -> String {
    fill(EXTEND_PATTERN, listing, version)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rendered_paths_are_instances_of_the_router_patterns() {
        assert_eq!(spawn_path("basic", 3), "/listings/basic/v3/spawn");
        assert_eq!(extend_path("gpu", 1), "/listings/gpu/v1/extend");
    }
}
