// The upstream OCI registry: one of the two places a blob's bytes can come
// from (spec §8.4), the other being the TOON store (`fetcher`).
//
// This is plain HTTP against the OCI distribution API — `GET
// /v2/<repository>/manifests/<digest>` for an index or a manifest, `GET
// /v2/<repository>/blobs/<digest>` for a config or a layer — with the
// generic anonymous bearer flow every public registry speaks. It returns RAW
// bytes: verifying them against the digest that was asked for is the
// fetcher's job, done identically for every source, so no source can skip
// it.
//
// Lifted out of `image_policy` (Milestone 1's manifest client) when the
// Image Registry entry made a blob's source a value rather than a fact about
// the whole image: an entry's `oci` source names a registry and a repository
// directly, and Milestone 1's `reference` form parses into the same pair.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use bytes::BytesMut;
use reqwest::header::{HeaderValue, ACCEPT, WWW_AUTHENTICATE};
use serde_json::Value;

use crate::outbound_guard::OutboundGuard;

/// Every OCI/Docker media type this provider reads as a manifest: an index
/// (OCI or the older Docker manifest list) or a single-platform manifest.
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.docker.distribution.manifest.v2+json";

/// How large a manifest or an index's own body may be before a fetch gives
/// up on it (TOON_Network#79) — a fixed ceiling, unrelated to any blob-size
/// limit, since nothing describes a size for these ahead of fetching them:
/// they are what a size (§8.1's `EntryBlob.size`, or a manifest's own
/// per-layer `size`) is read FROM. A real manifest or index is a few KB to
/// a few hundred KB even for a large image; generous headroom over that.
const MANIFEST_JSON_CEILING_BYTES: u64 = 16 * 1024 * 1024;

/// Which distribution endpoint a blob lives behind. A registry serves
/// indexes and manifests from `/manifests/` and everything else from
/// `/blobs/`; the media type decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciEndpoint {
    Manifests,
    Blobs,
}

impl OciEndpoint {
    /// The endpoint for a blob of `media_type`: indexes and manifests are
    /// served by `/manifests/`, configs and layers by `/blobs/`.
    pub fn for_media_type(media_type: &str) -> Self {
        if media_type.contains("manifest") || media_type.contains("image.index") {
            Self::Manifests
        } else {
            Self::Blobs
        }
    }

    fn path_segment(self) -> &'static str {
        match self {
            Self::Manifests => "manifests",
            Self::Blobs => "blobs",
        }
    }
}

/// An HTTP client for upstream registries. Cheap to clone: it holds only a
/// `reqwest::Client` (itself an `Arc`), the test override and the address
/// guard (also an `Arc`).
#[derive(Clone)]
pub struct OciClient {
    client: reqwest::Client,
    /// When set, every registry request goes to this base URL
    /// (`scheme://host[:port]`) instead of the registry named by the caller.
    /// Tests point it at a `wiremock` server.
    base_url_override: Option<String>,
    /// Where a fetch may go (TOON_Network#105). The `client` already
    /// resolves and redirects through this same guard; it is held here as
    /// well because the two URLs a TENANT or a hostile REGISTRY chooses —
    /// the registry a `reference` names, and the realm its 401 names — are
    /// refused before the request is built, so a URL that is refused on its
    /// face never becomes a connection at all.
    guard: Arc<OutboundGuard>,
}

impl OciClient {
    pub fn new(
        client: reqwest::Client,
        base_url_override: Option<String>,
        guard: Arc<OutboundGuard>,
    ) -> Self {
        Self {
            client,
            base_url_override,
            guard,
        }
    }

    /// The same client, dialling on `client` instead — how a Hidden
    /// Provider's fetcher swaps in one bound to the `anon` SOCKS port
    /// (`BlobFetcher::with_proxy`), token exchange included.
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// The raw bytes of `digest` from `registry`'s `repository`, over the
    /// endpoint the blob's kind calls for. Unverified: the caller checks
    /// them against `digest`.
    ///
    /// Streamed chunk by chunk and cut off the instant the body exceeds its
    /// bound (TOON_Network#79), the same way `fetcher::gateway_read` bounds
    /// a TOON store read — a hostile or merely misconfigured upstream
    /// registry gets no more chance to exhaust memory than a hostile
    /// gateway does. `Manifests` is bounded by the fixed
    /// `MANIFEST_JSON_CEILING_BYTES`, since nothing describes a size for an
    /// index or a manifest ahead of fetching it; `Blobs` is bounded by
    /// `blob_size_hint` — the blob's own declared size, an Image Registry
    /// entry's `EntryBlob.size` (§8.1), when the caller has one — or
    /// `default_blob_limit` (the provider's own whole-blob limit,
    /// `BlobFetcher::blob_byte_limit`) otherwise.
    pub async fn fetch(
        &self,
        registry: &str,
        repository: &str,
        endpoint: OciEndpoint,
        digest: &str,
        blob_size_hint: Option<u64>,
        default_blob_limit: u64,
    ) -> Result<bytes::Bytes> {
        let base = self
            .base_url_override
            .clone()
            .unwrap_or_else(|| format!("https://{}", pull_host(registry)));
        let url = format!(
            "{}/v2/{}/{}/{}",
            base,
            repository,
            endpoint.path_segment(),
            digest
        );
        let what = format!("{} {}/{}", endpoint.path_segment(), registry, repository);

        // The registry host came from the tenant's `reference`, so this is
        // the door (TOON_Network#105): an address inside the operator's own
        // network is refused here, before anything is sent, and the failure
        // names the SOURCE — `oci <registry>/<repository>`, which is what
        // §8.4's chain records and what `refused_image` ends up carrying.
        let parsed = reqwest::Url::parse(&url)
            .with_context(|| format!("{} does not name a URL to fetch {} from", what, digest))?;
        self.guard
            .check_url(&parsed)
            .with_context(|| format!("{} cannot be fetched", what))?;

        let send = |bearer: Option<&str>| {
            let mut req = self.client.get(&url);
            if endpoint == OciEndpoint::Manifests {
                req = req.header(ACCEPT, MANIFEST_ACCEPT);
            }
            if let Some(token) = bearer {
                req = req.bearer_auth(token);
            }
            req.send()
        };

        let response = send(None)
            .await
            .with_context(|| format!("could not reach registry for {} ({})", what, digest))?;

        let mut response = if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            // The generic bearer challenge flow (docker distribution spec):
            // the 401 names a token endpoint in `Www-Authenticate`, and an
            // anonymous pull token from it is usually enough for a public
            // image. `docker.io` itself always challenges this way; other
            // registries are tried anonymously first and only challenged if
            // they answer 401.
            match response.headers().get(WWW_AUTHENTICATE) {
                Some(challenge) => {
                    let token = self.bearer_token(challenge, repository).await?;
                    send(Some(&token)).await.with_context(|| {
                        format!(
                            "could not reach registry for {} ({}) after authenticating",
                            what, digest
                        )
                    })?
                }
                None => response,
            }
        } else {
            response
        };

        if !response.status().is_success() {
            bail!(
                "registry refused to serve {} for {}: HTTP {}",
                digest,
                what,
                response.status()
            );
        }
        let limit = match endpoint {
            OciEndpoint::Manifests => MANIFEST_JSON_CEILING_BYTES,
            OciEndpoint::Blobs => blob_size_hint.unwrap_or(default_blob_limit),
        };
        let mut body = BytesMut::with_capacity(usize::try_from(limit).unwrap_or(0));
        while let Some(chunk) = response
            .chunk()
            .await
            .with_context(|| format!("could not read the body of {} ({})", what, digest))?
        {
            body.extend_from_slice(&chunk);
            if body.len() as u64 > limit {
                bail!(
                    "the body of {} ({}) is longer than the {} bytes allowed for it",
                    what,
                    digest,
                    limit
                );
            }
        }
        Ok(body.freeze())
    }

    /// Exchange a `WWW-Authenticate: Bearer ...` challenge for an anonymous
    /// pull token, the way every OCI-distribution registry's public images
    /// are fetched without credentials.
    async fn bearer_token(&self, challenge: &HeaderValue, repository: &str) -> Result<String> {
        let challenge = challenge
            .to_str()
            .map_err(|_| anyhow!("registry sent a non-UTF-8 Www-Authenticate challenge"))?;
        let params = parse_bearer_challenge(challenge)
            .ok_or_else(|| anyhow!("unsupported Www-Authenticate challenge: {}", challenge))?;
        let realm = params
            .get("realm")
            .ok_or_else(|| anyhow!("bearer challenge has no realm"))?;

        let mut url = reqwest::Url::parse(realm)
            .with_context(|| format!("bearer challenge realm {:?} is not a URL", realm))?;
        // The realm is chosen by whatever answered the 401 — on a registry a
        // tenant named, that is the tenant's own server, and this request
        // would go wherever it says. Checked exactly like the registry was
        // (TOON_Network#105), plus `https`, because the answer is a
        // credential.
        self.guard.check_realm(&url)?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(service) = params.get("service") {
                query.append_pair("service", service);
            }
            let scope = params
                .get("scope")
                .cloned()
                .unwrap_or_else(|| format!("repository:{}:pull", repository));
            query.append_pair("scope", &scope);
        }

        let response = self
            .client
            .get(url)
            .send()
            .await
            .context("could not reach token endpoint")?;
        if !response.status().is_success() {
            bail!(
                "token endpoint refused an anonymous pull token: HTTP {}",
                response.status()
            );
        }
        let body: Value = response
            .json()
            .await
            .context("token endpoint response is not JSON")?;
        body.get("token")
            .or_else(|| body.get("access_token"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("token endpoint response has no token"))
    }
}

/// The host actually dialled for a registry name: Docker Hub's `docker.io`
/// is a name, and its pull endpoint is `registry-1.docker.io`.
fn pull_host(registry: &str) -> &str {
    if registry == "docker.io" {
        "registry-1.docker.io"
    } else {
        registry
    }
}

/// `Bearer realm="...",service="...",scope="..."` into its key/value pairs.
/// `None` if the challenge isn't the `Bearer` scheme this flow handles.
fn parse_bearer_challenge(challenge: &str) -> Option<HashMap<String, String>> {
    let rest = challenge.trim().strip_prefix("Bearer")?.trim_start();
    let mut params = HashMap::new();
    for part in split_challenge_params(rest) {
        let (key, value) = part.split_once('=')?;
        let value = value.trim().trim_matches('"');
        params.insert(key.trim().to_string(), value.to_string());
    }
    Some(params)
}

/// Split on commas that are outside a quoted value, since a scope
/// (`repository:a/b:pull`) never itself contains a comma but the header as a
/// whole is comma-separated `key="value"` pairs.
fn split_challenge_params(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                parts.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(s[start..].trim());
    parts
}

/// `registry.docker.io`-style scheme: everything up to the first `/` is a
/// registry host only if it looks like one (has a `.` or `:`, or is
/// `localhost`); otherwise the whole reference is a Docker Hub repository
/// (bare `alpine` means `library/alpine`), matching what
/// `image_events::looks_like_repository` already accepts.
pub fn parse_reference(reference: &str) -> (String, String) {
    let mut parts = reference.splitn(2, '/');
    let first = parts.next().unwrap_or("");
    let rest = parts.next();
    let looks_like_host = first.contains('.') || first.contains(':') || first == "localhost";
    if looks_like_host {
        (first.to_string(), rest.unwrap_or("").to_string())
    } else {
        match rest {
            Some(_) => ("docker.io".to_string(), reference.to_string()),
            None => ("docker.io".to_string(), format!("library/{}", reference)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_hub_references_normalise_to_docker_io() {
        assert_eq!(
            parse_reference("alpine"),
            ("docker.io".to_string(), "library/alpine".to_string())
        );
        assert_eq!(
            parse_reference("library/alpine"),
            ("docker.io".to_string(), "library/alpine".to_string())
        );
        assert_eq!(
            parse_reference("myuser/myapp"),
            ("docker.io".to_string(), "myuser/myapp".to_string())
        );
    }

    #[test]
    fn hosted_references_keep_their_registry() {
        assert_eq!(
            parse_reference("lscr.io/linuxserver/openssh-server"),
            (
                "lscr.io".to_string(),
                "linuxserver/openssh-server".to_string()
            )
        );
        assert_eq!(
            parse_reference("localhost:5000/team/app"),
            ("localhost:5000".to_string(), "team/app".to_string())
        );
    }

    #[test]
    fn manifests_and_indexes_go_to_the_manifests_endpoint_and_the_rest_to_blobs() {
        assert_eq!(
            OciEndpoint::for_media_type("application/vnd.oci.image.index.v1+json"),
            OciEndpoint::Manifests
        );
        assert_eq!(
            OciEndpoint::for_media_type("application/vnd.oci.image.manifest.v1+json"),
            OciEndpoint::Manifests
        );
        assert_eq!(
            OciEndpoint::for_media_type(
                "application/vnd.docker.distribution.manifest.list.v2+json"
            ),
            OciEndpoint::Manifests
        );
        assert_eq!(
            OciEndpoint::for_media_type("application/vnd.oci.image.config.v1+json"),
            OciEndpoint::Blobs
        );
        assert_eq!(
            OciEndpoint::for_media_type("application/vnd.oci.image.layer.v1.tar+gzip"),
            OciEndpoint::Blobs
        );
    }

    #[test]
    fn bearer_challenge_parses_realm_service_and_scope() {
        let params = parse_bearer_challenge(
            "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/alpine:pull\"",
        )
        .unwrap();
        assert_eq!(params["realm"], "https://auth.docker.io/token");
        assert_eq!(params["service"], "registry.docker.io");
        assert_eq!(params["scope"], "repository:library/alpine:pull");
    }

    #[test]
    fn a_non_bearer_challenge_is_not_parsed() {
        assert!(parse_bearer_challenge("Basic realm=\"x\"").is_none());
    }
}
