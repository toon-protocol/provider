//! `toon-provider topup`'s own logic (TOON_Network#171, ADR 0029 "Money":
//! top-up). Kept in its own module — rather than inline in `main.rs` — so it
//! is unit-testable with no HTTP, no process and no stdin: `main.rs` wires
//! these to `reqwest` and real `stdin`/`stderr`, and nothing else needs to.
//!
//! The publisher (`tools/publisher`) answers `POST /topup` on the same
//! origin it already answers `POST /publish` on — one process, one listener,
//! never on a published port (`deploy/docker-compose.yml`: `expose:` only,
//! no `ports:`). So this command reaches it the same way the provider app
//! already does: `publish_url`'s origin, with `/topup` in place of
//! `/publish`. It never talks to `operator_url` — the publisher holds the
//! channel, the provider app holds none of the money.

use anyhow::{Context, Result};
use url::Url;

/// The publisher's origin (`scheme://host[:port]`), derived from
/// `publish_url` (e.g. `http://directory-publisher:8081/publish`) — `/status`
/// and `/topup` are siblings of `/publish` on that same origin, never a
/// separately configured address.
pub fn publisher_origin(publish_url: &str) -> Result<String> {
    let url = Url::parse(publish_url)
        .with_context(|| format!("publish_url {publish_url:?} is not a URL"))?;
    let host = url
        .host_str()
        .with_context(|| format!("publish_url {publish_url:?} has no host"))?;
    Ok(match url.port() {
        Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
        None => format!("{}://{}", url.scheme(), host),
    })
}

/// `amount` as the publisher's `/topup` wants it: a positive integer, in the
/// token's smallest unit — the same units `TOON_DEPOSIT` and `channel
/// deposit` use. Checked here, before anything is sent, so a typo is a local
/// refusal rather than a round trip to be told the same thing.
pub fn validate_amount(amount: &str) -> Result<()> {
    let trimmed = amount.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        anyhow::bail!(
            "amount must be a positive integer in the token's smallest unit, got {amount:?}"
        );
    }
    if trimmed.bytes().all(|b| b == b'0') {
        anyhow::bail!("amount must be greater than zero");
    }
    Ok(())
}

/// Whether to go ahead: `--yes` skips the prompt outright, and otherwise the
/// operator must type `yes` (case-insensitive) — anything else, including a
/// closed stdin, refuses. `prompt` is given the question to show and returns
/// what the operator typed, so tests can hand this a canned answer instead of
/// real stdin.
pub fn confirmed(
    yes: bool,
    amount: &str,
    prompt: impl FnOnce(&str) -> Result<String>,
) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    let answer = prompt(&format!(
        "Add {amount} to the publisher's channel? Type \"yes\" to continue: "
    ))?;
    Ok(answer.trim().eq_ignore_ascii_case("yes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_drops_the_path_and_keeps_the_port() {
        assert_eq!(
            publisher_origin("http://directory-publisher:8081/publish").unwrap(),
            "http://directory-publisher:8081"
        );
    }

    #[test]
    fn origin_with_no_explicit_port() {
        assert_eq!(
            publisher_origin("https://publisher.example/publish").unwrap(),
            "https://publisher.example"
        );
    }

    #[test]
    fn origin_refuses_a_non_url() {
        assert!(publisher_origin("not a url").is_err());
    }

    #[test]
    fn origin_refuses_a_url_with_no_host() {
        assert!(publisher_origin("file:///publish").is_err());
    }

    #[test]
    fn validate_amount_accepts_a_positive_integer() {
        assert!(validate_amount("5000000").is_ok());
    }

    #[test]
    fn validate_amount_refuses_zero() {
        assert!(validate_amount("0").is_err());
    }

    #[test]
    fn validate_amount_refuses_a_decimal() {
        assert!(validate_amount("5.5").is_err());
    }

    #[test]
    fn validate_amount_refuses_a_negative_number() {
        assert!(validate_amount("-5").is_err());
    }

    #[test]
    fn validate_amount_refuses_non_numeric_text() {
        assert!(validate_amount("five million").is_err());
    }

    #[test]
    fn validate_amount_refuses_blank_input() {
        assert!(validate_amount("   ").is_err());
    }

    #[test]
    fn confirmed_skips_the_prompt_with_yes() {
        let asked = std::cell::Cell::new(false);
        let ok = confirmed(true, "5000000", |_| {
            asked.set(true);
            Ok(String::new())
        })
        .unwrap();
        assert!(ok);
        assert!(!asked.get(), "the prompt must not run when --yes is given");
    }

    #[test]
    fn confirmed_accepts_yes_case_insensitively() {
        assert!(confirmed(false, "5000000", |_| Ok("Yes\n".to_string())).unwrap());
        assert!(confirmed(false, "5000000", |_| Ok("  yes  ".to_string())).unwrap());
    }

    #[test]
    fn confirmed_refuses_anything_else() {
        assert!(!confirmed(false, "5000000", |_| Ok("no".to_string())).unwrap());
        assert!(!confirmed(false, "5000000", |_| Ok(String::new())).unwrap());
        assert!(!confirmed(false, "5000000", |_| Ok("y".to_string())).unwrap());
    }

    #[test]
    fn confirmed_propagates_a_prompt_failure() {
        assert!(confirmed(false, "5000000", |_| anyhow::bail!("stdin closed")).is_err());
    }
}
