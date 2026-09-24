//! The operator key: read from stdin, held in memory for as long as the
//! signing takes, wiped, and never written anywhere (ADR 0029 "Money: shown
//! everywhere, moved only by a person", connector ADR 0066's rule for the
//! dashboard applied to a terminal).
//!
//! - It is 64 hex characters: the 32-byte ed25519 seed `./keys.sh init`
//!   prints once, and the format `connector send --operator-key` reads.
//! - It is read byte by byte from an unbuffered handle on stdin, into a
//!   buffer that never grows (so never reallocates and leaves a copy
//!   behind), and that buffer, the decoded seed and the `SigningKey` built
//!   from it are all zeroised when dropped.
//! - No error names it: a malformed key is described by its length only.
//! - A key on the command line is refused before anything else happens
//!   (`RedeemArgs::refuse_key_on_argv`): by then it is already in `ps`,
//!   `/proc/<pid>/cmdline` and the shell's history.

use std::io::Read;

use anyhow::{bail, Result};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

/// The longest line accepted before giving up: a key and some whitespace.
/// The buffer is allocated at this size once and never grows.
const MAX_LINE: usize = 256;

/// Parse a key from `text`: 64 hex characters, surrounding whitespace
/// ignored. The error says what was wrong without repeating any of it.
pub fn parse_operator_key(text: &[u8]) -> Result<SigningKey> {
    let trimmed = text.trim_ascii();
    if trimmed.is_empty() {
        bail!(
            "no operator key on stdin: pipe it in (`… redeem < operator.key`) or type it at the \
             prompt"
        );
    }
    if trimmed.len() != 64 || !trimmed.iter().all(u8::is_ascii_hexdigit) {
        bail!(
            "the operator key must be 64 hex characters (the private half `./keys.sh init` \
             printed); what was read is {} characters{}",
            trimmed.len(),
            if trimmed.iter().all(u8::is_ascii_hexdigit) {
                ""
            } else {
                ", not all of them hex"
            }
        );
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    for (i, pair) in trimmed.chunks(2).enumerate() {
        seed[i] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(SigningKey::from_bytes(&seed))
}

fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

/// Read one line (or everything, up to EOF) from `reader` and parse it as
/// the operator key. `reader` should be unbuffered: whatever a buffered
/// reader held would outlive this function unwiped.
pub fn read_operator_key(mut reader: impl Read) -> Result<SigningKey> {
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_LINE));
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match reader.read(byte.as_mut()) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if line.len() == MAX_LINE {
                    bail!(
                        "the operator key must be 64 hex characters; the first line on stdin is \
                         longer than {MAX_LINE}"
                    );
                }
                line.push(byte[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => bail!("reading the operator key from stdin: {e}"),
        }
    }
    parse_operator_key(&line)
}

/// Turns terminal echo off for as long as it lives, so a key typed at the
/// prompt is not shown. `stty` rather than a terminal crate: it is on every
/// box this runs on, and it is one line. If it fails the key is still read
/// — it is echoed to this terminal, not written anywhere — and the operator
/// is told.
pub struct EchoOff {
    active: bool,
}

impl EchoOff {
    pub fn new() -> Self {
        let active = std::process::Command::new("stty")
            .arg("-echo")
            .stdin(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !active {
            eprintln!("(could not turn terminal echo off: the key will be shown as you type it)");
        }
        EchoOff { active }
    }
}

impl Default for EchoOff {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        if self.active {
            let _ = std::process::Command::new("stty")
                .arg("echo")
                .stdin(std::process::Stdio::inherit())
                .status();
            eprintln!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redeem::sign::keyid_hex;

    const KEY: &str = "4242424242424242424242424242424242424242424242424242424242424242";
    const KEYID: &str = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";

    #[test]
    fn a_key_line_parses_with_or_without_a_newline() {
        for input in [KEY.to_string(), format!("{KEY}\n"), format!("  {KEY}\r\n")] {
            let key = read_operator_key(input.as_bytes()).unwrap();
            assert_eq!(keyid_hex(&key), KEYID);
        }
        let upper = read_operator_key(KEY.to_uppercase().as_bytes()).unwrap();
        assert_eq!(keyid_hex(&upper), KEYID);
    }

    #[test]
    fn only_the_first_line_is_read() {
        let mut input = format!("{KEY}\nnext line").into_bytes();
        let mut cursor = std::io::Cursor::new(&mut input);
        let key = read_operator_key(&mut cursor).unwrap();
        assert_eq!(keyid_hex(&key), KEYID);
        assert_eq!(
            cursor.position(),
            65,
            "nothing past the newline is consumed"
        );
    }

    #[test]
    fn a_bad_key_is_described_without_being_repeated() {
        let not_hex = format!("{}zz", &KEY[..62]);
        for (input, says) in [
            ("", "no operator key"),
            ("\n", "no operator key"),
            (&KEY[..63], "is 63 characters"),
            (not_hex.as_str(), "not all of them hex"),
        ] {
            let error = format!("{:#}", read_operator_key(input.as_bytes()).unwrap_err());
            assert!(error.contains(says), "{input:?}: {error}");
            assert!(
                input.len() < 8 || !error.contains(&input[..8]),
                "the error repeats the key: {error}"
            );
        }
        let long = "4".repeat(MAX_LINE + 1);
        let error = format!("{:#}", read_operator_key(long.as_bytes()).unwrap_err());
        assert!(!error.contains("4444"), "{error}");
    }
}
