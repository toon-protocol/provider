//! Which channels a redeem touches: the ones the operator named
//! (`--channel`), everything over a floor (`--all-above`), or the ones
//! picked at the prompt. Pure, so the rules are tested on their own.

use anyhow::{bail, Result};

use crate::status::{channel_key, ChannelEarnings};

/// The channels a redeem can do anything for: money is unredeemed and the
/// channel is not settled (a closed one still redeems until it settles).
pub fn redeemable(channels: &[ChannelEarnings]) -> Vec<ChannelEarnings> {
    channels
        .iter()
        .filter(|c| c.unredeemed > 0 && c.status.as_deref() != Some("settled"))
        .cloned()
        .collect()
}

/// `--channel` ids against the redeemable list, in the order given. An id
/// the connector holds no redeemable money on is an error naming it — a
/// typo must not quietly redeem nothing — and so is a duplicate, which
/// would sign the same redeem twice.
pub fn by_ids(candidates: &[ChannelEarnings], ids: &[String]) -> Result<Vec<ChannelEarnings>> {
    let mut picked: Vec<ChannelEarnings> = Vec::new();
    for id in ids {
        let key = channel_key(id);
        let Some(channel) = candidates
            .iter()
            .find(|c| channel_key(&c.channel_id) == key)
        else {
            bail!(
                "--channel {id}: the connector holds no unredeemed claim on that channel (run \
                 `toon-provider redeem --list` to see the ones it does)"
            );
        };
        if picked.iter().any(|p| channel_key(&p.channel_id) == key) {
            bail!("--channel {id} is given twice");
        }
        picked.push(channel.clone());
    }
    Ok(picked)
}

/// `--all-above <amount>`: every channel whose unredeemed amount is
/// strictly more than `floor` base units.
pub fn above(candidates: &[ChannelEarnings], floor: u128) -> Vec<ChannelEarnings> {
    candidates
        .iter()
        .filter(|c| c.unredeemed > floor)
        .cloned()
        .collect()
}

/// An answer at the pick prompt, as indexes into a list of `count` rows:
/// `1,3`, `1 3`, `2-4`, `all`, or nothing (or `none`) for none. Numbers are
/// the 1-based row numbers the table printed.
pub fn parse_picks(answer: &str, count: usize) -> Result<Vec<usize>> {
    let answer = answer.trim();
    if answer.is_empty() || answer.eq_ignore_ascii_case("none") {
        return Ok(Vec::new());
    }
    if answer.eq_ignore_ascii_case("all") {
        return Ok((0..count).collect());
    }
    let mut picked = Vec::new();
    for token in answer
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
    {
        let (from, to) = match token.split_once('-') {
            Some((a, b)) => (row(a, count)?, row(b, count)?),
            None => {
                let n = row(token, count)?;
                (n, n)
            }
        };
        if from > to {
            bail!("{token:?} runs backwards");
        }
        for n in from..=to {
            if !picked.contains(&n) {
                picked.push(n);
            }
        }
    }
    Ok(picked)
}

/// A 1-based row number as a 0-based index.
fn row(text: &str, count: usize) -> Result<usize> {
    match text.trim().parse::<usize>() {
        Ok(n) if (1..=count).contains(&n) => Ok(n - 1),
        _ => bail!("{text:?} is not a row number between 1 and {count}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel(id: &str, unredeemed: u128, status: Option<&str>) -> ChannelEarnings {
        ChannelEarnings {
            channel_id: id.to_string(),
            counterparty: None,
            status: status.map(str::to_string),
            deposited: None,
            claimed: unredeemed,
            redeemed: 0,
            unredeemed,
            last_redeemed_at: None,
        }
    }

    fn evm(n: u8) -> String {
        format!("0x{}", format!("{n:02x}").repeat(32))
    }

    fn ids(list: &[ChannelEarnings]) -> Vec<&str> {
        list.iter().map(|c| c.channel_id.as_str()).collect()
    }

    #[test]
    fn nothing_owed_and_settled_channels_are_not_offered() {
        let all = [
            channel(&evm(1), 5_000, Some("open")),
            channel(&evm(2), 0, Some("open")),
            channel(&evm(3), 700, Some("settled")),
            channel(&evm(4), 700, Some("closed")),
            channel("2aEVJ8koKD8LTZrLRSGtAtU7LBt4e7QjjCgf1kzQ7Rip", 1, None),
        ];
        assert_eq!(
            ids(&redeemable(&all)),
            [
                evm(1).as_str(),
                evm(4).as_str(),
                "2aEVJ8koKD8LTZrLRSGtAtU7LBt4e7QjjCgf1kzQ7Rip"
            ]
        );
    }

    #[test]
    fn all_above_is_strictly_above() {
        let all = [
            channel(&evm(1), 1_000, None),
            channel(&evm(2), 1_001, None),
            channel(&evm(3), 50_000, None),
        ];
        assert_eq!(ids(&above(&all, 1_000)), [evm(2), evm(3)]);
        assert_eq!(above(&all, 50_000).len(), 0);
        assert_eq!(above(&all, 0).len(), 3);
    }

    #[test]
    fn channel_ids_match_however_they_are_spelled_and_in_the_order_given() {
        let all = [
            channel(&evm(1), 10, None),
            channel(&evm(2), 20, None),
            channel("2aEVJ8koKD8LTZrLRSGtAtU7LBt4e7QjjCgf1kzQ7Rip", 30, None),
        ];
        let picked = by_ids(
            &all,
            &[
                "solana:2aEVJ8koKD8LTZrLRSGtAtU7LBt4e7QjjCgf1kzQ7Rip".into(),
                evm(2).to_uppercase().replace("0X", ""),
            ],
        )
        .unwrap();
        assert_eq!(
            ids(&picked),
            [
                "2aEVJ8koKD8LTZrLRSGtAtU7LBt4e7QjjCgf1kzQ7Rip",
                evm(2).as_str()
            ]
        );
    }

    #[test]
    fn an_unknown_or_repeated_channel_is_refused() {
        let all = [channel(&evm(1), 10, None)];
        let error = by_ids(&all, &[evm(9)]).unwrap_err().to_string();
        assert!(error.contains(&evm(9)), "{error}");
        assert!(by_ids(&all, &[evm(1), evm(1)]).is_err());
    }

    #[test]
    fn picks_parse_lists_ranges_all_and_none() {
        assert_eq!(parse_picks("", 3).unwrap(), Vec::<usize>::new());
        assert_eq!(parse_picks("none", 3).unwrap(), Vec::<usize>::new());
        assert_eq!(parse_picks("all", 3).unwrap(), [0, 1, 2]);
        assert_eq!(parse_picks("1,3", 3).unwrap(), [0, 2]);
        assert_eq!(parse_picks(" 3 1 ", 3).unwrap(), [2, 0]);
        assert_eq!(parse_picks("2-3, 2", 3).unwrap(), [1, 2]);
        assert!(parse_picks("0", 3).is_err());
        assert!(parse_picks("4", 3).is_err());
        assert!(parse_picks("3-1", 3).is_err());
        assert!(parse_picks("one", 3).is_err());
    }
}
