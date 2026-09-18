// Standby Sets: which role a spawn gives THIS provider, and what the lease it
// creates remembers about the set (spec §6.2 step 3, §7).
//
// A tenant forms a Standby Set by sending one spawn to each member —
// `standby_set` lists the members' public keys, primary first, under one
// `workload_id`, and every member gets a request naming only itself. The
// CONTENT is still the same at every member, so nothing in it says what any
// single provider should do; the role comes from two things together: this
// provider's POSITION in the list, and WHICH ROUTE the request arrived on.
// Index 0 runs the workload and arrives on `.spawn`; every other index holds
// capacity and arrives on `.standby`. A mismatch between the two is a
// mis-addressed spawn and does nothing (spec §6.2 step 3).
//
// Membership never changes: a new set is a new spawn under a new workload id
// (spec §7), so nothing here ever updates a set.

use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};

use crate::nostr::wire::{ErrorCode, ErrorResponse, Op, Role};

/// Which of the two paid spawn routes a request arrived on.
///
/// Not a detail of the HTTP layer: the route is half of the role rule above,
/// because a spawn's CONTENT is identical at every member of the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnRoute {
    /// `<addr>.<listing>.v<n>.spawn`, at the listing's `price`.
    Spawn,
    /// `<addr>.<listing>.v<n>.standby`, at its `standby_price`.
    Standby,
}

impl SpawnRoute {
    /// The `op` a Lease Request must carry to be served here (spec §6.1).
    /// One op per route, so a request meant to reserve capacity can never be
    /// served as one meant to run a workload.
    pub(super) fn op(self) -> Op {
        match self {
            SpawnRoute::Spawn => Op::Spawn,
            SpawnRoute::Standby => Op::Standby,
        }
    }
}

/// The Standby Set a lease serves in, kept with the lease (spec §7).
///
/// Persisted, because everything a Warm Standby does after the spawn needs
/// it: the primary whose Liveness it watches is `members[0]`, and the
/// Takeover race is settled among `members` alone.
///
/// No `deny_unknown_fields`, unlike the wire shapes in `nostr::wire`: this
/// never crosses the wire, and one unknown key in a state file written by a
/// later version would fail the WHOLE table's parse and take every lease
/// with it (`persistence::load_leases`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandbySet {
    /// Every member's public key as 64 lowercase hex characters, primary
    /// first. Normalised on the way in, so a tenant that shipped `npub1…`
    /// and one that shipped hex leave the same record behind.
    pub members: Vec<String>,
    /// This provider's own position in `members`. 0 is the primary.
    pub index: usize,
}

impl StandbySet {
    /// The primary's public key: index 0 of the set, whatever this
    /// provider's own position is (spec §7). It is the key a Warm Standby
    /// watches Liveness for, and the `primary` a Takeover names.
    ///
    /// `None` only for a set with no members, which `membership` refuses to
    /// build — but this struct is also read back off disk, where nothing
    /// re-checks it, and a hand-edited state file must not panic a provider
    /// with paid leases on it.
    pub fn primary(&self) -> Option<&str> {
        self.members.first().map(String::as_str)
    }

    /// Whether this provider is the set's primary.
    pub fn is_primary(&self) -> bool {
        self.index == 0
    }
}

/// What a spawn's `standby_set` and its route make this provider: the role
/// the lease takes, and the set it remembers.
pub(super) struct Membership {
    pub role: Role,
    /// `None` for a standalone lease — a spawn with no `standby_set` at all.
    pub set: Option<StandbySet>,
}

fn invalid(message: impl Into<String>) -> ErrorResponse {
    ErrorResponse::new(ErrorCode::InvalidRequest, message)
}

/// Step 3 of the spec's spawn validation (§6.2): the role.
///
/// Every failure here is `invalid_request`: §6.2 names no code for step 3,
/// and a mis-addressed spawn is a request the tenant must correct rather
/// than one this provider could serve at another time or price. The refusal
/// is still billed (ADR 0003), so each says exactly what was wrong.
///
/// Who the request was addressed to is not asked here any more: a Lease
/// Request names exactly one provider on every op (§6.1), and step 1 has
/// already refused one that names anybody but this provider.
pub(super) fn membership(
    standby_set: Option<&[String]>,
    provider: &PublicKey,
    route: SpawnRoute,
) -> Result<Membership, ErrorResponse> {
    let Some(members) = standby_set else {
        // No set: a standalone lease, and `.standby` sells none.
        if route == SpawnRoute::Standby {
            return Err(invalid(
                "a spawn with no standby_set buys a standalone lease; buy it on .spawn",
            ));
        }
        return Ok(Membership {
            role: Role::Standalone,
            set: None,
        });
    };

    let keys = parse_members(members)?;
    let Some(index) = keys.iter().position(|k| k == provider) else {
        return Err(invalid(
            "this provider's key is not in the standby_set; a spawn goes only to the \
             providers the set names",
        ));
    };
    let role = match (index, route) {
        (0, SpawnRoute::Spawn) => Role::Primary,
        (0, SpawnRoute::Standby) => {
            return Err(invalid(
                "index 0 of a standby_set is the primary, which runs the workload; buy it \
                 on .spawn",
            ))
        }
        (_, SpawnRoute::Standby) => Role::Standby,
        (index, SpawnRoute::Spawn) => {
            return Err(invalid(format!(
                "index {} of a standby_set is a Warm Standby, which runs nothing; buy it \
                 on .standby",
                index
            )))
        }
    };

    Ok(Membership {
        role,
        set: Some(StandbySet {
            members: keys.iter().map(|k| k.to_hex()).collect(),
            index,
        }),
    })
}

/// Every member as a public key, in order.
///
/// A member that is not a key at all, or a key listed twice — which would
/// give one provider two positions and so two roles — is a set nobody can
/// take a position in.
fn parse_members(members: &[String]) -> Result<Vec<PublicKey>, ErrorResponse> {
    if members.is_empty() {
        return Err(invalid(
            "standby_set: an empty list names no provider; omit it for a standalone lease",
        ));
    }
    let mut keys = Vec::with_capacity(members.len());
    for (index, member) in members.iter().enumerate() {
        let key = PublicKey::parse(member)
            .map_err(|e| invalid(format!("standby_set[{}] is not a public key: {}", index, e)))?;
        if keys.contains(&key) {
            return Err(invalid(format!(
                "standby_set[{}] is listed twice; a provider has one position in a set",
                index
            )));
        }
        keys.push(key);
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    use nostr_sdk::{Keys, ToBech32};

    fn key() -> Keys {
        Keys::generate()
    }

    fn role_on(
        set: &[PublicKey],
        me: &PublicKey,
        route: SpawnRoute,
    ) -> Result<Membership, ErrorResponse> {
        let members: Vec<String> = set.iter().map(|k| k.to_hex()).collect();
        membership(Some(&members), me, route)
    }

    #[test]
    fn position_and_route_together_name_the_role() {
        let primary = key().public_key();
        let standby = key().public_key();
        let set = [primary, standby];

        let mine = role_on(&set, &primary, SpawnRoute::Spawn).unwrap();
        assert_eq!(mine.role, Role::Primary);
        assert!(mine.set.as_ref().unwrap().is_primary());

        let theirs = role_on(&set, &standby, SpawnRoute::Standby).unwrap();
        assert_eq!(theirs.role, Role::Standby);
        let theirs = theirs.set.unwrap();
        assert_eq!(theirs.index, 1);
        // Whatever its own position, a member knows who to watch.
        assert_eq!(theirs.primary(), Some(primary.to_hex().as_str()));
    }

    #[test]
    fn a_role_that_does_not_match_the_route_is_refused() {
        let primary = key().public_key();
        let standby = key().public_key();
        let set = [primary, standby];
        assert!(role_on(&set, &primary, SpawnRoute::Standby).is_err());
        assert!(role_on(&set, &standby, SpawnRoute::Spawn).is_err());
    }

    #[test]
    fn a_set_that_does_not_name_this_provider_is_refused() {
        let set = [key().public_key(), key().public_key()];
        assert!(role_on(&set, &key().public_key(), SpawnRoute::Standby).is_err());
    }

    #[test]
    fn an_empty_set_names_nobody() {
        // `[]` is not "a set of one, me": a spawn with no members has no
        // index 0 to be the primary, so it describes no Standby Set at all.
        let me = key().public_key();
        assert!(membership(Some(&[]), &me, SpawnRoute::Spawn).is_err());
        assert!(membership(Some(&[]), &me, SpawnRoute::Standby).is_err());
    }

    #[test]
    fn a_member_listed_twice_has_no_single_position() {
        let me = key().public_key();
        let hex = me.to_hex();
        assert!(membership(Some(&[hex.clone(), hex]), &me, SpawnRoute::Spawn).is_err());
    }

    #[test]
    fn a_bech32_member_names_the_same_provider_as_its_hex() {
        // A tenant may ship either spelling; the record keeps hex.
        let me = key().public_key();
        let set = vec![me.to_bech32().unwrap(), key().public_key().to_hex()];
        let mine = membership(Some(&set), &me, SpawnRoute::Spawn).unwrap();
        assert_eq!(mine.set.unwrap().members[0], me.to_hex());
    }

    #[test]
    fn a_standalone_spawn_belongs_to_no_set() {
        let me = key().public_key();
        let mine = membership(None, &me, SpawnRoute::Spawn).unwrap();
        assert_eq!(mine.role, Role::Standalone);
        assert!(mine.set.is_none());
        // …and buys nothing on the standby route.
        assert!(membership(None, &me, SpawnRoute::Standby).is_err());
    }

    #[test]
    fn each_route_serves_one_op() {
        // A request meant to reserve capacity can never be served as one
        // meant to run a workload: the op says which, and `lease_request`
        // refuses a mismatch before this module is reached (spec §6.1).
        assert_eq!(SpawnRoute::Spawn.op(), Op::Spawn);
        assert_eq!(SpawnRoute::Standby.op(), Op::Standby);
    }
}
