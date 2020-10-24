use crate::{SignedObject, UtcDateTime};
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
pub use yz_glue_dhchoice::DHChoice;

bitflags! {
    #[derive(Deserialize, Serialize)]
    pub struct PubkeyFlags: u8 {
        const A_DERIVE     = 0b00000001;
        const A_EXPAND     = 0b00000010;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum PubkeyAllowedPin {
    NetworkV4 { addr: Ipv4Addr, prefixlen: u8 },
    NetworkV6 { addr: Ipv6Addr, prefixlen: u8 },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PubkeyAssocData {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub pins: BTreeSet<PubkeyAllowedPin>,

    pub flags: PubkeyFlags,
}

impl PubkeyAssocData {
    pub fn is_allowed(&self, peer_addr: &std::net::IpAddr) -> bool {
        use self::PubkeyAllowedPin::*;
        use crate::prefix_match;
        use std::net::IpAddr;

        if self.pins.is_empty() {
            return true;
        }
        match peer_addr {
            IpAddr::V4(ip4) => {
                let peer_octs = ip4.octets();
                self.pins.iter().any(|i| {
                    if let NetworkV4 { addr, prefixlen } = i {
                        if prefix_match(&addr.octets(), &peer_octs, *prefixlen) {
                            return true;
                        }
                    }
                    false
                })
            }
            IpAddr::V6(ip6) => {
                let peer_octs = ip6.octets();
                self.pins.iter().any(|i| {
                    if let NetworkV6 { addr, prefixlen } = i {
                        if prefix_match(&addr.octets(), &peer_octs, *prefixlen) {
                            return true;
                        }
                    }
                    false
                })
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(tag = "type")]
pub struct Pubkey {
    pub dh: DHChoice,

    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub enum SignatureAlgo {
    Ed25519,
}

// we use b-tree sets and maps as these are probably faster
// to (de-/)serialize
pub type Roles = BTreeSet<serde_bytes::ByteBuf>;
pub type PubkeyMap = BTreeMap<Pubkey, PubkeyAssocData>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ticket {
    pub signature_algo: SignatureAlgo,

    pub creation_time: UtcDateTime,

    // validity check
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_last_valid_chk: Option<UtcDateTime>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ivd_valid_chk: Option<Duration>,

    // lifetime
    pub ts_lt_after: UtcDateTime,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_lt_until: Option<UtcDateTime>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_lt_renew_until: Option<UtcDateTime>,

    // ID
    pub ident: String,
    pub realm: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<u64>,

    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub roles: Roles,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pubkeys: PubkeyMap,

    /// This field allows to attach arbitrary data to the ticket,
    /// which is in turn signed by the T3P
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

impl Ticket {
    pub fn is_valid(&self, now: &UtcDateTime) -> bool {
        &self.ts_lt_after >= now && self.ts_lt_until.as_ref().map(|x| x >= now) != Some(true)
    }

    // PREREQ .is_valid()
    pub fn is_renewable(&self, now: &UtcDateTime) -> bool {
        self.ts_lt_renew_until.as_ref().map(|x| x >= now) == Some(false)
            && self.ts_lt_until.is_some()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AcquireTicketCommand {
    /// validitiy check interval
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ivd_valid_chk: Option<Duration>,

    // lifetimes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_lt_after: Option<UtcDateTime>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_lt_until: Option<UtcDateTime>,

    /// the T3P MAY restrict the lifetime to a maximum
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_lt_for: Option<Duration>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_lt_renew_until: Option<UtcDateTime>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_lt_renew_for: Option<Duration>,

    /// if set, basically try to execute the command as another user.
    /// `ident` is either taken from this value (if set),
    /// or from the authentification data
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ident: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<u64>,

    #[serde(default, skip_serializing_if = "Roles::is_empty")]
    pub roles: Roles,

    /// the T3P MAY disallow issuing tickets without specified
    /// associated pubkeys
    #[serde(default, skip_serializing_if = "PubkeyMap::is_empty")]
    pub pubkeys: PubkeyMap,

    /// This field allows to attach arbitrary data to the ticket,
    /// which is in turn signed by the T3P
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

fn combine_olt<F>(a: Option<UtcDateTime>, b: Option<UtcDateTime>, f: F) -> Option<UtcDateTime>
where
    F: FnOnce(UtcDateTime, UtcDateTime) -> UtcDateTime,
{
    match (a, b) {
        (None, None) => None,
        (Some(a), Some(b)) => Some(f(a, b)),
        (a, b) => a.or(b),
    }
}

fn combine_lt_until(
    now: &UtcDateTime,
    until: Option<UtcDateTime>,
    for_: Option<Duration>,
) -> Option<UtcDateTime> {
    combine_olt(
        until,
        for_.and_then(|x| chrono::Duration::from_std(x).ok())
            .map(|x| now.clone() + x),
        std::cmp::min,
    )
}

impl AcquireTicketCommand {
    pub fn try_finish(
        self,
        now: &UtcDateTime,
        realm: &str,
        parent_ticket: Option<&Ticket>,
        ident: &str,
    ) -> Result<Ticket, Response> {
        use std::cmp::{max, min};
        let ts_last_valid_chk = match &self.ts_lt_after {
            Some(x) if x > now => Some(now.clone()),
            _ => None,
        };
        let ts_lt_after = combine_olt(
            parent_ticket.map(|t| t.ts_lt_after.clone()),
            self.ts_lt_after.clone(),
            max,
        )
        .unwrap_or_else(|| now.clone());
        let ts_lt_until = combine_lt_until(
            now,
            combine_olt(
                parent_ticket.and_then(|t| t.ts_lt_until.clone()),
                self.ts_lt_until.clone(),
                min,
            ),
            self.ts_lt_for.clone(),
        );
        if let Some(ref until) = &ts_lt_until {
            if until < &ts_lt_after {
                return Err(Response::InvalidLifetime);
            }
        }
        let ts_lt_renew_until =
            if self.ts_lt_renew_until.is_some() || self.ts_lt_renew_for.is_some() {
                combine_lt_until(
                    now,
                    combine_olt(ts_lt_until.clone(), self.ts_lt_renew_until.clone(), min),
                    self.ts_lt_renew_for.clone(),
                )
            } else {
                None
            };
        Ok(Ticket {
            signature_algo: SignatureAlgo::Ed25519,
            creation_time: chrono::offset::Utc::now(),

            ts_last_valid_chk,
            ivd_valid_chk: self.ivd_valid_chk,

            ts_lt_after,
            ts_lt_until,
            ts_lt_renew_until,

            ident: ident.to_string(),
            realm: realm.to_string(),
            tid: self.tid,

            roles: match &parent_ticket {
                Some(t) => t.roles.intersection(&self.roles).cloned().collect(),
                None => self.roles,
            },

            pubkeys: self.pubkeys,
            payload: self.payload,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum AuthCommand {
    Password {
        username: String,
        password: serde_bytes::ByteBuf,
    },

    Ticket(SignedObject<Ticket>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Request {
    Auth(AuthCommand),

    Acquire(AcquireTicketCommand),

    /// the T3P won't accept revocations without lifetime limits
    Revoke {
        id: u64,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        ts_lt_until: Option<UtcDateTime>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        ts_lt_for: Option<Duration>,
    },

    Renew(SignedObject<Ticket>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Response {
    Success,
    Failure,
    Unimplemented,
    InvalidInvocation,
    InvalidLifetime,
    PermissionDenied,
    IdAlreadyInUse,
    Ticket(SignedObject<Ticket>),
}
