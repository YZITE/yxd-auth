use crate::UtcDateTime;
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use zeroize::Zeroize;

bitflags! {
    #[derive(Deserialize, Serialize)]
    pub struct PubkeyFlags: u8 {
        const A_DERIVE     = 0b00000001;
        const A_LIM_EXPAND = 0b00000010;
        const A_EXPAND     = 0b00000100;
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
    pins: BTreeSet<PubkeyAllowedPin>,
    flags: PubkeyFlags,
}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize, Zeroize,
)]
pub enum DHChoice {
    Ed25519,
    Ed448,
}

impl From<snow::params::DHChoice> for DHChoice {
    fn from(x: snow::params::DHChoice) -> DHChoice {
        use snow::params::DHChoice as SnDhc;
        match x {
            SnDhc::Curve25519 => DHChoice::Ed25519,
            SnDhc::Ed448 => DHChoice::Ed448,
        }
    }
}

impl From<DHChoice> for snow::params::DHChoice {
    fn from(x: DHChoice) -> Self {
        use snow::params::DHChoice as SnDhc;
        match x {
            DHChoice::Ed25519 => SnDhc::Curve25519,
            DHChoice::Ed448 => SnDhc::Ed448,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize, Zeroize)]
#[serde(tag = "type")]
#[zeroize(drop)]
pub struct Pubkey {
    dh: DHChoice,
    value: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Ticket {
    creation_time: UtcDateTime,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    ts_last_valid_chk: Option<UtcDateTime>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    ivd_valid_chk: Option<Duration>,

    ts_lt_after: UtcDateTime,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    ts_lt_until: Option<UtcDateTime>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    ts_lt_renew_until: Option<UtcDateTime>,

    ident: String,
    realm: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<u64>,

    // we use b-tree sets and maps as these are probably faster
    // to (de-/)serialize
    roles: BTreeSet<String>,
    pubkeys: BTreeMap<Pubkey, PubkeyAssocData>,
}
