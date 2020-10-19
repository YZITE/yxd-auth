use crate::UtcDateTime;
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use yz_glue_dhchoice::DHChoice;

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
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pins: BTreeSet<PubkeyAllowedPin>,

    flags: PubkeyFlags,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(tag = "type")]
pub struct Pubkey {
    dh: DHChoice,
    value: Vec<u8>,
}

// we use b-tree sets and maps as these are probably faster
// to (de-/)serialize
pub type Roles = BTreeSet<String>;
pub type PubkeyMap = BTreeMap<Pubkey, PubkeyAssocData>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ticket {
    creation_time: UtcDateTime,

    // validity check
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ts_last_valid_chk: Option<UtcDateTime>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    ivd_valid_chk: Option<Duration>,

    // lifetime
    ts_lt_after: UtcDateTime,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    ts_lt_until: Option<UtcDateTime>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    ts_lt_renew_until: Option<UtcDateTime>,

    // ID
    ident: String,
    realm: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    tid: Option<u64>,

    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    roles: BTreeSet<String>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pubkeys: PubkeyMap,
}
