use crate::ticket;
use crate::UtcDateTime;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Deserialize, Serialize)]
pub enum AuthCommand {
    Password { username: String, password: String },

    Ticket(ticket::Ticket),
}

#[derive(Clone, Deserialize, Serialize)]
pub enum Command {
    Auth(AuthCommand),

    Acquire {
        /// validitiy check interval
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ivd_valid_chk: Option<Duration>,

        // lifetimes
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ts_lt_after: Option<UtcDateTime>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        ts_lt_until: Option<UtcDateTime>,

        /// the T3P MAY restrict the lifetime to a maximum
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ts_lt_for: Option<Duration>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        ts_lt_renew_until: Option<UtcDateTime>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        ts_lt_renew_for: Option<UtcDateTime>,

        // ident & name are taken from the authentification data
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tid: Option<u64>,

        roles: ticket::Roles,

        /// the T3P MAY disallow issuing tickets without specified
        /// associated pubkeys
        pubkeys: ticket::PubkeyMap,
    },

    /// the T3P won't accept revocations without lifetime limits
    Revoke {
        id: u64,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        ts_lt_until: Option<UtcDateTime>,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        ts_lt_for: Option<Duration>,
    },

    Renew(ticket::Ticket),
}
