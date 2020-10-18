use serde::{Deserialize, Serialize};
use crate::ticket;

#[derive(Deserialize, Serialize)]
pub enum AuthCommand {
    Password {
        username: String,
        password: String,
    },

    Ticket(ticket::Ticket),
}

pub enum Command {
    Auth(AuthCommand),

    AcquireTicket {
        pubkeys: ticket::PubkeyMap,
    },
}

