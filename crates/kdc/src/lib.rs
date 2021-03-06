#![forbid(unsafe_code)]

// This library allows sharing of code between a keygen program
// and the main server.

use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};
use yxd_auth_core::Base64Key;

#[derive(Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub realm: String,
    pub listen: SocketAddr,
    pub dbpath: PathBuf,
    pub privkey_noise: Base64Key,
    pub keypair_sign: Base64Key,
}
