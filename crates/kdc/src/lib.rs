#![forbid(unsafe_code)]

// This library allows sharing of code between a keygen program
// and the main server.

use std::{net::SocketAddr, path::PathBuf};
use serde::{Deserialize, Serialize};
use yxd_auth_core::Base64Key;

#[derive(Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub dbpath: PathBuf,
    pub privkey_noise: Base64Key,
    pub keypair_sign: Base64Key,
}
