#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroize;

#[derive(Clone, Deserialize, Serialize, Zeroize)]
struct ServerConfig {
    listen: String,
    privkey: yxd_auth_core::Base64Key,
}

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("USAGE: yxd-auth-kdc CONFIG.toml");
        std::process::exit(1);
    }

    let cfgf = std::fs::read(&args[1]).expect("unable to read config file");
    let cfgf: ServerConfig = toml::from_slice(&cfgf[..]).expect("unable to parse config file");

    let yzesc = Arc::new(yz_encsess::Config {
        privkey: yz_encsess::new_key(cfgf.privkey.into_inner()),
        side: yz_encsess::SideConfig::Server,
        dhc: yxd_auth_core::pdus::DHChoice::Ed25519,
    });

    yxd_auth_core::block_on(|_| async move {});
}
