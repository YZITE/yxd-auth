#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroize;

async fn setup_session(
    scfg: Arc<yz_encsess::Config>,
    stream: async_net::TcpStream,
    peer_addr: std::net::SocketAddr,
) -> Result<
    yxd_auth_core::PacketStream<
        yz_encsess::Session,
        yxd_auth_core::pdus::Response,
        yxd_auth_core::pdus::Request,
    >,
> {
    let yzes = yz_encsess::Session::new(stream, scfg)
        .await
        .with_context(|| format!("KDC::setup_session with peer = {}", peer_addr))?;
    let pkts = yxd_auth_core::PacketStream::new(yzes);
    tracing::info!(
        "Established connection with {} and pubkey = {} ",
        peer_addr,
        yxd_auth_core::base64::encode(pkts.remote_static_pubkey().unwrap())
    );
    Ok(pkts)
}

fn main() {
    #[derive(Clone, Deserialize, Serialize, Zeroize)]
    struct ServerConfig {
        listen: String,
        privkey: yxd_auth_core::Base64Key,
    };

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
