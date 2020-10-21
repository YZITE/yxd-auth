#![forbid(unsafe_code)]

use async_lock::RwLock;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroize;
use yxd_auth_core::ring::signature;

struct ServerStateInner {
    keypair_sign: signature::Ed25519KeyPair,
}

impl ServerStateInner {
    fn signing_public_key(&self) -> signature::UnparsedPublicKey<&[u8]> {
        signature::UnparsedPublicKey::new(&signature::ED25519, self.keypair_sign.public_key().as_ref())
    }
}

type ServerState = Arc<ServerStateInner>;

async fn handle_client(
    srvstate: ServerState,
    yzescfg: Arc<yz_encsess::Config>,
    stream: async_net::TcpStream,
    peer_addr: std::net::SocketAddr,
) -> Result<()> {
    use yxd_auth_core::pdus::*;

    // setup session
    let yzes = yz_encsess::Session::new(stream, yzescfg)
        .await
        .with_context(|| format!("KDC::setup_session with peer = {}", peer_addr))?;
    let s = yxd_auth_core::PacketStream::<_, Response, Request>::new(yzes);
    tracing::info!(
        "Established connection with {} and pubkey = {}",
        peer_addr,
        yxd_auth_core::base64::encode(s.remote_static_pubkey().unwrap())
    );

    let mut auth_state: Option<String> = None;

    // handle commands
    while let Some(Request { cmd, sudo }) = s.try_recv().await.map_err(|e| anyhow!("{:?}", e))? {
        match cmd {
            Command::Auth(_) if sudo.is_some() => s.send(Response::InvalidInvocation).await?,
            Command::Auth(a) => {
                match a {
                    AuthCommand::Password { username, .. } => {
                        // FIXME: check if the user password matches
                        auth_state = Some(username);
                    }
                    AuthCommand::Ticket(sigt) => {
                        // FIXME: verify the ticket signature
                        match sigt.decode_and_verify(srvstate.signing_public_key()) {
                        }
                    }
                }
                s.send(Response::Success).await?;
            }

            // FIXME: admins should have SUDO rights
            _ if sudo.is_some() => s.send(Response::PermissionDenied).await?,
            _ if auth_state.is_none() => s.send(Response::PermissionDenied).await?,
            _ => s.send(Response::InvalidInvocation).await?,
        }
    }
}

fn main() {
    use yxd_auth_kdc::ServerConfig;

    tracing_subscriber::fmt::init();

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("USAGE: yxd-auth-kdc CONFIG.toml");
        std::process::exit(1);
    }

    let cfgf = std::fs::read(&args[1]).expect("unable to read config file");
    let cfgf: ServerConfig = toml::from_slice(&cfgf[..]).expect("unable to parse config file");

    let srvstate = Arc::new(ServerStateInner {
        keypair_sign: signature::Ed25519KeyPair::from_pkcs8(cfgf.keypair_sign.as_ref()).expect("unable to parse signing keypair"),
    });

    let yzesc = Arc::new(yz_encsess::Config {
        privkey: yz_encsess::new_key(cfgf.privkey.into_inner()),
        side: yz_encsess::SideConfig::Server,
        dhc: yxd_auth_core::pdus::DHChoice::Ed25519,
    });

    yxd_auth_core::block_on(|_| async move {});
}
