#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use async_lock::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use yxd_auth_core::ring::signature::{self, KeyPair};
use zeroize::Zeroize;

struct ServerStateInner {
    realm: String,
    keypair_sign: signature::Ed25519KeyPair,
}

impl ServerStateInner {
    fn signing_public_key(&self) -> signature::UnparsedPublicKey<&[u8]> {
        signature::UnparsedPublicKey::new(
            &signature::ED25519,
            self.keypair_sign.public_key().as_ref(),
        )
    }
}

type ServerState = Arc<ServerStateInner>;

struct ClientData {
    srvstate: ServerState,
    auth_state: Option<String>,
    parent_ticket: Option<yxd_auth_core::pdus::Ticket>,
}

impl ClientData {
    fn handle_req(&mut self, req: yxd_auth_core::pdus::Request) -> yxd_auth_core::pdus::Response {
        use yxd_auth_core::pdus::*;
        let Request { cmd, sudo } = req;

        match cmd {
            Command::Auth(_) if sudo.is_some() => Response::InvalidInvocation,
            Command::Auth(a) => {
                self.auth_state = match a {
                    AuthCommand::Password { username, .. } => {
                        // FIXME: check if the user password matches
                        Some(username)
                    }
                    AuthCommand::Ticket(sigt) => {
                        // FIXME: verify the ticket signature
                        match sigt.decode_and_verify(&self.srvstate.signing_public_key()) {
                            Ok(ticket) => {
                                if &ticket.realm != &self.srvstate.realm {
                                    return Response::PermissionDenied;
                                }
                                let asst = Some(ticket.ident.clone());
                                self.parent_ticket = Some(ticket);
                                asst
                            }
                            Err(x) => {
                                return Response::PermissionDenied;
                            }
                        }
                    }
                };
                Response::Success
            }

            // FIXME: admins should have SUDO rights
            _ if sudo.is_some() => Response::PermissionDenied,
            _ if self.auth_state.is_none() => Response::PermissionDenied,
            _ => Response::InvalidInvocation,
        }
    }
}

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
    let mut s = yxd_auth_core::PacketStream::<_, Response, Request>::new(yzes);
    tracing::info!(
        "Established connection with {} and pubkey = {}",
        peer_addr,
        yxd_auth_core::base64::encode(s.remote_static_pubkey().unwrap())
    );

    let mut clientdat = ClientData {
        srvstate,
        auth_state: None,
        parent_ticket: None,
    };

    // handle commands
    while let Some(req) = s.try_recv().await? {
        s.send(clientdat.handle_req(req)).await?;
    }

    Ok(())
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
        realm: cfgf.realm,
        keypair_sign: signature::Ed25519KeyPair::from_pkcs8(&*cfgf.keypair_sign)
            .expect("unable to parse signing keypair"),
    });

    let yzesc = Arc::new(yz_encsess::Config {
        privkey: yz_encsess::new_key(cfgf.privkey_noise.into_inner()),
        side: yz_encsess::SideConfig::Server,
        dhc: yxd_auth_core::pdus::DHChoice::Ed25519,
    });

    yxd_auth_core::block_on(|_| async move {});
}
