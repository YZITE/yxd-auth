#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use async_lock::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use yxd_auth_core::ring::signature::{self, KeyPair};
use zeroize::Zeroize;

const DHC: yxd_auth_core::pdus::DHChoice = yxd_auth_core::pdus::DHChoice::Ed25519;

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

struct ClAuthState {
    ident: String,
    allow_expand: bool,
    parent_ticket: Option<yxd_auth_core::pdus::Ticket>,
}

struct ClientData {
    srvstate: ServerState,
    peer_addr: std::net::SocketAddr,
    peer_ip_addr: std::net::IpAddr,
    pubkey: yxd_auth_core::pdus::Pubkey,
    auth_state: Option<ClAuthState>,
}

impl ClientData {
    fn handle_req(&mut self, req: yxd_auth_core::pdus::Request) -> yxd_auth_core::pdus::Response {
        use yxd_auth_core::pdus::*;
        let Request { cmd, sudo } = req;

        match cmd {
            Command::Auth(_) if sudo.is_some() => Response::InvalidInvocation,
            Command::Auth(a) => {
                self.auth_state = Some(match a {
                    AuthCommand::Password { username, .. } => {
                        // FIXME: check if the user password matches
                        ClAuthState {
                            ident: username,
                            allow_expand: true,
                            parent_ticket: None,
                        }
                    }
                    AuthCommand::Ticket(sigt) => {
                        match sigt.decode_and_verify(&self.srvstate.signing_public_key()) {
                            Ok(ticket) => {
                                if &ticket.realm != &self.srvstate.realm {
                                    return Response::PermissionDenied;
                                }
                                let allow_expand =
                                    if let Some(pke) = ticket.pubkeys.get(&self.pubkey) {
                                        if !pke.is_allowed(&self.peer_ip_addr) {
                                            return Response::PermissionDenied;
                                        }
                                        pke.flags.contains(PubkeyFlags::A_EXPAND)
                                    } else {
                                        false
                                    };
                                ClAuthState {
                                    ident: ticket.ident.clone(),
                                    allow_expand,
                                    parent_ticket: Some(ticket),
                                }
                            }
                            Err(x) => {
                                return Response::PermissionDenied;
                            }
                        }
                    }
                });
                Response::Success
            }

            // FIXME: admins should have SUDO rights
            _ if sudo.is_some() => Response::PermissionDenied,
            _ if self.auth_state.is_none() => Response::PermissionDenied,

            Command::Acquire(acq) => {
                // FIXME: handle sudo
                let now = yxd_auth_core::Utc::now();
                let auth_state = self.auth_state.as_ref().unwrap();
                match acq.try_finish(&now, &self.srvstate.realm, if auth_state.allow_expand { None } else { auth_state.parent_ticket.as_ref() }, &auth_state.ident) {
                    Ok(x) => match yxd_auth_core::SignedObject::encode(&x, &self.srvstate.keypair_sign) {
                        Ok(x) => Response::Ticket(x),
                        Err(e) => {
                            tracing::error!("unable to create ticket: {}", e);
                            Response::Failure
                        }
                    },
                    Err(resp) => resp,
                }
            } //_ => Response::InvalidInvocation,
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
    let pubkey = s.remote_static_pubkey().unwrap();
    tracing::info!(
        "Established connection with {} and pubkey = {}",
        peer_addr,
        yxd_auth_core::base64::encode(pubkey)
    );

    let peer_ip_addr = peer_addr.ip();

    let mut clientdat = ClientData {
        srvstate,
        peer_addr,
        peer_ip_addr,
        pubkey: Pubkey {
            dh: DHC.clone(),
            value: pubkey.to_vec(),
        },
        auth_state: None,
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
        dhc: DHC.clone(),
    });

    yxd_auth_core::block_on(|_| async move {});
}
