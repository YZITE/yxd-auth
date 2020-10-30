#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use async_lock::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use yxd_auth_core::pdus;
use yxd_auth_core::ring::signature::{self, KeyPair};
use zeroize::Zeroize;

const DHC: pdus::DHChoice = pdus::DHChoice::Ed25519;

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
    flags: pdus::PubkeyFlags,
    parent_ticket: Option<pdus::Ticket>,
}

struct ClientData {
    srvstate: ServerState,
    peer_addr: std::net::SocketAddr,
    pubkey: pdus::Pubkey,
    auth_state: Option<ClAuthState>,
}

impl ClientData {
    fn check_ticket<Fid>(
        &self,
        now: &yxd_auth_core::UtcDateTime,
        sigt: yxd_auth_core::SignedObject<pdus::Ticket>,
        identchk: Fid,
    ) -> ::std::result::Result<(pdus::Ticket, pdus::PubkeyFlags), ()>
    where
        Fid: FnOnce(&str) -> bool,
    {
        match sigt.decode_and_verify(&self.srvstate.signing_public_key()) {
            Ok(mut ticket) => {
                if &ticket.realm != &self.srvstate.realm || !identchk(&ticket.ident) {
                    tracing::warn!(
                        "client passed ticket with invalid realm ('{}') or ident ('{:?}')",
                        &ticket.realm,
                        &ticket.ident
                    );
                    return Err(());
                }
                if !ticket.is_valid(now) {
                    tracing::warn!("client tried to use invalid or expired ticket");
                    return Err(());
                }
                let pkf = if let Some(pke) = ticket.pubkeys.get(&self.pubkey) {
                    if !pke.is_allowed(&self.peer_addr.ip()) {
                        tracing::warn!(
                            "client tried to use ticket from non-allowed IP {}",
                            &self.peer_addr
                        );
                        return Err(());
                    }
                    pke.flags
                } else {
                    pdus::PubkeyFlags::empty()
                };
                ticket.ts_last_valid_chk = Some(now.clone());
                Ok((ticket, pkf))
            }
            Err(x) => {
                tracing::warn!("unable to decode+verify ticket: {}", x);
                Err(())
            }
        }
    }

    fn sign_ticket(&self, ticket: pdus::Ticket) -> pdus::Response {
        match yxd_auth_core::SignedObject::encode(&ticket, &self.srvstate.keypair_sign) {
            Ok(x) => pdus::Response::Ticket(x),
            Err(e) => {
                tracing::error!("unable to sign ticket: {}", e);
                pdus::Response::Failure
            }
        }
    }

    fn handle_req(&mut self, req: pdus::Request) -> pdus::Response {
        use pdus::*;
        let now = yxd_auth_core::Utc::now();

        match req {
            Request::Auth(a) => {
                self.auth_state = Some(match a {
                    AuthCommand::Password { username, .. } => {
                        // FIXME: check if the user password matches
                        ClAuthState {
                            ident: username,
                            flags: PubkeyFlags::all(),
                            parent_ticket: None,
                        }
                    }
                    AuthCommand::Ticket(sigt) => {
                        let now = yxd_auth_core::Utc::now();
                        match self.check_ticket(&now, sigt, |_| true) {
                            Ok((ticket, flags)) => ClAuthState {
                                ident: ticket.ident.clone(),
                                flags,
                                parent_ticket: Some(ticket),
                            },
                            Err(()) => return Response::PermissionDenied,
                        }
                    }
                });
                Response::Success
            }

            _ if self.auth_state.is_none() => Response::PermissionDenied,

            Request::Acquire(acq) => {
                // FIXME: admins should have SUDO rights; handle sudo
                let auth_state = self.auth_state.as_ref().unwrap();
                if !auth_state.flags.contains(PubkeyFlags::A_DERIVE) {
                    return Response::PermissionDenied;
                }
                match acq.try_finish(
                    &now,
                    &self.srvstate.realm,
                    if auth_state.flags.contains(PubkeyFlags::A_EXPAND) {
                        None
                    } else {
                        auth_state.parent_ticket.as_ref()
                    },
                    &auth_state.ident,
                ) {
                    Ok(x) => self.sign_ticket(x),
                    Err(resp) => resp,
                }
            }

            Request::Revoke { .. } => {
                // FIXME: implement revocation (requires database access)
                // FIXME: admins should have SUDO rights; handle sudo
                Response::Unimplemented
            }

            Request::Renew(sigt) => {
                let auth_state = self.auth_state.as_ref().unwrap();
                // FIXME: admins should have SUDO rights; handle sudo (sudo suppresses the ident check)
                match self.check_ticket(&now, sigt, |id| id == &auth_state.ident) {
                    Err(()) => Response::PermissionDenied,
                    Ok((ticket, _)) if !ticket.is_renewable(&now) => Response::Failure,

                    Ok((mut ticket, _)) => {
                        let incr = if let Some(ivd) = ticket.ivd_valid_chk {
                            match yxd_auth_core::chrono::Duration::from_std(ivd) {
                                Ok(x) => x,
                                Err(e) => {
                                    tracing::warn!("client tried to renew ticket with invalid ivd_valid_chk duration: {}", e);
                                    return Response::InvalidInvocation;
                                }
                            }
                        // FIXME: we should use the mean value of ivd and the default value
                        } else {
                            // FIXME: use a default value
                            return Response::Unimplemented;
                        };
                        let ts_lt_renew_until = ticket
                            .ts_lt_renew_until
                            .clone()
                            .unwrap()
                            .checked_add_signed(incr);
                        let ts_lt_until =
                            ticket.ts_lt_until.clone().unwrap().checked_add_signed(incr);
                        if ts_lt_renew_until.is_none() || ts_lt_until.is_none() {
                            Response::Failure
                        } else {
                            ticket.ts_lt_renew_until = ts_lt_renew_until;
                            ticket.ts_lt_until = ts_lt_until;
                            self.sign_ticket(ticket)
                        }
                    }
                }
            }
        }
    }
}

async fn handle_client(
    srvstate: ServerState,
    yzescfg: Arc<yz_encsess::Config>,
    stream: async_net::TcpStream,
    peer_addr: std::net::SocketAddr,
) -> Result<()> {
    use pdus::*;

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

    let mut clientdat = ClientData {
        srvstate,
        peer_addr,
        pubkey: Pubkey {
            dh: DHC.clone(),
            value: pubkey.to_vec(),
        },
        auth_state: None,
    };

    // handle commands
    {
        let span = tracing::span!(
            tracing::Level::INFO,
            "handle_client",
            "{}",
            &clientdat.peer_addr
        );
        let _enter = span.enter();
        while let Some(req) = s.try_recv().await? {
            s.send(clientdat.handle_req(req)).await?;
        }
    }

    Ok(())
}

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("USAGE: yxd-auth-kdc CONFIG.toml");
        std::process::exit(1);
    }

    let cfgf = std::fs::read(&args[1]).expect("unable to read config file");
    let cfgf: yxd_auth_kdc::ServerConfig = toml::from_slice(&cfgf[..]).expect("unable to parse config file");

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

    let (s, ctrl_c) = async_channel::bounded(2);
    ctrlc::set_handler(move || {
        let _ = s.try_send(());
    })
    .unwrap();

    yxd_auth_core::block_on(|_| async move {
        use futures_util::{future::FutureExt, stream::StreamExt};

        let listener = async_net::TcpListener::bind(cfgf.listen.to_string())
            .await
            .expect("unable to listen on port");

        pin_mut(ctrl_c);
    });
}
