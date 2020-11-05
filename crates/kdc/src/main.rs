#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use async_lock::RwLock;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf, sync::Arc, future::Future};
use yxd_auth_core::pdus;
use yxd_auth_core::ring::signature::{self, KeyPair};
use zeroize::{Zeroize, Zeroizing};

const DHC: pdus::DHChoice = pdus::DHChoice::Ed25519;

mod db_;

struct ServerStateInner {
    realm: String,
    keypair_sign: signature::Ed25519KeyPair,
    db: async_channel::Sender<db_::Message>,
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
    uid: i64,
    flags: pdus::PubkeyFlags,
    parent_ticket: Option<pdus::Ticket>,
}

struct ClientData {
    srvstate: ServerState,
    peer_addr: std::net::SocketAddr,
    pubkey: pdus::Pubkey,
    auth_state: Option<ClAuthState>,

    // FIXME: attack vector: attacker could hold connection for a very long time
    // TODO: implement max TTL with timestamp
    uid_cache: HashMap<String, (Option<i64>, u8)>,
}

#[derive(PartialEq)]
enum AllowAll {
    Yes,
    No,
}

impl ClientData {
    async fn get_user_intern(srvstate: &ServerStateInner, uid_cache: &mut HashMap<String, (Option<i64>, u8)>, username: &str) -> Option<i64> {
        use std::collections::hash_map::Entry;
        let mut do_clup = false;
        let ret = match uid_cache.entry(username.to_string()) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => {
                do_clup = true;
                v.insert((srvstate.get_user(username.to_string()).await.unwrap_or(None), 20))
            },
        }.0;
        if do_clup {
            // do cleanup...
            uid_cache.retain(|_, v| {
                if v.1 > 0 {
                    v.1 -= 1;
                }
                v.1 == 0
            });
        }
        ret
    }

    fn get_user<'a>(&'a mut self, username: &'a str) -> impl Future<Output = Option<i64>> + 'a {
        Self::get_user_intern(&self.srvstate, &mut self.uid_cache, username)
    }

    async fn handle_sudo(&mut self, sudoer: &str) -> bool {
        if let Some(ref user) = self.auth_state {
            if sudoer == &user.ident {
                return true;
            }
            match Self::get_user_intern(&self.srvstate, &mut self.uid_cache, sudoer).await {
                Some(sudo_as) => self.srvstate.check_sudo_as(user.uid, sudo_as).await.unwrap_or(false),
                None => false,
            }
        } else {
            false
        }
    }

    async fn check_ticket(
        &mut self,
        now: &yxd_auth_core::UtcDateTime,
        sigt: &yxd_auth_core::SignedObject<pdus::Ticket>,
        allow_all: AllowAll,
    ) -> ::std::result::Result<(pdus::Ticket, pdus::PubkeyFlags), ()> {
        match sigt.decode_and_verify(&self.srvstate.signing_public_key()) {
            Ok(mut ticket) => {
                if ticket.realm != self.srvstate.realm {
                    tracing::warn!(
                        "client passed ticket with invalid realm ('{}')",
                        &ticket.realm
                    );
                    return Err(());
                }
                if !(allow_all == AllowAll::Yes || self.handle_sudo(&ticket.ident).await) {
                    tracing::warn!(
                        "client passed ticket with invalid ident ('{:?}', realm = '{}')",
                        &ticket.ident,
                        &ticket.realm
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

    async fn handle_req(
        &mut self,
        req: pdus::Request,
    ) -> Result<pdus::Response, db_::DbConnectionLost> {
        use pdus::*;
        let now = yxd_auth_core::Utc::now();

        macro_rules! ifail {
            () => {
                return Ok(Response::Failure);
            };
        };

        Ok(match req {
            Request::Auth(a) => {
                self.auth_state = Some(match &a {
                    AuthCommand::Password {
                        ref username,
                        ref password,
                    } => {
                        if let Some(uid) = self.get_user(username).await {
                            if self
                                .srvstate
                                .check_user_login(uid, password.clone().into())
                                .await?
                            {
                                ClAuthState {
                                    ident: username.clone(),
                                    uid,
                                    flags: PubkeyFlags::all(),
                                    parent_ticket: None,
                                }
                            } else {
                                ifail!();
                            }
                        } else {
                            ifail!();
                        }
                    }
                    AuthCommand::Ticket(ref sigt) => {
                        let now = yxd_auth_core::Utc::now();
                        match self.check_ticket(&now, sigt, AllowAll::Yes).await {
                            Ok((ticket, flags)) => {
                                if let Some(uid) =
                                    self.get_user(&ticket.ident).await
                                {
                                    ClAuthState {
                                        ident: ticket.ident.clone(),
                                        uid,
                                        flags,
                                        parent_ticket: Some(ticket),
                                    }
                                } else {
                                    ifail!();
                                }
                            }
                            Err(()) => ifail!(),
                        }
                    }
                });
                Response::Success
            }

            _ if self.auth_state.is_none() => Response::Failure,

            Request::Acquire(acq) => {
                if let Some(ref x) = &acq.ident {
                    if !self.handle_sudo(&*x).await {
                        ifail!();
                    }
                }
                let auth_state = self.auth_state.as_ref().unwrap();
                if !auth_state.flags.contains(PubkeyFlags::A_DERIVE) {
                    ifail!();
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
                // FIXME: implement revocation via database
                // FIXME: admins should have SUDO rights; handle sudo
                Response::Unimplemented
            }

            Request::Renew(sigt) => {
                match self.check_ticket(&now, &sigt, AllowAll::No).await {
                    Err(()) => Response::Failure,
                    Ok((ticket, _)) if !ticket.is_renewable(&now) => Response::Failure,

                    Ok((mut ticket, _)) => {
                        let incr = if let Some(ivd) = ticket.ivd_valid_chk {
                            match yxd_auth_core::chrono::Duration::from_std(ivd) {
                                Ok(x) => x,
                                Err(e) => {
                                    tracing::warn!("client tried to renew ticket with invalid ivd_valid_chk duration: {}", e);
                                    return Ok(Response::InvalidInvocation);
                                }
                            }
                        // FIXME: we should use the mean value of ivd and the default value
                        } else {
                            // FIXME: use a default value
                            return Ok(Response::Unimplemented);
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
        })
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
        uid_cache: HashMap::with_capacity(21),
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
            s.send(
                &clientdat
                    .handle_req(req)
                    .await
                    .unwrap_or(pdus::Response::Failure),
            )
            .await?;
        }
    }

    Ok(())
}

fn main() {
    use futures_util::{future::FutureExt, pin_mut};

    tracing_subscriber::fmt::init();
    sodiumoxide::init().unwrap();

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("USAGE: yxd-auth-kdc CONFIG.toml");
        std::process::exit(1);
    }

    let cfgf = std::fs::read(&args[1]).expect("unable to read config file");
    let cfgf: yxd_auth_kdc::ServerConfig =
        toml::from_slice(&cfgf[..]).expect("unable to parse config file");

    let (db, dbchan_r) = async_channel::bounded(100);

    let dbpath = cfgf.dbpath;
    let dbthread = std::thread::Builder::new()
        .name("database".to_string())
        .spawn(move || crate::db_::database_worker(dbpath, dbchan_r))
        .expect("unable to start database worker");

    let srvstate = Arc::new(ServerStateInner {
        db,
        realm: cfgf.realm,
        keypair_sign: signature::Ed25519KeyPair::from_pkcs8(&*cfgf.keypair_sign)
            .expect("unable to parse signing keypair"),
    });

    let yzesc = Arc::new(yz_encsess::Config {
        privkey: yz_encsess::new_key(cfgf.privkey_noise.into_inner()),
        side: yz_encsess::SideConfig::Server,
        dhc: DHC.clone(),
    });

    let s = event_listener::Event::new();
    let ctrl_c = s.listen().fuse();
    ctrlc::set_handler(move || s.notify(usize::MAX)).unwrap();

    let listen_addr = cfgf.listen.to_string();

    yxd_server_executor::ServerExecutor::new().block_on(|ex| async move {
        let listener = async_net::TcpListener::bind(listen_addr)
            .await
            .expect("unable to listen on port");

        pin_mut!(ctrl_c);

        loop {
            let fut_accept = listener.accept().fuse();
            pin_mut!(fut_accept);
            futures_util::select! {
                x = ctrl_c => break,
                y = fut_accept => {
                    let (stream, peer_addr) = y.expect("accept failed");
                    ex.spawn(handle_client(srvstate.clone(), yzesc.clone(), stream, peer_addr)).detach();
                }
            };
        }

        std::mem::drop(srvstate);
    });

    dbthread.join().unwrap();
}
