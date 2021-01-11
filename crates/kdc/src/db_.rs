use yxd_auth_core::val64::{u2i as v64u2i, i2u as v64i2u};
use yxd_auth_core::OptionalTimer;
use zeroize::{Zeroize, Zeroizing};
use futures_lite::future::block_on;
use std::future::Future;
use std::task::{Context, Poll};

#[derive(Clone, Debug, thiserror::Error)]
#[error("db connection lost")]
pub struct DbConnectionLost;

macro_rules! dbrpc {
    ($($method:ident($($param:ident : $pty:ty),+) -> $retty:ty ;)+) => {
        #[allow(non_camel_case_types)]
        pub enum Message {
            $(
                $method {
                    ret: async_oneshot::Sender<$retty>,
                    $($param: $pty,)+
                },
            )+
        }

        impl crate::ServerStateInner {
        $(
            pub(crate) async fn $method(&self, $($param: $pty),+) -> Result<$retty, DbConnectionLost> {
                let (ret, recv) = async_oneshot::oneshot();
                let msg = Message::$method {
                    ret,
                    $($param,)+
                };
                self.db.send(msg).await.map_err(|_| DbConnectionLost)?;
                recv.await.map_err(|_| DbConnectionLost)
            }
        )+
        }
    }
}

// FIXME: add a way to create users
// FIXME: add a way to delete users
// FIXME: add a way to add sudoers
// FIXME: add a way to remove sudoers

// TODO: handle invalidation of UIDs

dbrpc! {
    get_user(user: String) -> Option<i64>;
    check_user_login(uid: i64, password: Zeroizing<Vec<u8>>) -> bool;
    check_sudo_as(uid: i64, sudo_as: i64) -> bool;

    create_revocable(owner_uid: i64, tid: u64, until: yxd_auth_core::UtcDateTime) -> bool;
    mark_as_revoked(owner_uid: i64, tid: u64) -> bool;
    check_is_revoked(owner_uid: i64, tid: u64) -> bool;
}

macro_rules! sendret {
    ($ret:ident, $value:expr) => {{
        drop($ret.send($value));
        return;
    }};
}

fn handle_dbreq(conn: &rusqlite::Connection, req: Message, timer: &mut OptionalTimer<i64>) {
    use rusqlite::{params, OptionalExtension, NO_PARAMS};
    use sodiumoxide::crypto::pwhash::argon2id13 as pwhash;
    use Message as M;

    match req {
        M::get_user { ret, user } => {
            let uid = conn
                .query_row(
                    "SELECT uid FROM users WHERE name = ?",
                    &[&user[..]],
                    |row| -> Result<i64, _> { row.get(0) },
                )
                .optional()
                .expect("SELECT uid failed");
            sendret!(ret, uid);
        }
        M::check_user_login { ret, uid, password } => {
            let mut stmt = conn
                .prepare_cached("SELECT hpwd FROM passwords WHERE uid = ?")
                .expect("SELECT hpwd prepare failed");

            let rows = stmt
                .query_map(&[uid], |row| row.get(0))
                .expect("SELECT hpwd query failed");
            let mut pw_matches = false;

            for i in rows {
                let i: Vec<u8> = i.expect("SELECT hpwd row transform failed");
                let mut hpw: Zeroizing<Vec<u8>> = i.into();

                // add padding
                let origlen = hpw.len();
                hpw.extend((origlen..128).map(|_| 0u8));

                // verify hash
                if let Some(hp) = pwhash::HashedPassword::from_slice(&hpw[..]) {
                    if pwhash::pwhash_verify(&hp, &password[..]) {
                        pw_matches = true;
                        break;
                    }
                }
            }

            sendret!(ret, pw_matches);
        }
        M::check_sudo_as { ret, uid, sudo_as } => {
            let row = conn
                .prepare_cached("SELECT id FROM sudoers WHERE primid = ? AND (sudo_as IS NULL OR sudo_as = ?) LIMIT 1")
                .expect("SELECT FROM sudoers: prepare failed")
                .query_map(&[uid, sudo_as], |_| Ok(true))
                .expect("SELECT FROM sudoers: query failed")
                .next();
            sendret!(ret, row.is_some());
        }

        M::create_revocable { ret, owner_uid, tid, until } => {
            let row = conn
                .prepare_cached("INSERT INTO trevocabl (tid, owner_uid, until) VALUES (?, ?, ?)")
                .expect("INSERT INTO trevocabl: prepare failed")
                .execute(&[x64u2i(tid), owner_uid, until.timestamp()]);
            sendret!(ret, row.is_ok());
        }
        M::mark_as_revoked { ret, owner_uid, tid } => {
            let row = conn
                .prepare_cached("UPDATE trevocabl SET revoked = 1 WHERE tid = ? AND owner_uid = ?")
                .expect("UPDATE trevocabl: prepare failed")
                .execute(&[x64u2i(tid), owner_uid]);
            sendret!(ret, row == Ok(1));
        }
        M::check_is_revoked { ret, owner_uid, tid } => {
            let row = conn
                .prepare_cached("SELECT revoked FROM trevocabl WHERE tid = ? AND owner_uid = ? LIMIT 1")
                .expect("SELECT FROM trevocabl: prepare failed")
                .query_map(&[x64u2i(tid), owner_uid], |revoked| row.get(0))
                .expect("SELECT FROM trevocabl: query failed")
                .next();
            sendret!(ret, row == Some(true));
        }
    }
}

pub fn database_worker(dbpath: std::path::PathBuf, reqs: async_channel::Receiver<Message>) {
    let conn = rusqlite::Connection::open(dbpath).expect("unable to open database");

    conn.execute_batch(
        "BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS users (
    uid INTEGER PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS passwords (
    pwid INTEGER PRIMARY KEY NOT NULL,
    uid INTEGER NOT NULL,
    hpwd TEXT NOT NULL,
    FOREIGN KEY (uid) REFERENCES users (uid)
        ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS sudoers (
    id INTEGER PRIMARY KEY NOT NULL,
    primuid INTEGER NOT NULL,
    sudo_as INTEGER NULL,

    FOREIGN KEY (primuid) REFERENCES users (uid)
        ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (sudo_as) REFERENCES users (uid)
        ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS trevocabl (
    tid INTEGER PRIMARY KEY NOT NULL,
    owner_uid INTEGER NOT NULL,
    until INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,

    FOREIGN KEY (owner_uid) REFERENCES users (uid)
        ON DELETE CASCADE ON UPDATE CASCADE,
);
COMMIT;",
    )
    .expect("unable to create required db tables");

    //conn.execute("PRAGMA foreign_keys=on;", rusqlite::NO_PARAMS)
    //    .expect("unable to enable constraint checking");

    let mut timer = OptionalTimer::<i64>(None);

    loop {
        use futures_util::{future::FutureExt, pin_mut};

        let tfut = (&mut timer).fuse();
        pin_mut!(tfut);
        let rfut = reqs.recv().fuse();
        pin_mut!(rfut);

        block_on(futures_util::select! {
            tm = tfut => {
                if let Err(x) = conn.execute("DELETE FROM trevocabl WHERE tid = ?", &[tm]) {
                    tracing::error!("unable to remove revoked tid {}: {}", tm, x);
                }
            },
            rq = rfut => {
                if let Ok(x) = rq {
                    handle_dbreq(&conn, x);
                } else {
                    break;
                }
            },
        });
    }
}
