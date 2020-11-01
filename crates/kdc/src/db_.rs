use zeroize::Zeroize;

#[derive(Clone, Debug, thiserror::Error)]
#[error("db connection lost")]
pub struct DbConnectionLost;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct UserInfo {
    pub hpwd: String,
    pub can_sudo: bool,
}

// FIXME: add a way to create users
// FIXME: add a way to delete users

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

dbrpc! {
    get_user(user: String) -> Option<UserInfo>;
}

pub fn database_worker(dbpath: std::path::PathBuf, reqs: async_channel::Receiver<Message>) {
    use futures_lite::future::block_on;
    use rusqlite::{params, OptionalExtension};

    let conn = rusqlite::Connection::open(dbpath).expect("unable to open database");

    // FIXME: add a sudoers table ($owner -> $sudo_as)
    conn.execute_batch(
        "BEGIN;
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    hpwd TEXT NOT NULL,
    can_sudo INTEGER NOT NULL
);
COMMIT;",
    )
    .expect("unable to create required db tables");

    while let Ok(x) = block_on(reqs.recv()) {
        match x {
            Message::get_user { ret, user } => {
                // do never fail if the consumer is gone
                drop(
                    ret.send(
                        conn.query_row(
                            "SELECT hpwd, can_sudo FROM users WHERE name = ?",
                            &[&user[..]],
                            |row| {
                                Ok(UserInfo {
                                    hpwd: row.get(0)?,
                                    can_sudo: row.get(1)?,
                                })
                            },
                        )
                        .optional()
                        .expect("get_user query failed"),
                    ),
                );
            }
        }
    }
}

