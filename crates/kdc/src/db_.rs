use async_oneshot::Sender as ReturnSender;

pub struct UserInfo {
    hpw: String,
}

#[allow(non_camel_case_types)]
pub enum Message {
    get_user {
        ret: ReturnSender<Option<UserInfo>>,

        user: String,
    },
}

pub fn database_worker(dbpath: std::path::PathBuf, reqs: async_channel::Receiver<Message>) {
    use futures_lite::future::block_on;
    use rusqlite::params;

    let conn = rusqlite::Connection::open(dbpath).expect("unable to open database");

    conn.execute_batch(
        "BEGIN;
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    hpwd TEXT NOT NULL,
    can_sudo INTEGER NOT NULL
);
COMMIT;"
    ).expect("unable to create required db tables");

    while let Ok(x) = block_on(reqs.recv()) {
        match x {
            _ => {},
        }
    }
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("db connection lost")]
pub struct DbConnectionLost;

impl From<async_oneshot::Closed> for DbConnectionLost {
    fn from(_: async_oneshot::Closed) -> DbConnectionLost {
        DbConnectionLost
    }
}

impl<T> From<async_channel::SendError<T>> for DbConnectionLost {
    fn from(_: async_channel::SendError<T>) -> DbConnectionLost {
        DbConnectionLost
    }
}

macro_rules! gmdbrpc {
    ($method:ident -> $retty:ty, $($param:ident : $pty:ty),+) => {
        pub(crate) async fn $method(&self, $($param: $pty),+) -> Result<$retty, DbConnectionLost> {
            let (ret, recv) = async_oneshot::oneshot();
            let msg = Message::$method {
                ret,
                $($param,)+
            };
            self.db.send(msg).await?;
            recv.await.map_err(DbConnectionLost::from)
        }
    }
}

impl crate::ServerStateInner {
    /*
    pub(crate) async fn get_user(&self, user: String) -> Result<UserInfo, DbConnectionLost> {
        let (ret, recv) = async_oneshot::oneshot();
        let msg = Message::GetUser {
            ret,
            user,
        };
        self.db.send(msg)?;
        Ok(recv.await?)
    }
    */
    gmdbrpc!(get_user -> Option<UserInfo>, user: String);
}
