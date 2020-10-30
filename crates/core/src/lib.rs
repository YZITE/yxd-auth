#![forbid(unsafe_code)]

pub type UtcDateTime = chrono::DateTime<chrono::Utc>;
pub use chrono::Utc;

pub mod error;

mod signedobj;
pub use signedobj::{Error as SignObjError, Signable, SignedObject};

pub mod pdus;

mod packet_stream;
pub use packet_stream::{Error as PacketStreamError, PacketStream};

mod base64key;
pub use base64key::Base64Key;

// utilities
pub use async_executor::Executor;
pub use base64;
pub use chrono;
pub use ring;
use event_listener::Event;
use std::sync::Arc;

pub struct ServerExecutor {
    // the user shouldn't be able to clone the current object.
    ex: Arc<Executor<'static>>,

    shutdown: Event,
}

impl ServerExecutor {
    pub fn new() -> Self {
        let ret = Self {
            ex: Arc::new(Executor::new()),
            shutdown: Event::new(),
        };

        use futures_lite::future::block_on as fblon;
        use std::thread::spawn;
        for _ in 0..num_cpus::get() {
            let ex = ret.ex.clone();
            let listener = ret.shutdown.listen();
            spawn(move || fblon(ex.run(listener)));
        }

        ret
    }

    /// Multithreaded `block_on` function
    #[inline]
    pub fn block_on<'x, F, I, R>(&'x mut self, f: F) -> R
    where
        F: FnOnce(&'x Executor<'static>) -> I,
        I: std::future::Future<Output = R> + 'x,
        R: 'x,
    {
        futures_lite::future::block_on(f(&*self.ex))
    }
}

impl Drop for ServerExecutor {
    fn drop(&mut self) {
        // we don't rely on the fact that this destructor runs,
        // as it only cleans up leftover resources
        // if this doesn't run, we thus just waste some resources
        self.shutdown.notify(usize::MAX);
    }
}

pub fn prefix_match(a: &[u8], b: &[u8], prefixlen: u8) -> bool {
    let (pfl_bs, pfl_subbs) = (usize::from(prefixlen / 8), prefixlen % 8);
    let rminlen = std::cmp::min(a.len(), b.len());
    if (rminlen < pfl_bs) || (&a[..pfl_bs] != &b[..pfl_bs]) {
        false
    } else if pfl_subbs == 0 {
        true
    } else if rminlen < (pfl_bs + 1) {
        false
    } else {
        let mask = 255u8.wrapping_shl(pfl_subbs.into());
        (a[pfl_bs] & mask) == (b[pfl_bs] & mask)
    }
}
