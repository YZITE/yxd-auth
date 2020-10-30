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

/// Multithreaded `block_on` function
pub fn block_on<F, I, R>(f: F) -> R
where
    F: FnOnce(&Executor<'_>) -> I,
    I: std::future::Future<Output = R>,
{
    use futures_lite::future::block_on;
    let ex = Executor::new();
    let shutdown = event_listener::Event::new();

    easy_parallel::Parallel::new()
        .each(0..num_cpus::get(), |_| block_on(ex.run(signal.listen())))
        .finish(|| {
            let ret = block_on(f(&ex));
            shutdown.notify(usize::MAX);
            ret
        })
        .1
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
