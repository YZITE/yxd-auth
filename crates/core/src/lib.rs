#![forbid(unsafe_code)]

pub type UtcDateTime = chrono::DateTime<chrono::Utc>;

mod signedobj;
pub use signedobj::SignedObject;

pub mod pdus;

mod packet_stream;
pub use packet_stream::{Error as PacketStreamError, PacketStream};

mod base64key;
pub use base64key::Base64Key;

// utilities
pub use async_executor::Executor;

/// Multithreaded `block_on` function
pub fn block_on<F, I, R>(f: F) -> R
where
    F: FnOnce(&Executor<'_>) -> I,
    I: std::future::Future<Output = R>,
{
    use futures_lite::future::block_on;
    let ex = Executor::new();
    let (signal, shutdown) = async_channel::unbounded::<()>();

    easy_parallel::Parallel::new()
        .each(0..num_cpus::get(), |_| block_on(ex.run(shutdown.recv())))
        .finish(|| {
            let ex = &ex;
            let ret = block_on(f(ex));
            std::mem::drop(signal);
            ret
        })
        .1
}
