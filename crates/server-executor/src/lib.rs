#![forbid(unsafe_code)]

pub use async_executor::Executor;
pub use event_listener::Event;
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
