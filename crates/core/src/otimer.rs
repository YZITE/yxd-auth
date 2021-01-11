use crate::UtcDateTime;
use std::{marker::Unpin, future::Future, pin::Pin};
use std::task::{Context, Poll};

pub struct OptionalTimer<T>(Option<(UtcDateTime, async_io::Timer, T)>);

impl<T> OptionalTimer<T> {
    pub fn new() -> Self {
        Self(None)
    }

    pub fn reset(&mut self, fire_at: UtcDateTime) -> Result<Option<(UtcDateTime, T)>, ()> {
        unimplemented!()
        //std::mem::replace(&mut self.0, Some(())
    }
}

impl<T: Unpin> Future for OptionalTimer<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let this = &mut Pin::into_inner(self).0;
        match this.take() {
            Some((tstamp, mut timer, value)) => {
                match Pin::new(&mut timer).poll(cx) {
                    Poll::Pending => {
                        *this = Some((tstamp, timer, value));
                        Poll::Pending
                    }
                    Poll::Ready(_) => {
                        Poll::Ready(value)
                    }
                }
            }
            None => Poll::Pending,
        }
    }
}
