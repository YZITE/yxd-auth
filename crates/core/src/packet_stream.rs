use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::stream::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use std::{future::Future, marker::Unpin, pin::Pin};
use yz_futures_codec::{codec::Cbor, Framed};
use yz_futures_util::sink::SinkExt;

pub struct PacketStream<S, Req, Resp>(Framed<S, Cbor<Req, Resp>>);
pub type Error = yz_futures_codec::Error<serde_cbor::Error>;
pub type Result<T> = ::std::result::Result<T, Error>;

impl<S, Req, Resp> PacketStream<S, Req, Resp>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Req: Serialize + 'static,
    Resp: for<'de> Deserialize<'de> + 'static,
{
    #[inline(always)]
    pub fn new(inner: S) -> Self {
        Self(Framed::new(inner, Cbor::new()))
    }

    #[inline]
    pub fn flush(&mut self) -> impl Future<Output = Result<()>> + '_ {
        let inner = &mut self.0;
        futures_micro::poll_fn(move |cx| {
            yz_futures_util::sink::FlushSink::poll_flush(Pin::new(inner), cx)
        })
    }

    #[inline(always)]
    pub fn send<'a>(&'a mut self, msg: &'a Req) -> impl Future<Output = Result<()>> + 'a {
        self.0.send_unpin(&msg)
    }

    #[inline(always)]
    pub fn recv(&mut self) -> impl Future<Output = Option<Result<Resp>>> + '_ {
        self.0.next()
    }

    #[inline(always)]
    pub fn try_recv(&mut self) -> impl Future<Output = Result<Option<Resp>>> + '_ {
        self.0.try_next()
    }
}

impl<S, Req, Resp> std::ops::Deref for PacketStream<S, Req, Resp>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Target = S;

    #[inline(always)]
    fn deref(&self) -> &S {
        &*self.0
    }
}

impl<S, Req, Resp> std::ops::DerefMut for PacketStream<S, Req, Resp>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut S {
        self.0.inner_mut()
    }
}
