use futures_codec::{CborCodec, Framed};
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::sink::SinkExt;
use futures_util::stream::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use std::{future::Future, marker::Unpin};

pub struct PacketStream<S, Req, Resp>(Framed<S, CborCodec<Req, Resp>>);
pub type Error = futures_codec::CborCodecError;
pub type Result<T> = ::std::result::Result<T, Error>;

impl<S, Req, Resp> PacketStream<S, Req, Resp>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Req: Serialize + 'static,
    Resp: for<'de> Deserialize<'de> + 'static,
{
    #[inline(always)]
    pub fn new(inner: S) -> Self {
        Self(Framed::new(inner, CborCodec::new()))
    }

    #[inline(always)]
    pub fn flush(&mut self) -> impl Future<Output = Result<()>> + '_ {
        self.0.flush()
    }

    #[inline(always)]
    pub fn send(&mut self, msg: Req) -> impl Future<Output = Result<()>> + '_ {
        self.0.send(msg)
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
        &mut *self.0
    }
}
