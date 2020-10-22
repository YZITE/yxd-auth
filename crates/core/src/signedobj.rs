use crate::pdus::SignatureAlgo;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use zeroize::Zeroize;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignedObject<T> {
    obj: Vec<u8>,
    signature: Vec<u8>,

    #[serde(skip)]
    _ph: PhantomData<T>,
}

impl<T> Zeroize for SignedObject<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.obj.zeroize();
        self.signature.zeroize();
    }
}

impl<T> Drop for SignedObject<T> {
    #[inline]
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub trait Signable: Serialize {
    type PrivateContext;
    type Error: std::fmt::Debug + std::error::Error;

    fn sign(obj: &[u8], decoded: &Self, ctx: &Self::PrivateContext)
        -> Result<Vec<u8>, Self::Error>;
}

pub trait Verifyable<'pk>: for<'de> Deserialize<'de> + Signable {
    type PublicContext: 'pk;

    fn verify(
        obj: &[u8],
        decoded: &Self,
        signature: &[u8],
        ctx: &Self::PublicContext,
    ) -> Result<(), <Self as Signable>::Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum Error<T: std::fmt::Debug + std::error::Error + 'static> {
    #[error("(de-) serialization error: {0}")]
    Serde(#[from] serde_cbor::error::Error),
    #[error(transparent)]
    Custom(T),
}

impl<T: Signable> SignedObject<T> {
    pub fn encode(obj: &T, ctx: &T::PrivateContext) -> Result<Self, Error<T::Error>> {
        // 1. serialize object
        let objenc = serde_cbor::to_vec(obj)?;
        // 2. create signature
        let signature = T::sign(&objenc[..], obj, ctx).map_err(Error::Custom)?;
        // 3. finish
        Ok(Self {
            obj: objenc,
            signature,
            _ph: PhantomData,
        })
    }

    pub fn decode_and_verify<'kp>(&self, ctx: &T::PublicContext) -> Result<T, Error<T::Error>>
    where
        T: Verifyable<'kp>,
    {
        let decoded = serde_cbor::from_slice(&self.obj[..])?;
        T::verify(&self.obj[..], &decoded, &self.signature[..], ctx).map_err(Error::Custom)?;
        Ok(decoded)
    }
}

use crate::error::UnspecifiedSignatureError as UnspecSignErr;

impl Signable for crate::pdus::Ticket {
    type PrivateContext = ring::signature::Ed25519KeyPair;
    type Error = UnspecSignErr;

    fn sign(
        obj: &[u8],
        decoded: &Self,
        ctx: &Self::PrivateContext,
    ) -> Result<Vec<u8>, UnspecSignErr> {
        assert_eq!(decoded.signature_algo, SignatureAlgo::Ed25519);
        Ok(ctx.sign(obj).as_ref().to_vec())
    }
}

impl<'kp> Verifyable<'kp> for crate::pdus::Ticket {
    type PublicContext = ring::signature::UnparsedPublicKey<&'kp [u8]>;

    fn verify(
        obj: &[u8],
        decoded: &Self,
        signature: &[u8],
        ctx: &Self::PublicContext,
    ) -> Result<(), UnspecSignErr> {
        if decoded.signature_algo != SignatureAlgo::Ed25519 {
            return Err(UnspecSignErr);
        }
        ctx.verify(obj, signature).map_err(|_| UnspecSignErr)
    }
}
