use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use zeroize::Zeroize;

#[derive(Clone, Deserialize, Serialize, Zeroize)]
pub struct SignedObject<T> {
    obj: Vec<u8>,
    signature: Vec<u8>,

    #[serde(skip)]
    _ph: PhantomData<T>,
}

impl<T: Serialize> SignedObject<T> {
    pub fn encode<S, R>(obj: &T, signf: S) -> Result<Self, serde_cbor::error::Error>
    where
        S: FnOnce(&[u8]) -> R,
        R: AsRef<[u8]>,
    {
        // 1. serialize object
        let objenc = serde_cbor::to_vec(obj)?;
        // 2. create signature
        let signature = signf(&objenc[..]).as_ref().to_vec();
        // 3. finish
        Ok(Self {
            obj: objenc,
            signature,
            _ph: PhantomData,
        })
    }
}

impl<T: for<'a> Deserialize<'a>> SignedObject<T> {
    /// This function does not check if the signature is valid!
    #[inline]
    pub fn decode(&self) -> Result<T, serde_cbor::error::Error> {
        serde_cbor::from_slice(&self.obj[..])
    }

    /// the given fn should have the following function signature:
    /// `verifyf(message, signature)`
    #[inline]
    pub fn verify<F>(&self, verifyf: F) -> Result<(), ()>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<(), ()>,
    {
        verifyf(&self.obj[..], &self.signature[..])
    }
}
