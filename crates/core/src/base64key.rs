use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Base64Key(pub Vec<u8>);

impl Base64Key {
    #[inline(always)]
    pub fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl std::ops::Deref for Base64Key {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for Base64Key {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        base64::encode(&self.0[..]).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Base64Key {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64::decode(&s)
            .map(Base64Key)
            .map_err(|_| D::Error::invalid_type(serde::de::Unexpected::Str(&s), &"base64 string"))
    }
}
