#[derive(Debug, thiserror::Error)]
#[error("not further specified signature error")]
pub struct UnspecifiedSignatureError;
