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
pub use base64;
pub use chrono;
pub use ring;

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
