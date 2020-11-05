// the following fns convert between i64 (db primary id) and u64 (ticket id)

#[inline]
pub fn i2u(x: i64) -> u64 {
    u64::from_be_bytes(i64::to_be_bytes(x))
}

#[inline]
pub fn u2i(x: u64) -> i64 {
    i64::from_be_bytes(u64::to_be_bytes(x))
}

#[cfg(test)]
mod tests {
    use std::convert::{TryInto, TryFrom};
    use super::{i2u as x64i2u, u2i as x64u2i};

    #[test]
    fn null_and_one() {
        assert_eq!(0, x64i2u(0));
        assert_eq!(0, x64u2i(0));

        assert_eq!(1, x64i2u(1));
        assert_eq!(1, x64u2i(1));
    }

    #[test]
    fn negative() {
        assert_eq!(u64::MAX, x64i2u(-1));
        assert_eq!(-1, x64u2i(x64i2u(-1)));

        assert_eq!(u64::MAX - 999, x64i2u(-1000));
        assert_eq!(-1000, x64u2i(x64i2u(-1000)));

        assert_eq!(-2, x64u2i(u64::MAX - 1));
    }

    #[test]
    fn iminmax() {
        assert_eq!(i64::MIN, x64u2i(u64::try_from(i64::MAX).unwrap() + 1));
        assert_eq!(u64::try_from(i64::MAX).unwrap(), x64i2u(x64u2i(i64::MAX.try_into().unwrap())));
    }
}
