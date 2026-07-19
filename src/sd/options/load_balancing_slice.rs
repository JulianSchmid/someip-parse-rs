use crate::err::{self, Layer, LenSource};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct LoadBalancingSlice<'a> {
    slice: &'a [u8],
}

impl<'a> LoadBalancingSlice<'a> {
    pub const LEN: usize = 5;

    pub fn from_slice(slice: &'a [u8]) -> Result<LoadBalancingSlice<'a>, err::LenError> {
        if slice.len() != Self::LEN {
            Err(err::LenError {
                required_len: Self::LEN,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::SdOption,
            })
        } else {
            Ok(LoadBalancingSlice { slice })
        }
    }

    #[inline]
    pub fn discardable(&self) -> bool {
        // SAFETY: slice is guaranteed to have a length of 5 during construction.
        0 != unsafe { *self.slice.get_unchecked(0) } & super::DISCARDABLE_FLAG
    }

    #[inline]
    pub fn priority(&self) -> u16 {
        // SAFETY: slice is guaranteed to have a length of 5 during construction.
        unsafe { u16::from_be_bytes([*self.slice.get_unchecked(1), *self.slice.get_unchecked(2)]) }
    }

    #[inline]
    pub fn weight(&self) -> u16 {
        // SAFETY: slice is guaranteed to have a length of 5 during construction.
        unsafe { u16::from_be_bytes([*self.slice.get_unchecked(3), *self.slice.get_unchecked(4)]) }
    }

    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

impl From<LoadBalancingSlice<'_>> for super::LoadBalancingOption {
    fn from(s: LoadBalancingSlice<'_>) -> Self {
        super::LoadBalancingOption {
            discardable: s.discardable(),
            priority: s.priority(),
            weight: s.weight(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::err::{Layer, LenSource};
    use crate::sd::options::LoadBalancingOption;

    #[test]
    fn from_slice() {
        assert_eq!(
            LoadBalancingSlice::from_slice(&[0u8; 4]),
            Err(err::LenError {
                required_len: LoadBalancingSlice::LEN,
                len: 4,
                len_source: LenSource::Slice,
                layer: Layer::SdOption,
            })
        );
        let s = LoadBalancingSlice::from_slice(&[0x80, 0x00, 0x01, 0x00, 0x02]).unwrap();
        assert_eq!(s.slice(), &[0x80, 0x00, 0x01, 0x00, 0x02]);
        assert!(
            LoadBalancingSlice::from_slice(&[0x80, 0x00, 0x01, 0x00, 0x02, 0x99, 0x99]).is_err()
        );
    }

    #[test]
    fn accessors() {
        let s = LoadBalancingSlice::from_slice(&[0x80, 0x12, 0x34, 0x56, 0x78]).unwrap();
        assert!(s.discardable());
        assert_eq!(s.priority(), 0x1234);
        assert_eq!(s.weight(), 0x5678);
        let s = LoadBalancingSlice::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
        assert!(!s.discardable());
        assert_eq!(s.priority(), 0);
        assert_eq!(s.weight(), 0);
    }

    #[test]
    fn from_conversion() {
        let s = LoadBalancingSlice::from_slice(&[0x80, 0x12, 0x34, 0x56, 0x78]).unwrap();
        let o: LoadBalancingOption = s.into();
        assert!(o.discardable);
        assert_eq!(o.priority, 0x1234);
        assert_eq!(o.weight, 0x5678);
        let s = LoadBalancingSlice::from_slice(&[0x00, 0xAB, 0xCD, 0xEF, 0x01]).unwrap();
        let o = LoadBalancingOption::from(s);
        assert!(!o.discardable);
        assert_eq!(o.priority, 0xABCD);
        assert_eq!(o.weight, 0xEF01);
    }
}
