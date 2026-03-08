use crate::err::{self, Layer, LenSource};
use arrayvec::ArrayVec;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ConfigurationSlice<'a> {
    slice: &'a [u8],
}

impl<'a> ConfigurationSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, err::LenError> {
        if slice.len() < 1 {
            return Err(err::LenError {
                required_len: 1,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::SdOption,
            });
        }
        Ok(Self { slice })
    }

    #[inline]
    pub fn discardable(&self) -> bool {
        // SAFETY: from_slice guarantees slice.len() >= 1.
        0 != unsafe { *self.slice.get_unchecked(0) } & super::DISCARDABLE_FLAG
    }

    #[inline]
    pub fn configuration_string(&self) -> &'a [u8] {
        // SAFETY: from_slice guarantees slice.len() >= 1, so offset 1 is valid and len - 1 is the remaining length.
        unsafe { core::slice::from_raw_parts(self.slice.as_ptr().add(1), self.slice.len() - 1) }
    }

    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

impl<'a> From<ConfigurationSlice<'a>> for super::ConfigurationOption {
    fn from(s: ConfigurationSlice<'a>) -> Self {
        let mut configuration_string = ArrayVec::new();
        configuration_string
            .try_extend_from_slice(s.configuration_string())
            .unwrap();
        Self {
            discardable: s.discardable(),
            configuration_string,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::sd::options::{ConfigurationOption, DISCARDABLE_FLAG};

    #[test]
    fn from_slice() {
        assert!(ConfigurationSlice::from_slice(&[]).is_err());
        let err = ConfigurationSlice::from_slice(&[]).unwrap_err();
        assert_eq!(err.required_len, 1);
        assert_eq!(err.len, 0);
        assert_eq!(err.len_source, LenSource::Slice);
        assert_eq!(err.layer, Layer::SdOption);

        let s = ConfigurationSlice::from_slice(&[0x00]).unwrap();
        assert_eq!(s.configuration_string(), &[] as &[u8]);
        assert_eq!(s.slice(), &[0x00]);

        let s = ConfigurationSlice::from_slice(&[0x80, 0x61, 0x62, 0x63]).unwrap();
        assert_eq!(s.configuration_string(), b"abc");
        assert_eq!(s.slice(), &[0x80, 0x61, 0x62, 0x63]);
    }

    #[test]
    fn accessors() {
        let s = ConfigurationSlice::from_slice(&[0x00]).unwrap();
        assert!(!s.discardable());
        assert_eq!(s.configuration_string(), &[] as &[u8]);
        assert_eq!(s.slice(), &[0x00]);

        let s = ConfigurationSlice::from_slice(&[DISCARDABLE_FLAG]).unwrap();
        assert!(s.discardable());
        assert_eq!(s.configuration_string(), &[] as &[u8]);
        assert_eq!(s.slice(), &[DISCARDABLE_FLAG]);

        let s = ConfigurationSlice::from_slice(&[0x7f, 0x78, 0x79]).unwrap();
        assert!(!s.discardable());
        assert_eq!(s.configuration_string(), b"xy");
        assert_eq!(s.slice(), &[0x7f, 0x78, 0x79]);
    }

    #[test]
    fn from_conversion() {
        let s = ConfigurationSlice::from_slice(&[0x00, 0x66, 0x6f, 0x6f]).unwrap();
        let opt = ConfigurationOption::from(s);
        assert!(!opt.discardable);
        assert_eq!(opt.configuration_string.as_slice(), b"foo");

        let s = ConfigurationSlice::from_slice(&[DISCARDABLE_FLAG, 0x62, 0x61, 0x72])
            .unwrap();
        let opt = ConfigurationOption::from(s);
        assert!(opt.discardable);
        assert_eq!(opt.configuration_string.as_slice(), b"bar");
    }
}
