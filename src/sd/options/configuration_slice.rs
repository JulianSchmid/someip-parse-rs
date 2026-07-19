use crate::{
    err::{self, Layer, LenSource},
    sd::options::{ConfigurationOption, SdConfigurationStringError},
};
use arrayvec::ArrayVec;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ConfigurationSlice<'a> {
    slice: &'a [u8],
}

impl<'a> ConfigurationSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, err::LenError> {
        if slice.is_empty() {
            return Err(err::LenError {
                required_len: 1,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::SdOption,
            });
        } else if slice.len() > ConfigurationOption::MAX_CONFIGURATION_STRING_LEN + 1 {
            return Err(err::LenError {
                required_len: ConfigurationOption::MAX_CONFIGURATION_STRING_LEN + 1,
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

    /// Validates the DNS-SD format of the configuration string.
    #[inline]
    pub fn validate(&self) -> Result<(), SdConfigurationStringError> {
        ConfigurationOption::validate_configuration_string(self.configuration_string())
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
            .expect("Configuration string length exceeds the maximum allowed configuration string size (should not happen, as length is checked in from_slice)");
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
        // empty slice error
        {
            let err = ConfigurationSlice::from_slice(&[]).unwrap_err();
            assert_eq!(err.required_len, 1);
            assert_eq!(err.len, 0);
            assert_eq!(err.len_source, LenSource::Slice);
            assert_eq!(err.layer, Layer::SdOption);
        }

        // too long slice error
        {
            let data = [0x00; ConfigurationOption::MAX_CONFIGURATION_STRING_LEN + 2];
            let err = ConfigurationSlice::from_slice(&data).unwrap_err();
            assert_eq!(
                err.required_len,
                ConfigurationOption::MAX_CONFIGURATION_STRING_LEN + 1
            );
            assert_eq!(
                err.len,
                ConfigurationOption::MAX_CONFIGURATION_STRING_LEN + 2
            );
            assert_eq!(err.len_source, LenSource::Slice);
            assert_eq!(err.layer, Layer::SdOption);
        }

        let data = [0x00; ConfigurationOption::MAX_CONFIGURATION_STRING_LEN + 1];
        let s = ConfigurationSlice::from_slice(&data).unwrap();
        assert_eq!(
            s.configuration_string().len(),
            ConfigurationOption::MAX_CONFIGURATION_STRING_LEN
        );

        let s = ConfigurationSlice::from_slice(&[0x00, 0x00]).unwrap();
        assert_eq!(s.configuration_string(), &[0x00]);
        assert_eq!(s.slice(), &[0x00, 0x00]);
        s.validate().unwrap();

        let s = ConfigurationSlice::from_slice(&[0x80, 0x03, 0x61, 0x62, 0x63, 0x00]).unwrap();
        assert_eq!(s.configuration_string(), b"\x03abc\0");
        assert_eq!(s.slice(), &[0x80, 0x03, 0x61, 0x62, 0x63, 0x00]);
        s.validate().unwrap();
    }

    #[test]
    fn accessors() {
        let s = ConfigurationSlice::from_slice(&[0x00, 0x00]).unwrap();
        assert!(!s.discardable());
        assert_eq!(s.configuration_string(), &[0x00]);
        assert_eq!(s.slice(), &[0x00, 0x00]);

        let s = ConfigurationSlice::from_slice(&[DISCARDABLE_FLAG, 0x00]).unwrap();
        assert!(s.discardable());
        assert_eq!(s.configuration_string(), &[0x00]);
        assert_eq!(s.slice(), &[DISCARDABLE_FLAG, 0x00]);

        let s = ConfigurationSlice::from_slice(&[0x7f, 0x02, 0x78, 0x79, 0x00]).unwrap();
        assert!(!s.discardable());
        assert_eq!(s.configuration_string(), b"\x02xy\0");
        assert_eq!(s.slice(), &[0x7f, 0x02, 0x78, 0x79, 0x00]);
    }

    #[test]
    fn from_conversion() {
        let s = ConfigurationSlice::from_slice(&[0x00, 0x03, 0x66, 0x6f, 0x6f, 0x00]).unwrap();
        let opt = ConfigurationOption::from(s);
        assert!(!opt.discardable);
        assert_eq!(opt.configuration_string.as_slice(), b"\x03foo\0");

        let s = ConfigurationSlice::from_slice(&[DISCARDABLE_FLAG, 0x03, 0x62, 0x61, 0x72, 0x00])
            .unwrap();
        let opt = ConfigurationOption::from(s);
        assert!(opt.discardable);
        assert_eq!(opt.configuration_string.as_slice(), b"\x03bar\0");
    }
}
