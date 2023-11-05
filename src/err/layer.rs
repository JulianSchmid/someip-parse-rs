/// Layers on which an error can occur.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Layer {
    /// Error occured in the SOMEIP header.
    SomeipHeader,
    /// Error occured in the SOMEIP TP header.
    SomeipTpHeader,
    /// Error occured in the SOMEIP payload.
    SomeipPayload,
}

impl Layer {
    /// String that is used as a title for the error.
    pub fn error_title(&self) -> &'static str {
        use Layer::*;
        match self {
            SomeipHeader => "SOMEIP Header Error",
            SomeipTpHeader => "SOMEIP TP Header Error",
            SomeipPayload => "SOMEIP Payload Error",
        }
    }
}

impl core::fmt::Display for Layer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use Layer::*;
        match self {
            SomeipHeader => write!(f, "SOMEIP header"),
            SomeipTpHeader => write!(f, "SOMEIP TP header"),
            SomeipPayload => write!(f, "SOMEIP payload"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::Layer::*;
    use std::{
        cmp::{Ord, Ordering},
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    #[test]
    fn debug() {
        assert_eq!("SomeipHeader", format!("{:?}", SomeipHeader));
    }

    #[test]
    fn clone_eq_hash_ord() {
        let layer = SomeipHeader;
        assert_eq!(layer, layer.clone());
        let hash_a = {
            let mut hasher = DefaultHasher::new();
            layer.hash(&mut hasher);
            hasher.finish()
        };
        let hash_b = {
            let mut hasher = DefaultHasher::new();
            layer.clone().hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash_a, hash_b);
        assert_eq!(Ordering::Equal, layer.cmp(&layer));
        assert_eq!(Some(Ordering::Equal), layer.partial_cmp(&layer));
    }

    #[test]
    fn error_title() {
        let tests = [
            (SomeipHeader, "SOMEIP Header Error"),
            (SomeipTpHeader, "SOMEIP TP Header Error"),
            (SomeipPayload, "SOMEIP Payload Error"),
        ];
        for test in tests {
            assert_eq!(test.0.error_title(), test.1);
        }
    }

    #[test]
    fn fmt() {
        let tests = [
            (SomeipHeader, "SOMEIP header"),
            (SomeipTpHeader, "SOMEIP TP header"),
            (SomeipPayload, "SOMEIP payload"),
        ];
        for test in tests {
            assert_eq!(format!("{}", test.0), test.1);
        }
    }
}
