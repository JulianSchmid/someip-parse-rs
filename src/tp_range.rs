/// Describing the range of received data in an TP stream.
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct TpRange {
    /// Offset of section
    pub start: u32,
    /// Offset + length of section
    pub end: u32,
}

impl TpRange {
    /// Return if the value is contained within the section.
    fn is_value_connected(&self, value: u32) -> bool {
        self.start <= value && self.end >= value
    }

    /// Combine both sections if possible.
    pub fn merge(&self, other: TpRange) -> Option<TpRange> {
        if self.is_value_connected(other.start)
            || self.is_value_connected(other.end)
            || other.is_value_connected(self.start)
            || other.is_value_connected(self.end)
        {
            Some(TpRange {
                start: core::cmp::min(self.start, other.start),
                end: core::cmp::max(self.end, other.end),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn debug_clone_eq() {
        let section = TpRange { start: 1, end: 2 };
        let _ = format!("{:?}", section);
        assert_eq!(section, section.clone());
        assert_eq!(section.cmp(&section), core::cmp::Ordering::Equal);
        assert_eq!(
            section.partial_cmp(&section),
            Some(core::cmp::Ordering::Equal)
        );

        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let h1 = {
            let mut h = DefaultHasher::new();
            section.hash(&mut h);
            h.finish()
        };
        let h2 = {
            let mut h = DefaultHasher::new();
            section.clone().hash(&mut h);
            h.finish()
        };
        assert_eq!(h1, h2);
    }

    #[test]
    fn is_value_connected() {
        let s = TpRange { start: 5, end: 9 };
        assert_eq!(false, s.is_value_connected(3));
        assert_eq!(false, s.is_value_connected(4));
        assert!(s.is_value_connected(5));
        assert!(s.is_value_connected(6));
        assert!(s.is_value_connected(7));
        assert!(s.is_value_connected(8));
        assert!(s.is_value_connected(9));
        assert_eq!(false, s.is_value_connected(10));
        assert_eq!(false, s.is_value_connected(11));
    }

    #[test]
    fn merge() {
        let tests = [
            ((0, 1), (1, 2), Some((0, 2))),
            ((0, 1), (2, 3), None),
            ((3, 7), (1, 2), None),
            ((3, 7), (1, 3), Some((1, 7))),
            ((3, 7), (1, 4), Some((1, 7))),
            ((3, 7), (1, 5), Some((1, 7))),
            ((3, 7), (1, 6), Some((1, 7))),
            ((3, 7), (1, 7), Some((1, 7))),
            ((3, 7), (1, 8), Some((1, 8))),
        ];
        for t in tests {
            let a = TpRange {
                start: t.0 .0,
                end: t.0 .1,
            };
            let b = TpRange {
                start: t.1 .0,
                end: t.1 .1,
            };
            let expected = t.2.map(|v| TpRange {
                start: v.0,
                end: v.1,
            });
            assert_eq!(a.merge(b), expected);
            assert_eq!(b.merge(a), expected);
        }
    }
}
