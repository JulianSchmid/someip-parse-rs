/// Describing the range of received data.
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct SectionRange {
    /// Offset of section
    pub start: u32,
    /// Offset + length of section
    pub end: u32,
}

impl SectionRange {
    /// Return if the value is contained within the section.
    fn is_value_connected(&self, value: u32) -> bool {
        self.start <= value && self.end >= value
    }

    /// Combine both sections if possible.
    pub fn merge(&self, other: SectionRange) -> Option<SectionRange> {
        if self.is_value_connected(other.start)
            || self.is_value_connected(other.end)
            || other.is_value_connected(self.start)
            || other.is_value_connected(self.end)
        {
            Some(SectionRange {
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
    fn is_value_connected() {
        let s = SectionRange { start: 5, end: 9 };
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
            let a = SectionRange {
                start: t.0 .0,
                end: t.0 .1,
            };
            let b = SectionRange {
                start: t.1 .0,
                end: t.1 .1,
            };
            let expected = t.2.map(|v| SectionRange {
                start: v.0,
                end: v.1,
            });
            assert_eq!(a.merge(b), expected);
            assert_eq!(b.merge(a), expected);
        }
    }
}
