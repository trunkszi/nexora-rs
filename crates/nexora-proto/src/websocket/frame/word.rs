//! The first two wire octets share one register-sized header word.

use uarch::prelude::*;

bitword! {
    pub(super) struct WebSocketHeader(u64) {
        [0..=3] pub OPCODE: u8,
        [4] pub RSV3,
        [5] pub RSV2,
        [6] pub RSV1,
        [7] pub FIN,
        [8..=14] pub LENGTH: u8,
        [15] pub MASK,
    }
}

assert_layout!(WebSocketHeader, size = 8, align = 8);

impl WebSocketHeader {
    #[hot_inline]
    pub(super) fn for_frame(fin: bool, opcode: u8, masked: bool, length: u8) -> Self {
        Self::new(0).patch(
            BitPatch::EMPTY
                .with_flag(Self::FIN, fin)
                .with_flag(Self::MASK, masked)
                .with_field(Self::OPCODE, u64::from(opcode) & 0xf)
                .with_field(Self::LENGTH, u64::from(length) & 0x7f),
        )
    }
}

#[cfg(test)]
mod unit_scenario {
    use super::*;

    #[test]
    fn header_fields_preserve_wire_bits() {
        let header = WebSocketHeader::for_frame(true, 2, false, 126);
        assert_eq!(header.raw(), 0x7e82);
        let header = WebSocketHeader::for_frame(false, 0, true, 127);
        assert_eq!(header.raw(), 0xff00);
        for reserved in [0x10, 0x20, 0x40] {
            let header = WebSocketHeader::new(0xff00 | reserved);
            assert!(!header.matches(pattern!(WebSocketHeader { !RSV1 & !RSV2 & !RSV3 })));
            assert_eq!(header.get(WebSocketHeader::LENGTH), 127);
            assert!(header.test(WebSocketHeader::MASK));
        }
    }
}
