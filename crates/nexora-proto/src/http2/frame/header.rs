//! Metadata and stream ID occupy separate ABI leaves; the wire needs 71 bits.

use uarch::prelude::*;

use super::{BytesMut, Http2FrameHeader, Http2FrameType, STREAM_MASK};

bitword! {
    pub(super) struct Http2FrameWord(u64) {
        [0..=7] pub FLAGS: u8,
        [8..=15] pub FRAME_TYPE: u8,
        [16..=39] pub LENGTH: u32,
    }
}

#[register_pass]
#[derive(Clone, Copy)]
pub(super) struct WireHeader {
    meta: Http2FrameWord,
    stream: u64,
}

assert_layout!(WireHeader, size = 16, align = 8, fields = { meta: 0, stream: 8 });

impl WireHeader {
    #[hot_inline]
    pub(super) fn read(bytes: &[u8]) -> Self {
        Self {
            meta: Http2FrameWord::new(u64::from_be_bytes([
                0, 0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4],
            ])),
            stream: u64::from(super::read_u32(&bytes[5..9]) & STREAM_MASK),
        }
    }

    #[inline]
    pub(super) fn from_header(header: Http2FrameHeader) -> Self {
        Self {
            meta: Http2FrameWord::new(0).patch(
                BitPatch::EMPTY
                    .with_field(Http2FrameWord::FLAGS, u64::from(header.flags))
                    .with_field(
                        Http2FrameWord::FRAME_TYPE,
                        u64::from(header.frame_type.as_byte()),
                    )
                    .with_field(Http2FrameWord::LENGTH, u64::from(header.length) & 0xff_ffff),
            ),
            stream: u64::from(header.stream_id),
        }
    }

    #[hot_inline]
    pub(super) fn header(self) -> Http2FrameHeader {
        Http2FrameHeader {
            length: self.meta.get(Http2FrameWord::LENGTH),
            frame_type: Http2FrameType::from_byte(self.meta.get(Http2FrameWord::FRAME_TYPE)),
            flags: self.meta.get(Http2FrameWord::FLAGS),
            stream_id: self.stream as u32,
        }
    }

    #[inline]
    pub(super) fn write(self, out: &mut BytesMut) {
        let meta = self.meta.raw().to_be_bytes();
        let stream = (self.stream as u32).to_be_bytes();
        out.extend_from_slice(&[
            meta[3], meta[4], meta[5], meta[6], meta[7], stream[0], stream[1], stream[2], stream[3],
        ]);
    }
}

#[cfg(test)]
mod unit_scenario {
    use super::*;

    #[test]
    fn metadata_and_stream_roundtrip_wire() {
        let input = [0x12, 0x34, 0x56, 0xab, 0xed, 0xff, 0xff, 0xff, 0xff];
        let header = WireHeader::read(&input).header();
        assert_eq!(header.length, 0x12_3456);
        assert_eq!(header.frame_type, Http2FrameType::Unknown(0xab));
        assert_eq!(header.flags, 0xed);
        assert_eq!(header.stream_id, 0x7fff_ffff);
        let mut output = BytesMut::new();
        WireHeader::from_header(header).write(&mut output);
        assert_eq!(
            output.as_slice(),
            &[0x12, 0x34, 0x56, 0xab, 0xed, 0x7f, 0xff, 0xff, 0xff]
        );
        assert_eq!(core::mem::size_of::<WireHeader>(), 16);
    }
    #[test]
    fn length_field_truncates_without_panicking() {
        let header = Http2FrameHeader {
            length: u32::MAX,
            flags: u8::MAX,
            frame_type: Http2FrameType::Data,
            stream_id: 1,
        };
        assert_eq!(WireHeader::from_header(header).header().length, 0xff_ffff);
    }
}
