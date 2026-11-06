use nexora_proto::WebSocketCodec;

#[test]
fn word_batches_preserve_payload_boundaries() {
    for mask in [[0, 0, 0, 0], [0xff; 4], [0x37, 0xfa, 0x21, 0x3d]] {
        for offset in 0..32 {
            for len in [0, 1, 7, 8, 31, 32, 33, 63, 64, 65, 255, 256, 257, 8193] {
                let mut bytes: Vec<_> = (0..offset + len + 32).map(|i| i as u8).collect();
                let original = bytes.clone();
                WebSocketCodec::apply_mask(&mut bytes[offset..offset + len], mask);
                assert_eq!(&bytes[..offset], &original[..offset]);
                assert_eq!(&bytes[offset + len..], &original[offset + len..]);
                for (i, byte) in bytes[offset..offset + len].iter().enumerate() {
                    assert_eq!(*byte, original[offset + i] ^ mask[i & 3]);
                }
                WebSocketCodec::apply_mask(&mut bytes[offset..offset + len], mask);
                assert_eq!(bytes, original);
            }
        }
    }
}
