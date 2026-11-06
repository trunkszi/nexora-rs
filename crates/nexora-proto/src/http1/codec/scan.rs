//! Independent word scans preserve the first carriage-return position.
use uarch::prelude::*;

#[inline]
fn cr_mask(bytes: &[u8]) -> u64 {
    let mut lane = [0; 8];
    lane.copy_from_slice(&bytes[..8]);
    let word = u64::from_le_bytes(lane) ^ 0x0d0d0d0d0d0d0d0d;
    word.wrapping_sub(0x0101010101010101) & !word & 0x8080808080808080
}

#[inline]
pub(super) fn find_cr(data: &[u8]) -> Option<usize> {
    let mut cursor = 0;
    while data.len() - cursor >= 32 {
        let words = [
            cr_mask(&data[cursor..]),
            cr_mask(&data[cursor + 8..]),
            cr_mask(&data[cursor + 16..]),
            cr_mask(&data[cursor + 24..]),
        ];
        if ilp_any!(words[0] != 0, words[1] != 0, words[2] != 0, words[3] != 0) {
            for (lane, mask) in words.into_iter().enumerate() {
                if mask != 0 {
                    return Some(cursor + lane * 8 + (mask.trailing_zeros() as usize >> 3));
                }
            }
        }
        cursor += 32;
    }
    while data.len() - cursor >= 8 {
        let mask = cr_mask(&data[cursor..]);
        if mask != 0 {
            return Some(cursor + (mask.trailing_zeros() as usize >> 3));
        }
        cursor += 8;
    }
    data[cursor..]
        .iter()
        .position(|&byte| byte == b'\r')
        .map(|offset| cursor + offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lane_and_tail_matches_scalar() {
        for len in 0..=96 {
            let mut bytes = vec![b'x'; len];
            assert_eq!(find_cr(&bytes), None);
            for index in 0..len {
                for byte in 0..=255 {
                    bytes[index] = byte;
                    assert_eq!(find_cr(&bytes), bytes.iter().position(|&b| b == b'\r'));
                }
                bytes[index] = b'x';
            }
            for index in 0..len {
                bytes[index] = b'\r';
                assert_eq!(find_cr(&bytes), Some(0));
            }
        }
    }
}
