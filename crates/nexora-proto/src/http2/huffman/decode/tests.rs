use super::*;

#[test]
fn nibble_matches_bit_decoder_on_wire() {
    let check = |wire: &[u8]| {
        assert_eq!(
            decode(wire).map_err(|error| error.to_string()),
            bit_reference(wire).map_err(|error| error.to_string()),
            "wire={wire:x?}"
        );
    };
    check(&[]);
    for first in 0..=u8::MAX {
        check(&[first]);
        for second in 0..=u8::MAX {
            check(&[first, second]);
        }
    }
    let mut random = 0x0123_4567_89ab_cdef_u64;
    for len in 3..=64 {
        for _ in 0..256 {
            let wire: Vec<_> = (0..len)
                .map(|_| {
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    random as u8
                })
                .collect();
            check(&wire);
        }
    }
    for len in 1..=8 {
        check(&vec![255; len]);
    }
}

fn bit_reference(input: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::with_capacity(input.len());
    let mut node = 0_usize;
    let mut trailing_bits = 0_u8;
    let mut trailing_ones = true;
    for &byte in input {
        for shift in (0..8).rev() {
            let bit = usize::from((byte >> shift) & 1);
            let next = TREE[node].next[bit];
            if next == ABSENT {
                return Err(ProtoError::Hpack("invalid Huffman code".into()));
            }
            node = usize::from(next);
            trailing_bits += 1;
            trailing_ones &= bit == 1;
            let symbol = TREE[node].symbol;
            if symbol == EOS {
                return Err(ProtoError::Hpack("Huffman EOS symbol in string".into()));
            }
            if symbol != ABSENT {
                decoded.push(symbol as u8);
                node = 0;
                trailing_bits = 0;
                trailing_ones = true;
            }
        }
    }
    if trailing_bits > 7 || !trailing_ones {
        return Err(ProtoError::Hpack("invalid Huffman padding".into()));
    }
    Ok(decoded)
}
