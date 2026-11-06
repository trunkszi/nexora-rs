//! Four-bit transitions retain the exact RFC prefix and padding state.
use uarch::prelude::*;

use super::{ABSENT, EOS, TREE};
use crate::{ProtoError, Result};

bitword! {
    struct DecodeStep(u32) {
        [0..=9] NEXT: u16,
        [10..=17] SYMBOL: u8,
        [18] EMIT,
        [19] INVALID,
        [20] EOS_SYMBOL,
        [21..=23] TAIL: u8,
        [24] ONES,
    }
}
assert_layout!(DecodeStep, size = 4, align = 4);
const STATES: usize = 513;
const STRIDE: usize = PowerOfTwo::<4>::VALUE;
static TABLE: CacheAligned<[DecodeStep; STATES * STRIDE]> = CacheAligned::new(build_table());
assert_layout!(
    CacheAligned<[DecodeStep; STATES * STRIDE]>,
    size = STATES * 64,
    align = 64
);

const fn build_table() -> [DecodeStep; STATES * STRIDE] {
    let mut table = [DecodeStep::new(0); STATES * STRIDE];
    let mut state = 0;
    while state < STATES {
        let mut nibble = 0;
        while nibble < STRIDE {
            table[state * STRIDE + nibble] = transition(state, nibble);
            nibble += 1;
        }
        state += 1;
    }
    table
}

const fn transition(mut node: usize, nibble: usize) -> DecodeStep {
    let mut emitted = false;
    let mut symbol = 0;
    let mut tail = 0;
    let mut ones = true;
    let mut invalid = false;
    let mut eos = false;
    let mut shift = 4;
    while shift != 0 {
        shift -= 1;
        let bit = (nibble >> shift) & 1;
        let next = TREE[node].next[bit];
        if next == ABSENT {
            invalid = true;
            break;
        }
        node = next as usize;
        tail += 1;
        ones = ones && bit == 1;
        let decoded = TREE[node].symbol;
        if decoded == EOS {
            eos = true;
            break;
        }
        if decoded != ABSENT {
            // The shortest code is five bits, so a nibble cannot emit twice.
            assert!(!emitted);
            emitted = true;
            symbol = decoded as u8;
            tail = 0;
            ones = true;
            node = 0;
        }
    }
    DecodeStep::new(0).patch(
        BitPatch::EMPTY
            .with_field(DecodeStep::NEXT, (node as u64) & 0x3ff)
            .with_field(DecodeStep::SYMBOL, (symbol as u64) & 0xff)
            .with_flag(DecodeStep::EMIT, emitted)
            .with_flag(DecodeStep::INVALID, invalid)
            .with_flag(DecodeStep::EOS_SYMBOL, eos)
            .with_field(DecodeStep::TAIL, tail & 7)
            .with_flag(DecodeStep::ONES, ones),
    )
}

#[inline]
fn decode_nibble(
    nibble: u8,
    node: &mut usize,
    trailing_bits: &mut u32,
    trailing_ones: &mut bool,
    out: &mut Vec<u8>,
) -> Result<()> {
    let step = TABLE[*node * STRIDE + usize::from(nibble)];
    if !step.matches(pattern!(DecodeStep { !INVALID & !EOS_SYMBOL })) {
        return Err(invalid_code(step.test(DecodeStep::EOS_SYMBOL)));
    }
    let emitted = predicate(step.test(DecodeStep::EMIT));
    *trailing_bits =
        emitted.select_register(u32::from(step.get(DecodeStep::TAIL)), *trailing_bits + 4);
    *trailing_ones = ((emitted & predicate(step.test(DecodeStep::ONES)))
        | (!emitted & predicate(*trailing_ones) & predicate(nibble == 15)))
    .as_bool();
    if emitted.as_bool() {
        out.push(step.get(DecodeStep::SYMBOL));
    }
    *node = usize::from(step.get(DecodeStep::NEXT));
    Ok(())
}

pub(super) fn decode(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut node = 0;
    let mut trailing_bits = 0;
    let mut trailing_ones = true;
    for &byte in input {
        decode_nibble(
            byte >> 4,
            &mut node,
            &mut trailing_bits,
            &mut trailing_ones,
            &mut out,
        )?;
        decode_nibble(
            byte & 15,
            &mut node,
            &mut trailing_bits,
            &mut trailing_ones,
            &mut out,
        )?;
    }
    if ilp_any!(trailing_bits > 7, !trailing_ones) {
        return Err(invalid_padding());
    }
    Ok(out)
}

#[cold_sink]
fn invalid_code(eos: bool) -> ProtoError {
    ProtoError::Hpack(
        if eos {
            "Huffman EOS symbol in string"
        } else {
            "invalid Huffman code"
        }
        .into(),
    )
}

#[cold_sink]
fn invalid_padding() -> ProtoError {
    ProtoError::Hpack("invalid Huffman padding".into())
}

#[cfg(test)]
mod tests;
