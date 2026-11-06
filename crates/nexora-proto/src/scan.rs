//! Stateless byte predicates shared by protocol validators.
use uarch::prelude::*;

#[inline]
pub(crate) fn all_bytes(input: &[u8], valid: impl Fn(u8) -> bool) -> bool {
    reduce_lanes::<4, _, _>(
        input,
        true,
        true,
        |accepted, byte| accepted & valid(*byte),
        |left, right| left & right,
    )
}

#[hot_inline]
pub(crate) fn is_token(byte: u8) -> bool {
    ilp_any!(
        byte.is_ascii_alphanumeric(),
        b"!#$%&'*+-.^_`|~".contains(&byte)
    )
}

#[hot_inline]
pub(crate) fn is_field_value(byte: u8) -> bool {
    ilp_all!(ilp_any!(byte >= b' ', byte == b'\t'), byte != 127)
}
