//! Chunk-extension token and quoted-string validation.

use super::{Result, chunk_error, is_token};

pub(super) fn validate_chunk_extensions(extension: &str) -> Result<()> {
    let mut remaining = extension.as_bytes();
    loop {
        remaining = trim_ows(remaining);
        let name_len = remaining.iter().take_while(|byte| is_token(**byte)).count();
        if name_len == 0 {
            return Err(chunk_error("invalid extension name"));
        }
        remaining = trim_ows(&remaining[name_len..]);
        if remaining.first() == Some(&b'=') {
            remaining = trim_ows(&remaining[1..]);
            if remaining.first() == Some(&b'"') {
                remaining = &remaining[1..];
                loop {
                    let Some((&byte, rest)) = remaining.split_first() else {
                        return Err(chunk_error("unterminated quoted extension"));
                    };
                    remaining = rest;
                    if byte == b'"' {
                        break;
                    }
                    if byte == b'\\' {
                        let Some((&escaped, rest)) = remaining.split_first() else {
                            return Err(chunk_error("incomplete quoted extension escape"));
                        };
                        if !crate::scan::is_field_value(escaped) {
                            return Err(chunk_error("invalid quoted extension escape"));
                        }
                        remaining = rest;
                    } else if !crate::scan::is_field_value(byte) {
                        return Err(chunk_error("invalid quoted extension"));
                    }
                }
            } else {
                let value_len = remaining.iter().take_while(|byte| is_token(**byte)).count();
                if value_len == 0 {
                    return Err(chunk_error("missing extension value"));
                }
                remaining = &remaining[value_len..];
            }
        }
        remaining = trim_ows(remaining);
        if remaining.is_empty() {
            return Ok(());
        }
        if remaining.first() != Some(&b';') {
            return Err(chunk_error("invalid extension separator"));
        }
        remaining = &remaining[1..];
    }
}

#[inline]
fn trim_ows(mut input: &[u8]) -> &[u8] {
    while input
        .first()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        input = &input[1..];
    }
    input
}
