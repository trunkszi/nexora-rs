//! RFC 7541 header compression with independent encoding and decoding contexts.

use std::collections::VecDeque;

use super::huffman::{huffman_decode, huffman_encode, huffman_encoded_len};
use crate::{BytesMut, ProtoError, Result};

const INITIAL_TABLE_SIZE: usize = 4096;
const DEFAULT_HEADER_LIST_SIZE: usize = 16 * 1024;

// RFC 7541 Appendix A. Index zero is reserved and is not stored here.
const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

#[derive(Debug)]
struct DynamicTable {
    entries: VecDeque<(String, String)>,
    size: usize,
    maximum: usize,
}

impl DynamicTable {
    fn new(maximum: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            maximum,
        }
    }

    fn resize(&mut self, maximum: usize) {
        self.maximum = maximum;
        self.evict_to(maximum);
    }

    fn evict_to(&mut self, target: usize) {
        while self.size > target {
            if let Some((name, value)) = self.entries.pop_back() {
                self.size -= name.len() + value.len() + 32;
            } else {
                self.size = 0;
                break;
            }
        }
    }

    fn insert(&mut self, name: String, value: String) {
        let Some(size) = entry_size(&name, &value) else {
            self.entries.clear();
            self.size = 0;
            return;
        };
        if size > self.maximum {
            self.entries.clear();
            self.size = 0;
            return;
        }
        self.evict_to(self.maximum - size);
        self.entries.push_front((name, value));
        self.size += size;
    }

    fn get(&self, index: usize) -> Result<(&str, &str)> {
        let index = index
            .checked_sub(1)
            .ok_or_else(|| hpack_error("zero index"))?;
        if let Some(&(name, value)) = STATIC_TABLE.get(index) {
            return Ok((name, value));
        }
        self.entries
            .get(index - STATIC_TABLE.len())
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .ok_or_else(|| hpack_error("header index outside table"))
    }

    fn find(&self, name: &str, value: Option<&str>) -> Option<usize> {
        STATIC_TABLE
            .iter()
            .position(|&(n, v)| n == name && value.is_none_or(|value| value == v))
            .map(|index| index + 1)
            .or_else(|| {
                self.entries
                    .iter()
                    .position(|(n, v)| n == name && value.is_none_or(|value| value == v))
                    .map(|index| index + STATIC_TABLE.len() + 1)
            })
    }
}

/// A connection-direction HPACK encoder with a FIFO dynamic table.
#[derive(Debug)]
pub struct HpackEncoder {
    table: DynamicTable,
    pending_minimum: Option<usize>,
}

impl Default for HpackEncoder {
    fn default() -> Self {
        Self::new(INITIAL_TABLE_SIZE)
    }
}

impl HpackEncoder {
    /// Creates an encoder using the peer's permitted dynamic table size.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(max_table_size: usize) -> Self {
        Self {
            table: DynamicTable::new(max_table_size),
            pending_minimum: (max_table_size != INITIAL_TABLE_SIZE).then_some(max_table_size),
        }
    }

    /// Applies the peer's table limit and schedules the next block's size update.
    /// The smallest intermediate limit is retained so evictions stay synchronized.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn set_max_table_size(&mut self, size: usize) {
        if size != self.table.maximum {
            self.pending_minimum = Some(self.pending_minimum.map_or(size, |min| min.min(size)));
            self.table.resize(size);
        }
    }

    /// Appends a complete header block, preserving field order and duplicates.
    /// Authorization and cookie fields always use never-indexed literals.
    /// Huffman encoding is selected only when it shortens a string.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn encode(&mut self, headers: &[(String, String)], out: &mut BytesMut) {
        if let Some(minimum) = self.pending_minimum.take() {
            encode_integer(minimum, 5, 0x20, out);
            if minimum != self.table.maximum {
                encode_integer(self.table.maximum, 5, 0x20, out);
            }
        }
        for (name, value) in headers {
            let sensitive = match name.len() {
                6 => name.eq_ignore_ascii_case("cookie"),
                10 => name.eq_ignore_ascii_case("set-cookie"),
                13 => name.eq_ignore_ascii_case("authorization"),
                19 => name.eq_ignore_ascii_case("proxy-authorization"),
                _ => false,
            };
            if !sensitive && let Some(index) = self.table.find(name, Some(value)) {
                encode_integer(index, 7, 0x80, out);
                continue;
            }
            let indexed = !sensitive
                && entry_size(name, value).is_some_and(|size| size <= self.table.maximum);
            let (prefix, flags) = if sensitive {
                (4, 0x10)
            } else if indexed {
                (6, 0x40)
            } else {
                (4, 0)
            };
            let name_index = self.table.find(name, None).unwrap_or(0);
            encode_integer(name_index, prefix, flags, out);
            if name_index == 0 {
                encode_string(name, out);
            }
            encode_string(value, out);
            if indexed {
                self.table.insert(name.clone(), value.clone());
            }
        }
    }
}

/// A connection-direction HPACK decoder with bounded table and header-list sizes.
#[derive(Debug)]
pub struct HpackDecoder {
    table: DynamicTable,
    max_table_size: usize,
    max_header_list_size: usize,
    required_reduction: Option<usize>,
    failed: bool,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new(INITIAL_TABLE_SIZE, DEFAULT_HEADER_LIST_SIZE)
    }
}

impl HpackDecoder {
    /// Creates a decoder with explicit dynamic table and decoded list limits.
    /// Each decoded field contributes its name and value octets plus 32 bytes.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn new(max_table_size: usize, max_header_list_size: usize) -> Self {
        Self {
            table: DynamicTable::new(max_table_size),
            max_table_size,
            max_header_list_size,
            required_reduction: None,
            failed: false,
        }
    }

    /// Changes the permitted table limit after the peer acknowledges SETTINGS.
    /// A reduction requires a matching update at the next header block's start.
    ///
    /// # Errors
    /// This function does not return errors.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn set_max_table_size(&mut self, size: usize) {
        self.max_table_size = size;
        if size < self.table.maximum {
            self.required_reduction =
                Some(self.required_reduction.map_or(size, |min| min.min(size)));
            self.table.resize(size);
        }
    }

    /// Decodes one complete header block, preserving order and duplicate fields.
    /// A list-size rejection still processes valid table changes through the end
    /// of the block, allowing later streams to reuse the compression context.
    /// Names and values must be UTF-8 because this API exposes Rust strings.
    /// A compression error permanently rejects later blocks because the peer's
    /// table state can no longer be recovered from the malformed block.
    ///
    /// # Errors
    /// Returns [`ProtoError::Hpack`] for malformed representations, invalid table
    /// references, integer overflow, invalid UTF-8, missing required updates,
    /// or a compression context that previously failed.
    /// Returns [`ProtoError::HeaderListTooLarge`] if the decoded list exceeds its limit.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<(String, String)>> {
        if self.failed {
            return Err(hpack_error("compression context previously failed"));
        }
        let result = self.decode_block(block);
        if matches!(result, Err(ProtoError::Hpack(_))) {
            self.failed = true;
        }
        result
    }

    fn decode_block(&mut self, block: &[u8]) -> Result<Vec<(String, String)>> {
        let mut cursor = 0;
        let mut headers = Vec::new();
        let mut list_size = 0usize;
        let mut too_large = false;
        let mut saw_field = false;
        let mut first_update = None;
        let mut update_count = 0;
        while let Some(&first) = block.get(cursor) {
            if first & 0xe0 == 0x20 {
                if saw_field {
                    return Err(hpack_error("table size update after header field"));
                }
                let size = decode_integer(block, &mut cursor, 5)?;
                update_count += 1;
                if update_count > 2 || first_update.is_some_and(|minimum| size < minimum) {
                    return Err(hpack_error("invalid table size update sequence"));
                }
                if size > self.max_table_size {
                    return Err(hpack_error("table size update exceeds permitted maximum"));
                }
                if self
                    .required_reduction
                    .is_some_and(|minimum| size > minimum)
                {
                    return Err(hpack_error("table size update omits required reduction"));
                }
                self.required_reduction = None;
                first_update = Some(size);
                self.table.resize(size);
                continue;
            }
            if self.required_reduction.is_some() {
                return Err(hpack_error("missing required table size update"));
            }
            saw_field = true;
            let incremental = first & 0xc0 == 0x40;
            let field = if first & 0x80 != 0 {
                let index = decode_integer(block, &mut cursor, 7)?;
                let (name, value) = self.table.get(index)?;
                add_list_size(
                    name,
                    value,
                    &mut list_size,
                    &mut too_large,
                    self.max_header_list_size,
                );
                if too_large {
                    continue;
                }
                (name.to_owned(), value.to_owned())
            } else {
                let prefix = if incremental { 6 } else { 4 };
                let index = decode_integer(block, &mut cursor, prefix)?;
                let name = if index == 0 {
                    decode_string(block, &mut cursor)?
                } else {
                    self.table.get(index)?.0.to_owned()
                };
                let value = decode_string(block, &mut cursor)?;
                add_list_size(
                    &name,
                    &value,
                    &mut list_size,
                    &mut too_large,
                    self.max_header_list_size,
                );
                (name, value)
            };
            if incremental {
                self.table.insert(field.0.clone(), field.1.clone());
            }
            if !too_large {
                headers.push(field);
            }
        }
        if self.required_reduction.is_some() {
            return Err(hpack_error("missing required table size update"));
        }
        if too_large {
            return Err(ProtoError::HeaderListTooLarge {
                size: list_size,
                max: self.max_header_list_size,
            });
        }
        Ok(headers)
    }
}

fn hpack_error(reason: &str) -> ProtoError {
    ProtoError::Hpack(reason.to_owned())
}

fn entry_size(name: &str, value: &str) -> Option<usize> {
    name.len().checked_add(value.len())?.checked_add(32)
}

fn add_list_size(name: &str, value: &str, total: &mut usize, too_large: &mut bool, maximum: usize) {
    match entry_size(name, value).and_then(|size| total.checked_add(size)) {
        Some(size) => {
            *total = size;
            *too_large |= size > maximum;
        }
        None => {
            *total = usize::MAX;
            *too_large = true;
        }
    }
}

fn encode_integer(mut value: usize, prefix: u32, flags: u8, out: &mut BytesMut) {
    let mask = (1u8 << prefix) - 1;
    if value < usize::from(mask) {
        out.put_u8(flags | value as u8);
        return;
    }
    out.put_u8(flags | mask);
    value -= usize::from(mask);
    while value >= 128 {
        out.put_u8((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.put_u8(value as u8);
}

fn decode_integer(input: &[u8], cursor: &mut usize, prefix: u32) -> Result<usize> {
    let first = *input
        .get(*cursor)
        .ok_or_else(|| hpack_error("truncated integer"))?;
    *cursor += 1;
    let mask = (1u8 << prefix) - 1;
    let mut value = usize::from(first & mask);
    if value < usize::from(mask) {
        return Ok(value);
    }
    let mut shift = 0;
    loop {
        let byte = *input
            .get(*cursor)
            .ok_or_else(|| hpack_error("truncated integer"))?;
        *cursor += 1;
        let part = usize::from(byte & 0x7f);
        if shift >= usize::BITS || part > (usize::MAX >> shift) {
            return Err(hpack_error("integer overflow"));
        }
        value = value
            .checked_add(part << shift)
            .ok_or_else(|| hpack_error("integer overflow"))?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn encode_string(value: &str, out: &mut BytesMut) {
    let encoded_len = huffman_encoded_len(value.as_bytes());
    if encoded_len < value.len() {
        encode_integer(encoded_len, 7, 0x80, out);
        huffman_encode(value.as_bytes(), out);
    } else {
        encode_integer(value.len(), 7, 0, out);
        out.extend_from_slice(value.as_bytes());
    }
}

fn decode_string(input: &[u8], cursor: &mut usize) -> Result<String> {
    let first = *input
        .get(*cursor)
        .ok_or_else(|| hpack_error("missing string length"))?;
    let length = decode_integer(input, cursor, 7)?;
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| hpack_error("string length overflow"))?;
    let bytes = input
        .get(*cursor..end)
        .ok_or_else(|| hpack_error("truncated string"))?;
    *cursor = end;
    let bytes = if first & 0x80 != 0 {
        huffman_decode(bytes)?
    } else {
        bytes.to_vec()
    };
    String::from_utf8(bytes).map_err(|_| hpack_error("string is not UTF-8"))
}
