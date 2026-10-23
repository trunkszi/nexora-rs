//! Ordered HTTP header fields with case-insensitive name matching.

use crate::error::{ProtoError, Result};

/// A header name and its unmodified field value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    /// ASCII lowercase header name.
    pub name: String,
    /// Header field value.
    pub value: String,
}

/// Ordered header fields, including repeated fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    fields: Vec<HeaderField>,
}

impl Headers {
    /// Creates an empty header list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a header list with room for `cap` fields.
    ///
    /// # Panics
    /// Panics if the requested allocation exceeds the platform capacity limit.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            fields: Vec::with_capacity(cap),
        }
    }

    /// Replaces all fields with this name, retaining the first field's position.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into().to_ascii_lowercase();
        let value = value.into();
        if let Some(index) = self.fields.iter().position(|field| field.name == name) {
            self.fields[index].value = value;
            let mut position = 0;
            self.fields.retain(|field| {
                let retain = position == index || field.name != name;
                position += 1;
                retain
            });
        } else {
            self.fields.push(HeaderField { name, value });
        }
    }

    /// Appends a field without replacing fields with the same name.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.fields.push(HeaderField {
            name: name.into().to_ascii_lowercase(),
            value: value.into(),
        });
    }

    /// Returns the first value with a case-insensitively matching name.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.name.eq_ignore_ascii_case(name))
            .map(|field| field.value.as_str())
    }

    /// Returns all matching values in insertion order.
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|field| field.name.eq_ignore_ascii_case(name))
            .map(|field| field.value.as_str())
            .collect()
    }

    /// Reports whether at least one matching field exists.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Removes every matching field and returns the first removed value.
    pub fn remove(&mut self, name: &str) -> Option<String> {
        let first = self
            .fields
            .iter()
            .position(|field| field.name.eq_ignore_ascii_case(name))?;
        let value = self.fields.remove(first).value;
        self.fields
            .retain(|field| !field.name.eq_ignore_ascii_case(name));
        Some(value)
    }

    /// Iterates over fields in insertion order.
    pub fn iter(&self) -> std::slice::Iter<'_, HeaderField> {
        self.fields.iter()
    }

    /// Returns the number of fields, including duplicates.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Reports whether the header list is empty.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Removes all fields while retaining the allocated field capacity.
    pub fn clear(&mut self) {
        self.fields.clear();
    }

    /// Returns the aggregate name and value length in bytes.
    pub fn byte_size(&self) -> usize {
        self.fields.iter().fold(0usize, |size, field| {
            size.saturating_add(field.name.len())
                .saturating_add(field.value.len())
        })
    }

    /// Parses a consistent decimal length across all field lines and comma lists.
    ///
    /// # Errors
    /// Returns an invalid-header error for empty, nondecimal, overflowing or
    /// conflicting values. Only HTTP optional whitespace surrounds each value.
    pub fn content_length(&self) -> Result<Option<usize>> {
        let mut length = None;
        for field in &self.fields {
            if !field.name.eq_ignore_ascii_case("content-length") {
                continue;
            }
            for part in field.value.split(',') {
                let part = part.trim_matches([' ', '\t']);
                if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(ProtoError::InvalidHeader("invalid content-length".into()));
                }
                let parsed = part.parse::<usize>().map_err(|_| {
                    ProtoError::InvalidHeader("content-length exceeds addressable size".into())
                })?;
                if length.is_some_and(|previous| previous != parsed) {
                    return Err(ProtoError::InvalidHeader(
                        "conflicting content-length values".into(),
                    ));
                }
                length = Some(parsed);
            }
        }
        Ok(length)
    }

    /// Reports whether the final transfer coding token is `chunked`.
    ///
    /// Transfer codings are combined in field order. A substring, parameterized
    /// token or a coding preceding another coding does not indicate chunk framing.
    pub fn is_chunked(&self) -> bool {
        self.fields
            .iter()
            .filter(|field| field.name.eq_ignore_ascii_case("transfer-encoding"))
            .flat_map(|field| field.value.split(','))
            .next_back()
            .is_some_and(|token| {
                token
                    .trim_matches([' ', '\t'])
                    .eq_ignore_ascii_case("chunked")
            })
    }
}

/// Converts typed header representations to and from an ordered header list.
pub trait HeaderMapExt: Sized {
    /// Converts the typed representation into fields.
    fn to_headers(&self) -> Headers;

    /// Parses typed values from header fields.
    ///
    /// # Errors
    /// Returns an error when required fields are absent or field values are invalid.
    fn from_headers(headers: &Headers) -> Result<Self>;
}
