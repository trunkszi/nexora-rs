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
#[derive(Debug, Clone, Default)]
pub struct Headers {
    fields: Vec<HeaderField>,
    // Tiny lists scan directly; larger lists keep collision-checked name hashes.
    hashes: Vec<u64>,
}

impl PartialEq for Headers {
    fn eq(&self, other: &Self) -> bool {
        self.fields == other.fields
    }
}
impl Eq for Headers {}

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
            hashes: Vec::with_capacity(if cap > 4 { cap } else { 0 }),
        }
    }

    /// Replaces all fields with this name, retaining the first field's position.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let mut name = name.into();
        name.make_ascii_lowercase();
        let value = value.into();
        let hash = if self.hashes.is_empty() {
            0
        } else {
            name_hash(&name)
        };
        let index = if self.hashes.is_empty() {
            self.fields.iter().position(|field| field.name == name)
        } else {
            self.hashes
                .iter()
                .zip(&self.fields)
                .position(|(tag, field)| *tag == hash && field.name == name)
        };
        if let Some(index) = index {
            self.fields[index].value = value;
            if index + 1 == self.fields.len()
                || (!self.hashes.is_empty() && !self.hashes[index + 1..].contains(&hash))
            {
                return;
            }
            let mut position = 0;
            if !self.hashes.is_empty() {
                self.hashes.retain(|tag| {
                    let keep =
                        position == index || *tag != hash || self.fields[position].name != name;
                    position += 1;
                    keep
                });
            }
            let mut position = 0;
            self.fields.retain(|field| {
                let retain = position == index || field.name != name;
                position += 1;
                retain
            });
        } else {
            self.fields.push(HeaderField { name, value });
            self.index_last();
        }
    }

    /// Appends a field without replacing fields with the same name.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let mut name = name.into();
        name.make_ascii_lowercase();
        self.fields.push(HeaderField {
            name,
            value: value.into(),
        });
        self.index_last();
    }

    fn index_last(&mut self) {
        if !self.hashes.is_empty() {
            self.hashes
                .push(name_hash(&self.fields[self.fields.len() - 1].name));
        } else if self.fields.len() > 4 {
            self.hashes
                .extend(self.fields.iter().map(|field| name_hash(&field.name)));
        }
    }

    /// Returns the first value with a case-insensitively matching name.
    pub fn get(&self, name: &str) -> Option<&str> {
        if self.hashes.is_empty() {
            return self
                .fields
                .iter()
                .find(|field| field.name.eq_ignore_ascii_case(name))
                .map(|field| field.value.as_str());
        }
        let hash = name_hash(name);
        self.hashes
            .iter()
            .zip(&self.fields)
            .find(|(tag, field)| **tag == hash && field.name.eq_ignore_ascii_case(name))
            .map(|(_, field)| field.value.as_str())
    }

    /// Returns all matching values in insertion order.
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        if self.hashes.is_empty() {
            return self
                .fields
                .iter()
                .filter(|field| field.name.eq_ignore_ascii_case(name))
                .map(|field| field.value.as_str())
                .collect();
        }
        let hash = name_hash(name);
        self.hashes
            .iter()
            .zip(&self.fields)
            .filter(|(tag, field)| **tag == hash && field.name.eq_ignore_ascii_case(name))
            .map(|(_, field)| field.value.as_str())
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
        let indexed = !self.hashes.is_empty();
        if indexed {
            self.hashes.remove(first);
        }
        let value = self.fields.remove(first).value;
        let mut position = 0;
        if indexed {
            self.hashes.retain(|_| {
                let keep = !self.fields[position].name.eq_ignore_ascii_case(name);
                position += 1;
                keep
            });
        }
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
        self.hashes.clear();
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

// Names are ASCII-folded in the hash; equality still checks collisions and
// preserves the public ordered-field representation.
fn name_hash(name: &str) -> u64 {
    name.bytes().fold(0xcbf29ce484222325, |hash, byte| {
        (hash ^ u64::from(byte.to_ascii_lowercase())).wrapping_mul(0x100000001b3)
    })
}

#[cfg(test)]
mod mutation_scenarios {
    use super::Headers;

    #[test]
    fn indexed_duplicates_preserve_order() {
        let mut headers = Headers::new();
        headers.append("X-Topic", "first");
        for index in 0..12 {
            headers.append(format!("x-key-{index}"), "value");
        }
        headers.append("x-TOPIC", "second");
        headers.insert("X-TOPIC", "replacement");
        assert_eq!(headers.len(), 13);
        assert_eq!(
            headers.iter().next().map(|field| field.value.as_str()),
            Some("replacement")
        );
        assert_eq!(headers.get_all("X-Topic"), ["replacement"]);
        assert_eq!(headers.remove("X-key-6").as_deref(), Some("value"));
        assert_eq!(headers.get("x-key-7"), Some("value"));
        assert_eq!(headers.remove("X-TOPIC").as_deref(), Some("replacement"));
        assert_eq!(headers.get("x-topic"), None);
        headers.clear();
        headers.append("HOST", "example.com");
        assert_eq!(headers.get("Host"), Some("example.com"));
        assert_eq!(headers.len(), 1);
    }
}

#[cfg(test)]
mod equality_scenarios {
    use super::Headers;
    #[test]
    fn equality_ignores_index_history() {
        let mut previous = Headers::new();
        previous.append("host", "example.com");
        for index in 0..8 {
            previous.append(format!("x-key-{index}"), "value");
        }
        for index in 0..8 {
            assert_eq!(
                previous.remove(&format!("x-key-{index}")).as_deref(),
                Some("value")
            );
        }
        let mut fresh = Headers::new();
        fresh.append("HOST", "example.com");
        assert_eq!(previous, fresh);
    }
}
