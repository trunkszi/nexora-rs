//! Thread-local byte views with shared storage and copy-on-write mutation.

use std::{
    fmt,
    hash::{Hash, Hasher},
    ops::{Bound, Deref, DerefMut, RangeBounds},
    rc::Rc,
};

use uarch::prelude::*;

#[uarch::register_pass]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Span {
    pub(crate) start: usize,
    pub(crate) len: usize,
}
assert_layout!(Span, size = 2 * size_of::<usize>(), align = align_of::<usize>(),
    fields = { start: 0, len: size_of::<usize>() });

#[derive(Clone)]
enum Storage {
    Static(&'static [u8]),
    Shared(Rc<Vec<u8>>),
}

impl Storage {
    #[hot_inline]
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Static(bytes) => bytes,
            Self::Shared(bytes) => bytes,
        }
    }
}

/// An immutable contiguous byte view. Clones and slices share their storage.
#[derive(Clone)]
pub struct Bytes {
    storage: Storage,
    span: Span,
}

impl Bytes {
    /// Construct an empty allocation-free view.
    pub const fn new() -> Self {
        Self {
            storage: Storage::Static(&[]),
            span: Span { start: 0, len: 0 },
        }
    }

    /// Borrow static bytes without allocating or copying.
    pub fn from_static(bytes: &'static [u8]) -> Self {
        Self {
            storage: Storage::Static(bytes),
            span: Span {
                start: 0,
                len: bytes.len(),
            },
        }
    }

    /// Copy the supplied bytes into owned storage.
    pub fn copy_from_slice(data: &[u8]) -> Self {
        Self::from(data.to_vec())
    }

    /// Return the number of visible bytes.
    #[hot_inline]
    pub fn len(&self) -> usize {
        self.span.len
    }

    /// Return whether this view contains no bytes.
    #[hot_inline]
    pub fn is_empty(&self) -> bool {
        self.span.len == 0
    }

    /// Borrow the visible bytes.
    #[hot_inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.storage.as_slice()[self.span.start..self.span.start + self.span.len]
    }

    /// Create a view of a subrange without copying its bytes.
    ///
    /// # Panics
    ///
    /// Panics if either endpoint overflows, the range is reversed, or an
    /// endpoint exceeds the visible length.
    pub fn slice(&self, range: impl RangeBounds<usize>) -> Self {
        let start = match range.start_bound() {
            Bound::Included(&start) => start,
            Bound::Excluded(&start) => {
                assert!(start < self.span.len, "slice start exceeds buffer length");
                start + 1
            }
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(&end) => {
                assert!(end < self.span.len, "slice end exceeds buffer length");
                end + 1
            }
            Bound::Excluded(&end) => end,
            Bound::Unbounded => self.span.len,
        };
        assert!(start <= end && end <= self.span.len, "invalid slice range");
        Self {
            storage: self.storage.clone(),
            span: Span {
                start: self.span.start + start,
                len: end - start,
            },
        }
    }

    /// Remove and return the prefix without copying its bytes.
    ///
    /// # Panics
    ///
    /// Panics if `at` exceeds the visible length, leaving this view unchanged.
    #[hot_inline]
    pub fn split_to(&mut self, at: usize) -> Self {
        assert!(at <= self.span.len, "split index exceeds buffer length");
        let prefix = self.slice(..at);
        self.span.start += at;
        self.span.len -= at;
        prefix
    }

    /// Remove and return the suffix without copying its bytes.
    ///
    /// # Panics
    ///
    /// Panics if `at` exceeds the visible length, leaving this view unchanged.
    #[hot_inline]
    pub fn split_off(&mut self, at: usize) -> Self {
        assert!(at <= self.span.len, "split index exceeds buffer length");
        let suffix = self.slice(at..);
        self.span.len = at;
        suffix
    }

    /// Release the backing storage and become an empty view.
    #[hot_inline]
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

impl Default for Bytes {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Bytes").field(&self.as_slice()).finish()
    }
}

impl PartialEq for Bytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Bytes {}

impl Hash for Bytes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl AsRef<[u8]> for Bytes {
    #[hot_inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Deref for Bytes {
    type Target = [u8];

    #[hot_inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl From<&[u8]> for Bytes {
    fn from(bytes: &[u8]) -> Self {
        Self::copy_from_slice(bytes)
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        Self {
            storage: Storage::Shared(Rc::new(bytes)),
            span: Span { start: 0, len },
        }
    }
}

impl From<&str> for Bytes {
    fn from(value: &str) -> Self {
        Self::copy_from_slice(value.as_bytes())
    }
}

impl From<String> for Bytes {
    fn from(value: String) -> Self {
        Self::from(value.into_bytes())
    }
}

/// A mutable byte view whose splits share storage until a view is mutated.
///
/// Splitting and freezing never copy bytes. A write detaches shared storage;
/// exclusively owned views reuse their allocation and compact consumed bytes
/// only when tail capacity is insufficient.
#[derive(Clone)]
pub struct BytesMut {
    storage: Rc<Vec<u8>>,
    span: Span,
}

impl BytesMut {
    /// Construct an empty buffer with the default 4096-byte capacity.
    pub fn new() -> Self {
        Self::with_capacity(4096)
    }

    /// Construct an empty buffer with at least `capacity` writable bytes.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` exceeds `isize::MAX`.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            storage: Rc::new(Vec::with_capacity(capacity)),
            span: Span { start: 0, len: 0 },
        }
    }

    /// Return the number of visible bytes.
    #[hot_inline]
    pub fn len(&self) -> usize {
        self.span.len
    }

    /// Return whether this view contains no bytes.
    #[hot_inline]
    pub fn is_empty(&self) -> bool {
        self.span.len == 0
    }

    /// Return the capacity available from the current view's starting offset.
    ///
    /// Mutating a shared view may allocate an independent buffer of this capacity.
    #[hot_inline]
    pub fn capacity(&self) -> usize {
        self.storage.capacity() - self.span.start
    }

    /// Remove all visible bytes while retaining the allocation.
    #[hot_inline]
    pub fn clear(&mut self) {
        self.span.start = 0;
        self.span.len = 0;
    }

    /// Ensure room for at least `additional` bytes beyond the visible length.
    ///
    /// # Panics
    ///
    /// Panics if the requested length exceeds `isize::MAX`.
    #[hot_inline]
    pub fn reserve(&mut self, additional: usize) {
        self.make_writable(additional);
    }

    /// Resize the visible bytes, filling any new bytes with `value`.
    ///
    /// # Panics
    ///
    /// Panics if `new_len` exceeds `isize::MAX`.
    #[hot_inline]
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.make_writable(new_len.saturating_sub(self.span.len));
        Rc::make_mut(&mut self.storage).resize(self.span.start + new_len, value);
        self.span.len = new_len;
    }

    /// Append the supplied bytes.
    ///
    /// # Panics
    ///
    /// Panics if the resulting length exceeds `isize::MAX`.
    #[inline]
    pub fn extend_from_slice(&mut self, extend: &[u8]) {
        self.make_writable(extend.len());
        Rc::make_mut(&mut self.storage).extend_from_slice(extend);
        self.span.len += extend.len();
    }

    /// Append an unsigned 8-bit integer.
    ///
    /// # Panics
    ///
    /// Panics if the resulting length exceeds `isize::MAX`.
    #[inline]
    pub fn put_u8(&mut self, n: u8) {
        self.extend_from_slice(&[n]);
    }

    /// Append an unsigned 16-bit integer in network byte order.
    ///
    /// # Panics
    ///
    /// Panics if the resulting length exceeds `isize::MAX`.
    #[inline]
    pub fn put_u16(&mut self, n: u16) {
        self.extend_from_slice(&n.to_be_bytes());
    }

    /// Append the low 24 bits of `n` in network byte order.
    ///
    /// # Panics
    ///
    /// Panics if the resulting length exceeds `isize::MAX`.
    #[inline]
    pub fn put_u24(&mut self, n: u32) {
        self.extend_from_slice(&n.to_be_bytes()[1..]);
    }

    /// Append an unsigned 32-bit integer in network byte order.
    ///
    /// # Panics
    ///
    /// Panics if the resulting length exceeds `isize::MAX`.
    #[inline]
    pub fn put_u32(&mut self, n: u32) {
        self.extend_from_slice(&n.to_be_bytes());
    }

    /// Append an unsigned 64-bit integer in network byte order.
    ///
    /// # Panics
    ///
    /// Panics if the resulting length exceeds `isize::MAX`.
    #[inline]
    pub fn put_u64(&mut self, n: u64) {
        self.extend_from_slice(&n.to_be_bytes());
    }

    /// Append a byte slice.
    ///
    /// # Panics
    ///
    /// Panics if the resulting length exceeds `isize::MAX`.
    #[inline]
    pub fn put_slice(&mut self, src: &[u8]) {
        self.extend_from_slice(src);
    }

    /// Consume `cnt` bytes from the front without copying.
    ///
    /// # Panics
    ///
    /// Panics if `cnt` exceeds the visible length, leaving this view unchanged.
    #[hot_inline]
    pub fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.span.len, "advance count exceeds buffer length");
        self.span.start += cnt;
        self.span.len -= cnt;
    }

    /// Remove and return a shared prefix without copying bytes.
    ///
    /// # Panics
    ///
    /// Panics if `at` exceeds the visible length, leaving this view unchanged.
    #[inline]
    pub fn split_to(&mut self, at: usize) -> Self {
        assert!(at <= self.span.len, "split index exceeds buffer length");
        let prefix = Self {
            storage: Rc::clone(&self.storage),
            span: Span {
                start: self.span.start,
                len: at,
            },
        };
        self.span.start += at;
        self.span.len -= at;
        prefix
    }

    /// Remove and return all visible bytes without copying them.
    #[hot_inline]
    pub fn split(&mut self) -> Self {
        self.split_to(self.span.len)
    }

    /// Convert this view to immutable bytes without copying or reallocating.
    #[hot_inline]
    pub fn freeze(self) -> Bytes {
        Bytes {
            storage: Storage::Shared(self.storage),
            span: Span {
                start: self.span.start,
                len: self.span.len,
            },
        }
    }

    /// Borrow the visible bytes.
    #[hot_inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.storage[self.span.start..self.span.start + self.span.len]
    }

    /// Borrow the visible bytes for mutation, detaching shared storage first.
    #[hot_inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.make_writable(0);
        &mut Rc::make_mut(&mut self.storage)[self.span.start..self.span.start + self.span.len]
    }

    #[inline]
    fn make_writable(&mut self, additional: usize) {
        assert!(
            additional <= (isize::MAX as usize) - self.span.len,
            "buffer capacity overflow"
        );
        let required = self.span.len + additional;
        if Rc::get_mut(&mut self.storage).is_none() {
            let mut storage = Vec::with_capacity(self.capacity().max(required));
            storage.extend_from_slice(self.as_slice());
            self.storage = Rc::new(storage);
            self.span.start = 0;
        }
        let storage = Rc::make_mut(&mut self.storage);
        storage.truncate(self.span.start + self.span.len);
        if storage.capacity() - self.span.start < required {
            storage.copy_within(self.span.start..self.span.start + self.span.len, 0);
            storage.truncate(self.span.len);
            self.span.start = 0;
            storage.reserve(additional);
        }
    }
}

impl Default for BytesMut {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for BytesMut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BytesMut").field(&self.as_slice()).finish()
    }
}

impl PartialEq for BytesMut {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for BytesMut {}

impl AsRef<[u8]> for BytesMut {
    #[hot_inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for BytesMut {
    #[hot_inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl Deref for BytesMut {
    type Target = [u8];

    #[hot_inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for BytesMut {
    #[hot_inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}
