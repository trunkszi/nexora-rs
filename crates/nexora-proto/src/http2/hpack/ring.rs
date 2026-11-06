//! Newest-first HPACK entries in a power-of-two ring.

use std::num::NonZeroU64;

use uarch::{
    mem::{L1, prefetch_read},
    prelude::*,
};

type Entry = (String, String);

#[derive(Debug)]
pub(super) struct EntryRing {
    slots: Vec<Option<Entry>>,
    head: usize,
    len: usize,
    divisor: FastDivisorU64,
}

impl EntryRing {
    pub(super) fn new() -> Self {
        Self {
            slots: vec![None; PowerOfTwo::<2>::VALUE],
            head: 0,
            len: 0,
            divisor: FastDivisorU64::new(NonZeroU64::new(4).unwrap_or(NonZeroU64::MIN)),
        }
    }

    #[hot_inline]
    pub(super) fn len(&self) -> usize {
        self.len
    }

    #[hot_inline]
    fn physical(&self, index: usize) -> usize {
        self.divisor.rem(self.head as u64 + index as u64) as usize
    }

    #[hot_inline]
    pub(super) fn get(&self, index: usize) -> Option<&Entry> {
        if index >= self.len {
            return None;
        }
        let slot = &self.slots[self.physical(index)];
        prefetch_read::<L1, _>(slot as *const _);
        slot.as_ref()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &Entry> {
        (0..self.len).filter_map(|index| self.get(index))
    }

    pub(super) fn push_front(&mut self, entry: Entry) {
        if self.len == self.slots.len() {
            self.grow();
        }
        self.head = self.divisor.rem((self.head + self.slots.len() - 1) as u64) as usize;
        self.slots[self.head] = Some(entry);
        self.len += 1;
    }

    pub(super) fn pop_back(&mut self) -> Option<Entry> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        let slot = self.physical(self.len);
        self.slots[slot].take()
    }

    pub(super) fn clear(&mut self) {
        while self.pop_back().is_some() {}
        self.head = 0;
    }

    #[cold_sink]
    fn grow(&mut self) {
        let capacity = self.slots.len() * 2;
        let mut slots = vec![None; capacity];
        for (index, target) in slots[..self.len].iter_mut().enumerate() {
            let source = self.physical(index);
            *target = self.slots[source].take();
        }
        self.slots = slots;
        self.head = 0;
        self.divisor =
            FastDivisorU64::new(NonZeroU64::new(capacity as u64).unwrap_or(NonZeroU64::MIN));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrap_grow_and_clear_preserve_indices() {
        let mut ring = EntryRing::new();
        let mut expected = std::collections::VecDeque::new();
        for index in 0..256 {
            let entry = (index.to_string(), String::new());
            ring.push_front(entry.clone());
            expected.push_front(entry);
            if index % 3 == 0 {
                assert_eq!(ring.pop_back(), expected.pop_back());
            }
            assert_eq!(
                ring.iter().collect::<Vec<_>>(),
                expected.iter().collect::<Vec<_>>()
            );
        }
        ring.clear();
        assert_eq!(ring.len(), 0);
        assert!(ring.get(0).is_none());
        ring.push_front((String::from("reset"), String::new()));
        assert_eq!(ring.get(0).map(|entry| entry.0.as_str()), Some("reset"));
    }
}
