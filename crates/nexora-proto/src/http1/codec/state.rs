//! Direction guards and the current message's framing share one scalar word.
use uarch::prelude::*;

use super::{Framing, Headers, Http1KeepAlive, has_token};

bitword! {
    pub(super) struct Http1StateWord(u32) {
        [0] pub ENCODE_CLOSED,
        [1] pub DECODE_CLOSED,
        [2] pub CHUNKED,
        [3] pub KEEP_ALIVE,
        [4] pub CONTENT_LENGTH_PRESENT,
        [5] pub UPGRADE,
        [6] pub EXPECT_CONTINUE,
        [7] pub HEAD_RESPONSE,
        [8..=9] pub PHASE: u8,
    }
}
assert_layout!(Http1StateWord, size = 4, align = 4);

impl Http1StateWord {
    #[hot_inline]
    pub(super) fn persistence(self) -> Http1KeepAlive {
        if self.test(Self::UPGRADE) {
            Http1KeepAlive::Upgrade
        } else if self.test(Self::KEEP_ALIVE) {
            Http1KeepAlive::KeepAlive
        } else {
            Http1KeepAlive::Close
        }
    }

    #[hot_inline]
    pub(super) fn encode_closed(self) -> bool {
        self.test(Self::ENCODE_CLOSED)
    }
    #[hot_inline]
    pub(super) fn decode_closed(self) -> bool {
        self.test(Self::DECODE_CLOSED)
    }
    #[hot_inline]
    pub(super) fn either_closed(self) -> bool {
        !self.matches(pattern!(Http1StateWord { !ENCODE_CLOSED & !DECODE_CLOSED }))
    }
    #[hot_inline]
    pub(super) fn close_encode(&mut self, closed: bool) {
        *self = self.patch(BitPatch::EMPTY.with_flag(Self::ENCODE_CLOSED, closed));
    }
    #[hot_inline]
    pub(super) fn close_decode(&mut self, closed: bool) {
        *self = self.patch(BitPatch::EMPTY.with_flag(Self::DECODE_CLOSED, closed));
    }
    pub(super) fn message(
        &mut self,
        headers: &Headers,
        framing: Framing,
        keep: Http1KeepAlive,
        head: bool,
    ) {
        *self = self.patch(
            BitPatch::EMPTY
                .with_flag(Self::CHUNKED, matches!(framing, Framing::Chunked))
                .with_flag(Self::KEEP_ALIVE, keep == Http1KeepAlive::KeepAlive)
                .with_flag(
                    Self::CONTENT_LENGTH_PRESENT,
                    matches!(framing, Framing::Length(_)),
                )
                .with_flag(Self::UPGRADE, keep == Http1KeepAlive::Upgrade)
                .with_flag(
                    Self::EXPECT_CONTINUE,
                    has_token(headers, "expect", "100-continue"),
                )
                .with_flag(Self::HEAD_RESPONSE, head),
        );
        *self = self.patch(patch!(Http1StateWord { PHASE: 2 }));
    }
}
