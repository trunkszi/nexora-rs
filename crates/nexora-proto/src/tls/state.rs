use uarch::prelude::*;

bitword! {
 pub(super) struct TlsStateWord(u32) {
  [0] pub PEER_CLOSED,
  [1] pub LOCAL_CLOSED,
  [2] pub CLOSE_SENT,
 }
}
assert_layout!(TlsStateWord, size = 4, align = 4);
impl TlsStateWord {
    #[hot_inline]
    pub(super) fn close_sent(self) -> bool {
        self.test(Self::CLOSE_SENT)
    }
    #[hot_inline]
    pub(super) fn set_close_sent(&mut self, value: bool) {
        *self = self.patch(BitPatch::EMPTY.with_flag(Self::CLOSE_SENT, value));
    }

    #[hot_inline]
    pub(super) fn peer_closed(self) -> bool {
        self.test(Self::PEER_CLOSED)
    }
    #[hot_inline]
    pub(super) fn set_peer_closed(&mut self, value: bool) {
        *self = self.patch(BitPatch::EMPTY.with_flag(Self::PEER_CLOSED, value));
    }
    #[hot_inline]
    pub(super) fn local_closed(self) -> bool {
        self.test(Self::LOCAL_CLOSED)
    }
    #[hot_inline]
    pub(super) fn set_local_closed(&mut self, value: bool) {
        *self = self.patch(BitPatch::EMPTY.with_flag(Self::LOCAL_CLOSED, value));
    }
}
