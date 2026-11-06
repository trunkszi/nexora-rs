use uarch::prelude::*;

bitword! {
 pub(crate) struct ServerIoWord(u32) {
  [0] pub RECV_ON,
  [1] pub SEND_ON,
  [2] pub CLOSE_ON,
  [3] pub CLOSE_PENDING,
  [4] pub HTTP_CLOSE,
  [5] pub ACCEPT_ON,
  [6] pub SHUTTING_DOWN,
 }
}
assert_layout!(ServerIoWord, size = 4, align = 4);
impl ServerIoWord {
    #[hot_inline]
    pub(crate) fn busy(self) -> bool {
        !self.matches(pattern!(ServerIoWord { !RECV_ON & !SEND_ON & !CLOSE_ON }))
    }

    #[hot_inline]
    pub(crate) fn recv_on(self) -> bool {
        self.test(Self::RECV_ON)
    }
    #[hot_inline]
    pub(crate) fn set_recv_on(&mut self, value: bool) {
        *self = self.patch(BitPatch::EMPTY.with_flag(Self::RECV_ON, value));
    }
    #[hot_inline]
    pub(crate) fn send_on(self) -> bool {
        self.test(Self::SEND_ON)
    }
    #[hot_inline]
    pub(crate) fn set_send_on(&mut self, value: bool) {
        *self = self.patch(BitPatch::EMPTY.with_flag(Self::SEND_ON, value));
    }
    #[hot_inline]
    pub(crate) fn close_on(self) -> bool {
        self.test(Self::CLOSE_ON)
    }
    #[hot_inline]
    pub(crate) fn set_close_on(&mut self, value: bool) {
        *self = self.patch(BitPatch::EMPTY.with_flag(Self::CLOSE_ON, value));
    }
    #[hot_inline]
    pub(crate) fn close_pending(self) -> bool {
        self.test(Self::CLOSE_PENDING)
    }
    #[hot_inline]
    pub(crate) fn set_close_pending(&mut self, value: bool) {
        *self = self.patch(BitPatch::EMPTY.with_flag(Self::CLOSE_PENDING, value));
    }
    #[hot_inline]
    pub(crate) fn http_close(self) -> bool {
        self.test(Self::HTTP_CLOSE)
    }
    #[hot_inline]
    pub(crate) fn set_http_close(&mut self, value: bool) {
        *self = self.patch(BitPatch::EMPTY.with_flag(Self::HTTP_CLOSE, value));
    }
    #[hot_inline]
    pub(crate) fn accept_on(self) -> bool {
        self.test(Self::ACCEPT_ON)
    }
    #[hot_inline]
    pub(crate) fn set_accept_on(&mut self, value: bool) {
        *self = self.patch(BitPatch::EMPTY.with_flag(Self::ACCEPT_ON, value));
    }
    #[hot_inline]
    pub(crate) fn shutting_down(self) -> bool {
        self.test(Self::SHUTTING_DOWN)
    }
    #[hot_inline]
    pub(crate) fn set_shutting_down(&mut self, value: bool) {
        *self = self.patch(BitPatch::EMPTY.with_flag(Self::SHUTTING_DOWN, value));
    }
}
