use std::{
    cell::{Cell, UnsafeCell},
    collections::VecDeque,
};

use uarch::{
    layout::Isolated,
    mem::{L1, prefetch_read},
};

use super::*;

bitword! {
    struct InboxStateWord(u32) {
        [0] pub OPEN, [1] pub CLOSED, [2] pub WAKING, [3] pub DRAINING,
    }
}
assert_layout!(InboxStateWord, size = 4, align = 4);
assert_layout!(
    Isolated<UnsafeCell<VecDeque<InboxCommand>>>,
    size = 128,
    align = 128
);

/// State shared by every handle for one inbox.
pub(super) struct InboxShared {
    /// Commands staged for the drive loop, in staging order.
    commands: Isolated<UnsafeCell<VecDeque<InboxCommand>>>,
    state: Cell<InboxStateWord>,
    /// Last request identifier handed out.
    pub(super) next_request_id: Cell<u64>,
    /// Last timer identifier handed out.
    pub(super) next_timer_id: Cell<u64>,
    /// Last WebSocket session identifier handed out.
    pub(super) next_websocket_session_id: Cell<u64>,
}

impl InboxShared {
    #[hot_inline]
    pub(super) fn is_closed(&self) -> bool {
        !self
            .state
            .get()
            .matches(pattern!(InboxStateWord { OPEN & !CLOSED & !DRAINING }))
    }
    #[cold_sink]
    pub(super) fn begin_drain(&self) {
        self.state
            .set(self.state.get().patch(patch!(InboxStateWord {
                OPEN: false,
                CLOSED: true,
                DRAINING: true
            })));
    }

    /// Creates an empty shared state with all counters at zero.
    pub(super) fn new() -> Self {
        Self {
            commands: Isolated::new(UnsafeCell::new(VecDeque::new())),
            state: Cell::new(
                InboxStateWord::default().patch(patch!(InboxStateWord { OPEN: true })),
            ),
            next_request_id: Cell::new(0),
            next_timer_id: Cell::new(0),
            next_websocket_session_id: Cell::new(0),
        }
    }

    /// Advances `counter` and returns its new value; the first value is one.
    pub(super) fn advance(counter: &Cell<u64>) -> u64 {
        let next = counter.get().wrapping_add(1);
        counter.set(next);
        next
    }

    /// Stages a command unless the queue has begun draining.
    #[inline]
    pub(super) fn push(&self, command: InboxCommand) {
        if self.is_closed() {
            return;
        }
        // SAFETY: Every handle is `!Send + !Sync` through `Rc` and
        // `PhantomData<*mut ()>`, so this queue is reachable only from the
        // thread that owns the handles. This borrow ends before the function
        // returns, no user code runs while it is live, and no other borrow can
        // overlap it.
        unsafe { &mut *self.commands.value.get() }.push_back(command);
        self.state.set(
            self.state
                .get()
                .patch(patch!(InboxStateWord { WAKING: true })),
        );
    }

    /// Removes the oldest staged command.
    #[inline]
    pub(super) fn pop(&self) -> Option<InboxCommand> {
        // SAFETY: Every handle is `!Send + !Sync` through `Rc` and
        // `PhantomData<*mut ()>`, so this queue is reachable only from the
        // thread that owns the handles. The command moves out before this
        // borrow ends and no other borrow can overlap it.
        let queue = unsafe { &mut *self.commands.value.get() };
        if let Some(next) = queue.get(1) {
            prefetch_read::<L1, _>(next as *const _);
        }
        let command = queue.pop_front();
        self.state.set(
            self.state
                .get()
                .patch(BitPatch::EMPTY.with_flag(InboxStateWord::WAKING, !queue.is_empty())),
        );
        command
    }

    /// Returns the number of staged commands.
    #[hot_inline]
    pub(super) fn len(&self) -> usize {
        // SAFETY: Every handle is `!Send + !Sync` through `Rc` and
        // `PhantomData<*mut ()>`, so this queue is reachable only from the
        // thread that owns the handles. This borrow ends before the function
        // returns and no other borrow can overlap it.
        unsafe { &*self.commands.value.get() }.len()
    }

    /// Reports whether no command is staged.
    #[hot_inline]
    pub(super) fn is_empty(&self) -> bool {
        !self.state.get().test(InboxStateWord::WAKING)
    }
}
