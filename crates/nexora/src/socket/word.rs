//! Phase and outstanding-operation accounting share one register word.

use uarch::prelude::*;

use super::SocketPhase;

bitword! {
    pub(super) struct SocketWord(u64) {
        [0..=7] pub PHASE: u8,
        [32..=63] pub IN_FLIGHT: u32,
    }
}

impl SocketWord {
    #[inline]
    pub(super) const fn phase(self) -> SocketPhase {
        match self.get(Self::PHASE) {
            0 => SocketPhase::Idle,
            1 => SocketPhase::Connecting,
            2 => SocketPhase::Connected,
            3 => SocketPhase::Cancelling,
            4 => SocketPhase::CancelRequested,
            5 => SocketPhase::CloseReady,
            6 => SocketPhase::CloseQueued,
            7 => SocketPhase::CloseSubmitted,
            8 => SocketPhase::Closed,
            _ => SocketPhase::Closed,
        }
    }

    #[hot_inline]
    pub(super) fn set_phase(&mut self, phase: SocketPhase) {
        *self = self.patch(Self::PHASE.patch(phase as u8));
    }

    #[hot_inline]
    pub(super) const fn count(self) -> usize {
        self.get(Self::IN_FLIGHT) as usize
    }

    #[inline]
    pub(super) fn start(&mut self) -> bool {
        if self.get(Self::IN_FLIGHT) == u32::MAX {
            return false;
        }
        *self = self.wrapping_add_top_field(Self::IN_FLIGHT, 1);
        true
    }

    #[inline]
    pub(super) fn retire(&mut self) -> bool {
        if self.count() == 0 {
            return false;
        }
        *self = self.wrapping_add_top_field(Self::IN_FLIGHT, u64::MAX);
        true
    }
}

#[cfg(test)]
mod lifecycle_scenario {
    use super::*;

    #[test]
    fn operation_count_preserves_close_phase() {
        let mut word = SocketWord::new(0);
        word.set_phase(SocketPhase::CancelRequested);
        for count in 1..=65 {
            assert!(word.start());
            assert_eq!(word.count(), count);
            assert_eq!(word.phase(), SocketPhase::CancelRequested);
        }
        for count in (0..65).rev() {
            assert!(word.retire());
            assert_eq!(word.count(), count);
            assert_eq!(word.phase(), SocketPhase::CancelRequested);
        }
        let empty = word.raw();
        assert!(!word.retire());
        assert_eq!(word.raw(), empty);
        word = word.patch(patch!(SocketWord {
            IN_FLIGHT: 0xffff_ffff
        }));
        let full = word.raw();
        assert!(!word.start());
        assert_eq!(word.raw(), full);
        word.set_phase(SocketPhase::CloseSubmitted);
        assert_eq!(word.count(), u32::MAX as usize);
        assert!(word.retire());
        assert_eq!(word.count(), (u32::MAX - 1) as usize);
        assert_eq!(word.phase(), SocketPhase::CloseSubmitted);
    }
    #[test]
    fn unknown_phase_is_closed() {
        for raw in 9..=255 {
            assert_eq!(SocketWord::new(raw).phase(), SocketPhase::Closed);
        }
    }
}
