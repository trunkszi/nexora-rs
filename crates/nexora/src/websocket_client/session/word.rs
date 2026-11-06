use super::*;

bitword! {
    pub(in crate::websocket_client) struct WsSessionWord(u32) {
        [0..=3] pub PHASE: u8,
        [4..=5] pub DNS_LEFT: u8,
    }
}
assert_layout!(WsSessionWord, size = 4, align = 4);

impl WsSessionWord {
    #[inline]
    pub(in crate::websocket_client) fn phase(self) -> SessionPhase {
        match self.get(Self::PHASE) {
            0 => SessionPhase::Resolving,
            1 => SessionPhase::Connecting,
            2 => SessionPhase::Handshaking,
            3 => SessionPhase::Upgrading,
            4 => SessionPhase::Open,
            5 => SessionPhase::CloseFlush,
            6 => SessionPhase::CloseNotified,
            7 => SessionPhase::Teardown,
            8 => SessionPhase::TeardownNotified,
            9 => SessionPhase::Closed,
            _ => SessionPhase::Closed,
        }
    }
    #[hot_inline]
    pub(in crate::websocket_client) fn set_phase(&mut self, phase: SessionPhase) {
        *self = self.patch(BitPatch::EMPTY.with_field(Self::PHASE, (phase as u64) & 0xf));
    }
    #[hot_inline]
    pub(in crate::websocket_client) fn dns_left(self) -> u8 {
        self.get(Self::DNS_LEFT)
    }
    #[hot_inline]
    pub(in crate::websocket_client) fn set_dns_left(&mut self, count: u8) {
        *self = self.patch(BitPatch::EMPTY.with_field(Self::DNS_LEFT, u64::from(count) & 3));
    }
    pub(in crate::websocket_client) fn begin_teardown(&mut self) {
        let mut phase = self.phase();
        phase.begin_teardown();
        self.set_phase(phase);
    }
    pub(in crate::websocket_client) fn notify_close(&mut self) -> bool {
        let mut phase = self.phase();
        let notify = phase.notify_close();
        self.set_phase(phase);
        notify
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_phases_close_session() {
        for phase in 10..=15 {
            let word = WsSessionWord::new(0x30 | phase);
            assert_eq!(word.phase(), SessionPhase::Closed);
            assert_eq!(word.dns_left(), 3);
        }
    }
}
