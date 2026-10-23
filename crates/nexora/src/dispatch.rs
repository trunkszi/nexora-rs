//! Static routing of caller-owned business state on a shared ring.

use liburing::{Completion, CompletionDispatcher, SubmissionContext, SubsystemId, UringError};

/// A dispatcher declaring the subsystem identities it owns.
pub trait CompletionRoute: CompletionDispatcher {
    /// Reports whether this route owns completions for `subsystem`.
    /// # Errors
    /// This function does not return errors.
    /// # Panics
    /// This function does not panic.
    fn accepts(&self, subsystem: SubsystemId) -> bool;
}

/// Two borrowed routes, composable without allocation or ring-owned handlers.
pub struct CompletionRoutes<'a, A: ?Sized, B: ?Sized> {
    first: &'a mut A,
    second: &'a mut B,
}

impl<'a, A: CompletionRoute + ?Sized, B: CompletionRoute + ?Sized> CompletionRoutes<'a, A, B> {
    /// Borrows two disjoint subsystem owners for one dispatch turn.
    /// # Errors
    /// This function does not return errors.
    /// # Panics
    /// This function does not panic.
    pub fn new(first: &'a mut A, second: &'a mut B) -> Self {
        Self { first, second }
    }
}

impl<A: CompletionRoute + ?Sized, B: CompletionRoute + ?Sized> CompletionDispatcher
    for CompletionRoutes<'_, A, B>
{
    fn dispatch(
        &mut self,
        completion: Completion,
        submissions: &mut SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        let id = completion.operation_id.subsystem_id();
        match (self.first.accepts(id), self.second.accepts(id)) {
            (true, false) => self.first.dispatch(completion, submissions),
            (false, true) => self.second.dispatch(completion, submissions),
            (true, true) => Err(UringError::InvalidConfig("overlapping completion routes")),
            (false, false) => Err(UringError::InvalidSubsystemId(id.raw())),
        }
    }
}

impl<A: CompletionRoute + ?Sized, B: CompletionRoute + ?Sized> CompletionRoute
    for CompletionRoutes<'_, A, B>
{
    fn accepts(&self, subsystem: SubsystemId) -> bool {
        self.first.accepts(subsystem) || self.second.accepts(subsystem)
    }
}

pub(crate) struct RejectForeign;
impl CompletionDispatcher for RejectForeign {
    fn dispatch(
        &mut self,
        completion: Completion,
        _: &mut SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        Err(UringError::InvalidSubsystemId(
            completion.operation_id.subsystem_id().raw(),
        ))
    }
}
