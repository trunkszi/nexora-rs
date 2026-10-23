//! Reentrant command delivery through the public inbox.

use std::{cell::Cell, net::SocketAddr, rc::Rc, time::Duration};

use nexora::{
    Error, Result,
    inbox::*,
    proto::{Request, Response, WebSocketMessage},
};

fn request() -> Result<Request> {
    Request::get("http://example.test/").map_err(Error::from)
}

#[test]
fn identifiers_advance_monotonically_across_handles() -> Result<()> {
    let inbox = SubsystemInbox::new();
    let mut first = inbox.context();
    let mut second = inbox.context();
    let requests = [
        inbox.next_request_id().raw(),
        first.submit(request()?, |_ctx, _id, _result| {})?.raw(),
        second.submit(request()?, |_ctx, _id, _result| {})?.raw(),
        inbox.next_request_id().raw(),
    ];
    assert!(requests.windows(2).all(|pair| pair[1] == pair[0] + 1));
    let first_timer = inbox.next_timer_id().raw();
    let second_timer = second.set_timer(Duration::ZERO, |_ctx, _id| {}).raw();
    assert_eq!(second_timer, first_timer + 1);
    let first_websocket = inbox.next_websocket_session_id().raw();
    let second_websocket = inbox.next_websocket_session_id().raw();
    assert_eq!(second_websocket, first_websocket + 1);
    assert!(second_websocket < (1u64 << 52));
    Ok(())
}

#[test]
fn context_stages_commands_in_submission_order() -> Result<()> {
    let inbox = SubsystemInbox::new();
    let mut context = inbox.context();
    let request_id = context.submit(request()?, |_ctx, _id, _result| {})?;
    context.cancel(request_id);
    let timer_id = context.set_timer(Duration::from_millis(5), |_ctx, _id| {});
    let session_id = WebSocketSessionId::new(3);
    context.websocket_send(session_id, WebSocketMessage::Text(String::from("hello")));
    context.websocket_close(session_id, None);
    assert_eq!(inbox.len(), 5);
    assert!(matches!(
        inbox.pop(),
        Some(InboxCommand::Submit(command)) if command.request_id == request_id
    ));
    assert!(matches!(inbox.pop(), Some(InboxCommand::Cancel(id)) if id == request_id));
    assert!(matches!(
        inbox.pop(),
        Some(InboxCommand::SetTimer(command)) if command.timer_id == timer_id
    ));
    assert!(matches!(
        inbox.pop(),
        Some(InboxCommand::WebSocketSend { session_id: id, .. }) if id == session_id
    ));
    assert!(matches!(
        inbox.pop(),
        Some(InboxCommand::WebSocketClose { session_id: id, .. }) if id == session_id
    ));
    assert!(inbox.is_empty());
    Ok(())
}

#[test]
fn callbacks_stage_follow_up_commands_without_reentering_the_queue() -> Result<()> {
    let inbox = SubsystemInbox::new();
    let mut context = inbox.context();
    let request_id = context.submit(request()?, |ctx, id, _result| ctx.cancel(id))?;
    let command = match inbox.pop() {
        Some(InboxCommand::Submit(command)) => command,
        other => {
            assert!(other.is_none(), "expected exactly one staged submission");
            return Ok(());
        }
    };
    let mut callback_context = inbox.context();
    (command.callback)(
        &mut callback_context,
        command.request_id,
        Ok(Response::ok("ok")),
    );
    assert!(matches!(inbox.pop(), Some(InboxCommand::Cancel(id)) if id == request_id));
    assert!(inbox.is_empty());
    Ok(())
}

#[test]
fn dropping_the_last_handle_cancels_staged_submissions() -> Result<()> {
    let calls = Rc::new(Cell::new(0));
    let cancelled = Rc::new(Cell::new(false));
    {
        let inbox = SubsystemInbox::new();
        let mut context = inbox.context();
        let calls = Rc::clone(&calls);
        let cancelled = Rc::clone(&cancelled);
        let _request_id = context.submit(request()?, move |_ctx, _id, result| {
            calls.set(calls.get() + 1);
            cancelled.set(matches!(result, Err(Error::Cancelled)));
        })?;
    }
    assert_eq!(calls.get(), 1);
    assert!(cancelled.get());
    Ok(())
}

#[test]
fn dns_and_deferred_responses_keep_their_payload() -> Result<()> {
    let inbox = SubsystemInbox::new();
    let address = SocketAddr::from(([192, 0, 2, 1], 443));
    inbox.dns_resolved(DnsResolution::success(
        "example.test",
        443,
        AddressFamily::Ipv4,
        vec![address],
        Duration::from_secs(30),
    ));
    inbox.defer_response(DeferredResponse::new(9, Some(3), Response::ok("reply")));
    let resolution = match inbox.pop() {
        Some(InboxCommand::DnsResolved(resolution)) => resolution,
        other => {
            assert!(other.is_none(), "expected exactly one DNS outcome");
            return Ok(());
        }
    };
    assert_eq!(resolution.host, "example.test");
    assert_eq!(resolution.port, 443);
    assert_eq!(resolution.family, AddressFamily::Ipv4);
    assert_eq!(resolution.addrs, vec![address]);
    assert_eq!(resolution.ttl, Duration::from_secs(30));
    assert!(resolution.error.is_none());
    assert!(resolution.is_usable());
    assert!(
        matches!(inbox.pop(), Some(InboxCommand::Respond(reply)) if reply.connection_id == 9 && reply.stream_id == Some(3))
    );
    assert!(inbox.is_empty());
    Ok(())
}
