This file is the authoritative operational contract for coding agents (OpenAI Codex, Claude Code, Gemini CLI) working in nexora-rs.

## Project Overview

Nexora is a Rust 2024 HTTP/1.1, HTTP/2, WebSocket, and TLS library with three
layers: Sans-IO protocols, procedural macros, and a completion-driven SDK.
Keep protocol parsing independent of operating-system I/O and application routing.

Drive networking through `liburing::Proactor` and hostname resolution through
`cares::ProactorResolver` on the same owning thread. Use a single-threaded
Run-To-Completion model: apply completions, advance explicit state machines,
stage follow-up work, then return control to the caller. Keep runtime handles
`!Send + !Sync`; scale by giving each thread its own proactor and handles.

Use zero asynchronous runtime dependencies and zero `Mutex`, `RwLock`, or
`mpsc` primitives in library execution and callback dispatch. Route re-entrant
actions through the local inbox. Timers and registered completions advance
waiting work without sleeping or blocking the ring-owning thread.

## Workspace Layout

```text
nexora-rs/
|-- Cargo.toml                         # Members, shared dependencies, lints, profiles
|-- Cargo.lock                         # Resolved versions and upstream Git revisions
|-- rust-toolchain.toml                # Pinned toolchain, components, and targets
|-- rustfmt.toml                       # Workspace formatting rules
|-- .cargo/config.toml                 # Serial test-runner default
|-- deny.toml                          # Dependency source, license, and ban policy
|-- AGENTS.md                          # Agent maintenance contract
|-- README.md                          # User-facing architecture and usage
|-- crates/
|   |-- nexora-proto/                  # L1: buffers, HTTP types, and Sans-IO codecs
|   |   |-- src/{bytes,error,uri,headers,tls}.rs
|   |   |-- src/{http1,http2,websocket}/
|   |   +-- tests/                     # In-memory protocol and lifecycle coverage
|   |-- nexora-macros/                 # L2: validated declarations and generated APIs
|   |   |-- src/
|   |   +-- tests/ui/                  # Compile-pass and compile-fail fixtures
|   +-- nexora/                        # L3: shared-ring client and server SDK
|       |-- src/                       # Runtime state machines and public facade
|       |-- examples/                  # Four runnable loopback applications
|       +-- tests/                     # Integration, E2E, lifecycle, and scenarios
+-- .github/
    +-- workflows/ci.yml               # Hosted CI entry point
```

Keep root configuration authoritative. Register crates through the root
workspace; inherit dependencies, package metadata, and workspace lints in members.
Keep local design material under ignored `.scratch/` paths and out of Git.

## Crate Layering & Module Responsibilities

| Layer | Crate or module | Responsibility and dependency boundary |
| --- | --- | --- |
| L1 | `nexora-proto` | Buffers, protocol models, and Sans-IO transformations. Uses neither `liburing` nor `cares`; transport reads, writes, clocks, and scheduling belong to the caller. |
| L1 | `crates/nexora-proto/src/bytes.rs` | Shared byte views, zero-copy splitting and freezing, cursor advancement, growth, and copy-on-write isolation. |
| L1 | `crates/nexora-proto/src/error.rs` | `ProtoError`, `Http2ErrorCode`, and protocol `Result`; preserve named failure causes. |
| L1 | `crates/nexora-proto/src/{uri,headers}.rs` | URI and redirect validation, authority handling, ordered headers, and framing-header interpretation. |
| L1 | `crates/nexora-proto/src/http1/` | HTTP models, bounded incremental framing, content-length/chunked bodies, persistence, and upgrade handoff. |
| L1 | `crates/nexora-proto/src/http2/` | Frames, HPACK/Huffman, settings, stream lifecycle, signed flow-control windows, and pending output. |
| L1 | `crates/nexora-proto/src/tls.rs` | Sans-IO rustls sessions, TLS 1.3, certificate verification, PEM/DER trust, mTLS, ALPN, and close alerts. |
| L1 | `crates/nexora-proto/src/websocket/` | Upgrade validation, masking, fragmentation, UTF-8 checks, control frames, and close-handshake state. |
| L2 | `nexora-macros` | Compile-time validation and expansion. Production dependencies are `syn`, `quote`, and `proc-macro2`. |
| L2 | `crates/nexora-macros/src/{header_map,rest_request}.rs` | Typed header conversion and REST path/query/body construction referencing the consuming application's protocol crate. |
| L2 | `crates/nexora-macros/src/{http_service,websocket_handler,literals}.rs` | Service routing, WebSocket event delegation, and validated `headers!` / `http2_headers!` literals. |
| L3 | `nexora` | Public SDK integrating L1, L2, `liburing`, and `cares`; owns network and application lifecycle. |
| L3 | `crates/nexora/src/lib.rs` | Public facade and re-exports; keep implementation in its responsible module. |
| L3 | `crates/nexora/src/{error,inbox}.rs` | Runtime errors, IDs, callback contexts, and local re-entrant command staging. |
| L3 | `crates/nexora/src/dns.rs` and `dns/cache.rs` | Resolver overrides, dual-stack queries, answer decoding, and flushing; the cache owns TTL expiry and bounded eviction. |
| L3 | `crates/nexora/src/socket.rs` | Descriptor ownership, pinned RX/TX storage, in-flight accounting, cancellation quarantine, and final close. |
| L3 | `crates/nexora/src/pool.rs` | Origin state, waiter coalescing, HTTP/1 connection limits, HTTP/2 admission, and eviction. |
| L3 | `crates/nexora/src/client.rs` | Admission, connect/TLS progress, redirects, deadlines, cancellation, and terminal callbacks. |
| L3 | `crates/nexora/src/server.rs` | Listener registration, protocol demultiplexing, service contexts, deferred responders, and shutdown. |
| L3 | `crates/nexora/src/{websocket_client,websocket_server}.rs` and `websocket_client/session.rs` | Public configuration and session addressing, push, keepalive, and close progression; session storage owns protocol state and retained DMA resources. |

Production submodules group implementation by responsibility and ownership.
Keep standalone test files in each crate's Cargo `tests/` directory. Private
invariant tests stay inline with the implementation they exercise; source
subdirectories contain no `tests.rs` or `*_tests.rs` files.
L1 remains independent of L2 and L3; L2 emits references to L1/L3 at expansion
sites without linking the SDK as a production dependency. Macro dev-dependencies
may exercise real protocol and SDK consumers. Keep generated code compatible
with caller imports, configuration attributes, generics, and normal Rust names.

## Build, Lint, and Test Commands

Run every command from the workspace root. Use the toolchain declared in
`rust-toolchain.toml`; inspect manifests before selecting additional features.

`.cargo/config.toml` defaults `RUST_TEST_THREADS` to `1` so process-wide thread
and descriptor snapshots are isolated from sibling test cases. An explicit
environment value or `-- --test-threads=N` can override this default for a
deliberate parallel run; resource-snapshot results require serial execution.

| Command | Purpose |
| --- | --- |
| `cargo build --workspace` | Build the default workspace configuration. |
| `cargo fmt --all -- --check` | Check formatting without rewriting unrelated files. |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Enforce strict lints across libraries, tests, and examples. |
| `cargo test --workspace --all-targets` | Run workspace unit and integration targets, including example test harnesses. |
| `cargo test --workspace --doc` | Run documentation tests separately. |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked` | Build public documentation with warnings denied. |
| `cargo test -p nexora-proto` | Run focused Sans-IO protocol and documentation tests. |
| `cargo test -p nexora-macros` | Run macro behavior and compile-time diagnostics tests. |
| `cargo test -p nexora --test integration_tests` | Verify protocol, resolver, and runtime integration boundaries. |
| `cargo test -p nexora --test e2e_tests` | Drive complete application request/response and WebSocket exchanges. |
| `cargo test -p nexora --test lifecycle_tests` | Verify cancellation, closure, ownership, and resource release. |
| `cargo test -p nexora --test scenario_tests` | Exercise fragmentation, backpressure, failover, and recovery. |
| `cargo test -p nexora-proto --release` | Verify protocol behavior under the release profile. |
| `cargo run -p nexora --example http1_keepalive_and_cares_dns` | Exercise HTTP/1 persistence and loopback DNS on the shared ring. |
| `cargo run -p nexora --example http2_tls_multiplex_and_cancel` | Exercise TLS HTTP/2 multiplexing and stream cancellation. |
| `cargo run -p nexora --example websocket_echo_and_push_timer` | Exercise WebSocket echo and a timed server push. |
| `cargo run -p nexora --example unified_gateway_server` | Exercise one listener serving HTTP/1, HTTP/2, and WebSocket. |
| `git diff --check` | Check patch whitespace before handoff. |

Runtime tests and examples require Linux with usable io_uring, loopback networking,
and upstream native build prerequisites. Use the CI workflow and upstream build
errors to identify missing tools. Record setup failures as unavailable validation.
Build success or a Sans-IO test does not establish that a real-ring test ran.

GitHub-hosted CI runs full-workspace formatting, Clippy, tests, and strict rustdoc
directly through Cargo. Preserve Cargo's native lockfile format so metadata queries
leave the working tree clean, and review dependency resolution changes.

## Hard Invariants & Runtime Contracts

### Platform, manifests, and source form

- Target Linux x86_64 with Rust edition 2024 and the pinned root toolchain.
- Keep authored source, documentation, and configuration files at or below 800 lines;
  split by responsibility early. The generated `Cargo.lock` is exempt.
- Use English ASCII for source, comments, rustdoc, errors, logs, CLI text, and docs.
- Apply source vocabulary, dependency, ASCII, and file-size rules to every file.
- Declare every dependency as a single-line inline table: `name = { ... }`.
  Put versions and sources in `[workspace.dependencies]`; members inherit them
  with `name = { workspace = true }`, including development and build dependencies.
- Use `sonic-rs` with default features disabled for JSON values and serialization.
  Generated JSON-body code references `sonic_rs` in the consuming crate.
- Source `liburing` from
  `https://github.com/trunkszi/liburing-rs.git` with `branch = "main"`.
  Source `cares` from
  `https://github.com/trunkszi/cares-rs.git` with `branch = "main"`.
- Preserve workspace lint severity, package metadata inheritance, and profiles.
  Keep author metadata consistent with `[workspace.package]` and the license.
- Maintain `deny.toml` source/license rules and the resolved dependency graph.
  Keep executors, readiness-runtime substitutes, and thread-based resolvers out
  of dependencies; use the existing proactor and resolver integration instead.

### Thread affinity and byte storage

- Keep runtime handles and their mutable state `!Send + !Sync` on their creator
  thread. Preserve that property in new wrappers, callbacks, and session handles.
- Use zero `Mutex`, `RwLock`, or `mpsc` primitives for library ownership and
  dispatch. Coordinate local work with explicit state and inbox commands.
- Use `Rc<Vec<u8>>` for shared heap backing in `Bytes` and `BytesMut`; static
  immutable slices may remain borrowed. Preserve cheap clones and zero-copy
  slicing, splitting, and freezing. Detach shared storage before mutation.
- Keep cursor bounds, capacity growth, and view isolation valid after clear,
  advance, split, freeze, and owner drop. Check invalid ranges before mutation.
- Keep mock-peer threads and their coordination inside test infrastructure;
  their implementation does not authorize synchronization in library paths.

### Re-entrant inbox delivery

- Stage callback-originated actions in `SubsystemInbox` using its local shared
  queue and short `UnsafeCell` accesses. Keep delivery free of `RefCell` borrows.
- Move a command out and release queue access before invoking user code.
  A callback may submit, cancel, arm a timer, or address another session without
  recreating a mutable reference to the active client, server, or proactor.
- Document allocator re-entry restrictions wherever inbox growth can allocate.
  Preserve deterministic command ordering and explicit shutdown handling.

### SocketEntry lifecycle and DMA isolation

- Maintain the socket-entry ownership contract
  `SocketEntry: Active -> Cancelling -> Closing -> Closed`.
  The current transport wrapper is `IoUringSocket`; map its Idle, Connecting,
  and Connected states into the active part of this lifecycle.
- Keep RX/TX allocations pinned while any submitted operation can reference them.
  Retain the descriptor, buffers, and retirement record across both the cancel
  CQE and the target operation's final CQE, in either arrival order.
- A cancel CQE alone does not release DMA ownership. Submit final close only
  after target operations retire; release buffers and recycle storage only after
  the close completes. Treat late completions as retirement work, not callbacks.
- Quarantine a dropped subsystem until its operations retire while allowing
  sibling subsystems on the same proactor to continue making progress.

### Generational IDs and terminal callbacks

- Encode `RequestId` and `WebSocketSessionId` with a 32-bit generation and a 32-bit
  index in their 64-bit value: generation in the upper half, index below it.
  Validate both fields before accessing a slot or dispatching a completion.
- Advance the generation when recycling a slot and reject stale handles.
  Verify round trips through command and completion payloads; preserve every
  identity bit or reject an unrepresentable value before submitting work.
- Preserve the Terminal Callback Exactly-Once guarantee for each admitted request:
  success, protocol/I/O failure, timeout, cancellation, or shutdown completes it.
  Remove or take the callback before invoking it, so re-entry cannot invoke it twice.
- Preserve single-thread callback execution and accepted follow-up work when a
  callback submits another request. Late events cannot revive a terminal request.

### DNS coalescing, cancellation, and pooling

- Apply static host overrides before the DNS cache and shared resolver.
  Keep cache TTLs, address families, and per-origin state explicit.
- Coalesce waiters while an origin is `ResolvingDns` or handshaking. Removing
  one waiter leaves shared queries alive for the remaining requests.
- When the last waiter leaves `ResolvingDns`, cancel its retained
  `cares::QueryHandle` values through the resolver and retire the origin lookup.
  Apply the same rule to rejected admission, explicit cancellation, and timeout.
- Combine dual-stack results according to usable addresses, then try remaining
  addresses after connection failure. Preserve per-origin connection limits,
  HTTP/2 stream admission, idle eviction, and shutdown drain semantics.

### Deferred responders and protocol handoff

- A live `Responder` dropped before sending queues a
  `500 Internal Server Error` response through the inbox. A disconnected or
  already-completed responder rejects a late response without duplicating output.
- Consume only through `\r\n\r\n` during an HTTP/1.1 `101 Switching Protocols`
  handoff. Preserve every trailing byte for the WebSocket decoder, including a
  complete first frame coalesced with the HTTP headers.
- Validate content length, transfer coding, and size limits before committing
  input/output changes. Return `BodyTooLarge` for excessive reassembly; the
  server admission path translates the request limit into status 413.
- Keep HTTP/2 connection and stream flow-control windows as signed `i64` values.
  A settings reduction may make a stream window negative; retain queued data
  until valid `WINDOW_UPDATE` credit permits sending. Keep stream cancellation
  local to its stream and preserve GOAWAY drain boundaries.
- Verify TLS identities by default and retain ALPN, certificate, and record
  failures as explicit results. Drain accepted plaintext and closure alerts in
  order; keep half-close and fatal-error handling deterministic.
- Declare transport EOF and request-method context explicitly when extending
  APIs that need them; buffered bytes alone do not establish transport closure.

### Errors, safety, and documentation

- Return typed `Result` values at protocol, runtime, and system boundaries.
  Preserve named causes and validate a complete state change before committing it.
- Propagate, return, or explicitly handle each failure; document intentional
  recovery. Preserve the strict workspace rules for fallibility and cloning.
- Attach `// SAFETY:` to every unsafe block, stating pointer validity, lifetime,
  aliasing, initialization, and ownership conditions relevant to that operation.
- Give every unsafe function a `# Safety` rustdoc section. Give public fallible
  APIs `# Errors` and public APIs with panic paths `# Panics` sections.
- Explain durable business and ownership rules in comments. Keep task identifiers,
  conversation history, agent assignments, and temporary validation notes outside source.

## Four-Dimensional Testing Matrix

| Dimension | Concrete distribution | Required assertions |
| --- | --- | --- |
| Integration test | `crates/nexora-proto/tests/{bytes_headers_tests,http1_tls_tests,hpack_frame_tests,http2_multiplex_tests,websocket_tests}.rs`; macro behavior and UI targets; `crates/nexora/tests/integration_tests.rs`. | Shared-byte isolation, framing, TLS trust/ALPN/mTLS, compression, macro expansion, and real resolver/proactor collaboration at public seams. |
| E2E test | Named in-memory closed loops in protocol targets; `crates/nexora/tests/e2e_tests.rs` for SDK entry points. | Formal request submission through client/server processing to delivered responses or WebSocket messages; identify in-memory transport replacements and real loopback boundaries. |
| Lifecycle test | Tagged protocol tests, module lifecycle tests, and `crates/nexora/tests/lifecycle_tests.rs`. | Legal/illegal transitions, terminal callback counts, duplicate/late events, cancel/target CQE order, responder fallback, close drain, subsystem drop, and resource release. |
| Scenario test | Tagged adversarial protocol tests and `crates/nexora/tests/scenario_tests.rs`. | One-byte trickle and coalescing, framing limits, DNS retry/TCP fallback, multi-IP failover, negative windows and recovery, resets, slow peers, and reconnect behavior. |

Use test/module names to expose the exercised dimension. Give every case a
controlled initial condition, triggering event, and observable business result.
Use protocol fixtures for wire corner cases and real loopback peers for runtime
claims. Keep fixture data with the tests that consume it.

Retain unit tests for nontrivial local rules, but test multi-component contracts
through their real public seams. Avoid duplicating getters or field echo checks.
Record state/output and resource assertions; logs or process survival alone are
supporting evidence. Distinguish real kernel cancellation from injected CQEs.
Count a case once even when it exercises both lifecycle and scenario behavior.

## Change Hygiene

1. Read the current task, this guide, manifests, and the relevant source/tests.
   Inspect `git status`, staged diffs, and unstaged diffs before editing.
2. Establish module ownership and affected callers before a cross-layer change.
   Re-read target content before writing; preserve unrelated and concurrent work.
3. Treat the contracts above as maintenance requirements. Verify existing code
   against them; report implementation drift and resolve it within the authorized
   scope rather than describing an unimplemented requirement as current behavior.
4. Add behavioral regressions for changed rules and run the focused package or
   test target first. Expand verification to producers, consumers, generated code,
   and backends affected by the public contract.
5. For code changes, run the Cargo checks above before completion.
   Run affected examples for runtime/API changes and all four for broad SDK changes.
   Exercise release builds when changing profiles, buffers, parsing, or lifecycle.
6. For documentation-only changes, check commands and references against current
   files, ASCII/word policy, file length, and the patch. Keep Rust builds reserved
   for changes that require them.
7. Preserve dependency lock integrity when manifests change. Keep lints strict
   and report prerequisite or shared-workspace failures with their exact scope.
8. Finish with `git diff --check` and a final ownership review. Report commands,
   test dimensions, results, and unverified runtime boundaries. A plan, build,
   skipped test, and completed runtime exchange are separate kinds of evidence.
9. Keep staging and history unchanged unless the user explicitly requests them.
   Update this guide and user-facing documentation when paths, commands, public
   behavior, or ownership contracts change; preserve the user's edit boundaries.
