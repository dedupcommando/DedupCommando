// SPDX-License-Identifier: Apache-2.0
//! The serialized browsing actor — staged by R4B-2b with no production caller.
//!
//! One thread owns one `ScanStore` and answers every browsing question through a typed
//! request/event protocol. Serialization is the point: today four different call sites open
//! their own connections mid-frame and re-validate the same authority, and no two of them can
//! agree on what the database said. The actor makes the database's answer one thing.
//!
//! Dormant by design in this commit: `BrowseFleet` sits unused inside `App`,
//! `AppEvent::Browse` is a carrier nothing constructs, and no production code spawns the
//! thread. R4B-2c performs the atomic cutover; until then every behaviour here is driven by
//! the tests at the bottom of this file.
//!
//! Layout, and why it is three nested modules rather than one flat one:
//! - `guarded` owns the only `ScanStore`. Its `inner` field is private to that module, so a
//!   request handler cannot reach a store method that is not deliberately exposed — and every
//!   exposed method carries exactly the identity-probe discipline printed on it.
//! - `emit` owns the only event sink. A handler cannot emit around the poisoning funnel,
//!   because the sink itself is private to `emit`.
//! - `arms` holds the request handlers, which therefore see only the door and the funnel.
//!
//! The module privacy holds while the layout holds; it is paired with exhaustive routing
//! tests rather than replacing them.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crossbeam_channel::{Receiver, Sender};

use crate::error::AppError;
use crate::model::duplicate::{AttributedDirGroup, DirSigAlgo, FileEntry};
use crate::model::plan::{ActionPlan, GroupId, MarkIntent, PlanRefusal, RequestedMark};
use crate::model::scan::{ScanStatus, ScanSummary};
use crate::state::store::{
    AttributedDirGroupSummaries, CandidateView, DirGroupAnswer, FileInfoAnswer, LiveDirSignature,
    MarkWriteError, MembershipMiss, MembershipSummaries, PanelFile, ResolvedGroup,
};

// ---------------------------------------------------------------------------------------------
// Identity and lifetime primitives
// ---------------------------------------------------------------------------------------------

/// One actor's identity for its whole life. Never reused: allocation is a checked global
/// counter, and `Closed` events are routed by this id alone, so a late terminal from a dead
/// actor can never be mistaken for the live one's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActorId(u64);

/// Which installed scan a request talks about. Bumped only by a successful `Open`, on both
/// sides at once, so in-flight requests of the previous scan stay valid through a failed
/// reopen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Activation(pub u64);

/// One request's identity. Allocated with `checked_add` and never reused — a wrap would let a
/// stale reply settle a fresh ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestId(pub u64);

/// The capability the actor opened its connection with. Immutable for the actor's life: the
/// connection kind is decided by THIS field via `open_writable`/`open_read_only`, never by the
/// mutable process-global observer flag, so a later global flip cannot retro-fit a live
/// connection. Changing role means replacing the actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowseRole {
    Operator,
    Observer,
}

/// Request-scoped cancellation. Created by the consumer BEFORE the request is enqueued and
/// never reset by anyone: a fresh operation carries a fresh token, so there is no window in
/// which an Esc pressed between enqueue and handler entry can be erased.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        CancelToken(Arc::new(AtomicBool::new(false)))
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Where the actor's replies go. Production hands in a wrapper over the application event
/// channel in R4B-2c; the tests hand in a channel of their own.
pub trait BrowseSink: Send {
    fn emit(&self, event: BrowseEvent);
}

/// Why a consumer-side registration or enqueue did not happen. One vocabulary for the ticket
/// constructor, the inflight ledger and the send gate, so a caller settles from a `match` and
/// never from a sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendRefusal {
    /// The request names one pathname twice.
    DuplicatePath { path: PathBuf },
    /// The path set and the before-image do not describe the same exact set.
    BeforeImageMismatch { path: PathBuf },
    /// A live ticket or long operation already carries this request id.
    RequestAlreadyLive,
    /// Another live ticket already owns this pathname.
    PathAlreadyLive { path: PathBuf },
    /// One long operation at a time; the live one must settle first.
    LongOperationLive,
    /// Linearized after `begin_close`: never accepted, never queued.
    Closing,
    /// The actor's receiver is gone; its `Closed` is already observable.
    Disconnected,
    /// `SetMarks`/`AutoSelect` carry settlement state and may only travel through their typed
    /// entry points — an untracked optimistic mutation is unrepresentable.
    RequiresTicket,
    /// `Shutdown` belongs to `begin_close` alone.
    ShutdownReserved,
}

/// One in-flight mark mutation the consumer still owes a settlement for: the activation, the
/// request id, the exact path set and the per-path durable before-image. Retained inside the
/// handle so a draining actor's tickets survive until its `Closed` arrives — this is what a
/// consumer needs to roll optimistic UI state back honestly, whatever happens to the actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkTicket {
    pub act: Activation,
    pub req: RequestId,
    /// The exact pathnames the request touches, in request order, unique.
    pub paths: Vec<PathBuf>,
    /// The durable mark each path carried BEFORE this request, same set as `paths`.
    pub before: Vec<(PathBuf, Option<MarkIntent>)>,
}

/// The complete, unvalidated inputs of a mark send whose halves disagreed. Deliberately NOT a
/// `MarkTicket` — its invariant never held — but nothing the caller supplied is discarded:
/// settlement can still be decided locally from every field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedMarkInputs {
    pub act: Activation,
    pub req: RequestId,
    pub paths: Vec<PathBuf>,
    pub before: Vec<(PathBuf, Option<MarkIntent>)>,
}

/// A refused mark send: the typed reason plus the COMPLETE attempted settlement state — the
/// whole ticket when one could exist, the whole raw inputs when the constructor refused. The
/// refusal is a self-contained ownership transfer back to the caller; no field the caller
/// supplied is dropped anywhere on this path.
#[derive(Debug)]
pub enum RefusedMarkSend {
    /// The halves disagreed; no ticket could exist. Everything supplied comes back raw.
    Invalid {
        reason: SendRefusal,
        inputs: RejectedMarkInputs,
    },
    /// A valid ticket was refused — conflict, closing or a dead receiver. Here it is, whole.
    Refused {
        reason: SendRefusal,
        ticket: MarkTicket,
    },
}

impl RefusedMarkSend {
    pub fn reason(&self) -> &SendRefusal {
        match self {
            RefusedMarkSend::Invalid { reason, .. } | RefusedMarkSend::Refused { reason, .. } => {
                reason
            }
        }
    }

    pub fn before(&self) -> &[(PathBuf, Option<MarkIntent>)] {
        match self {
            RefusedMarkSend::Invalid { inputs, .. } => &inputs.before,
            RefusedMarkSend::Refused { ticket, .. } => &ticket.before,
        }
    }
}

/// A refused long-operation send: the typed reason plus the complete `LongOperation` — the
/// activation, the request id and the ORIGINAL request-scoped token, not a token detached
/// from the request it belonged to.
#[derive(Debug)]
pub struct RefusedAutoSelect {
    pub reason: SendRefusal,
    pub long_op: LongOperation,
}

impl MarkTicket {
    /// The only constructor. Validates that `paths` is duplicate-free and that `before`
    /// describes exactly the same set — a ticket whose halves disagree could «settle» a path
    /// it never covered, or forget one it did. A refusal returns every supplied field.
    pub fn new(
        act: Activation,
        req: RequestId,
        paths: Vec<PathBuf>,
        before: Vec<(PathBuf, Option<MarkIntent>)>,
    ) -> std::result::Result<MarkTicket, RefusedMarkSend> {
        let invalid = |reason: SendRefusal,
                       paths: Vec<PathBuf>,
                       before: Vec<(PathBuf, Option<MarkIntent>)>| {
            RefusedMarkSend::Invalid {
                reason,
                inputs: RejectedMarkInputs {
                    act,
                    req,
                    paths,
                    before,
                },
            }
        };
        let duplicate = {
            let mut seen: std::collections::BTreeSet<&PathBuf> = std::collections::BTreeSet::new();
            paths.iter().find(|path| !seen.insert(path)).cloned()
        };
        if let Some(path) = duplicate {
            return Err(invalid(SendRefusal::DuplicatePath { path }, paths, before));
        }
        let doubled = {
            let mut image: std::collections::BTreeSet<&PathBuf> = std::collections::BTreeSet::new();
            before
                .iter()
                .map(|(path, _)| path)
                .find(|path| !image.insert(path))
                .cloned()
        };
        if let Some(path) = doubled {
            return Err(invalid(SendRefusal::DuplicatePath { path }, paths, before));
        }
        let disagree = {
            let requested: std::collections::BTreeSet<&PathBuf> = paths.iter().collect();
            let imaged: std::collections::BTreeSet<&PathBuf> =
                before.iter().map(|(path, _)| path).collect();
            paths
                .iter()
                .find(|path| !imaged.contains(path))
                .or_else(|| {
                    before
                        .iter()
                        .map(|(path, _)| path)
                        .find(|path| !requested.contains(path))
                })
                .cloned()
        };
        if let Some(path) = disagree {
            return Err(invalid(
                SendRefusal::BeforeImageMismatch { path },
                paths,
                before,
            ));
        }
        Ok(MarkTicket {
            act,
            req,
            paths,
            before,
        })
    }
}

/// The retained record of one live long operation: enough for the fleet to cancel it, for the
/// consumer to settle it on its terminal event, and for a retirement to reveal that a sweep
/// was mid-flight when the actor died. The token is the request-scoped one — stored, never
/// reset, never shared with a later operation.
#[derive(Debug, Clone)]
pub struct LongOperation {
    pub act: Activation,
    pub req: RequestId,
    pub cancel: CancelToken,
}

/// What settling one request id released.
#[derive(Debug)]
pub enum Settled {
    Marks(MarkTicket),
    Long(LongOperation),
}

/// Everything a terminal retirement drains: complete tickets, before-images included, and the
/// live long operation if one was mid-flight. Every path lock is released with it.
#[derive(Debug, Default)]
pub struct DrainedInflight {
    pub tickets: Vec<MarkTicket>,
    pub long_op: Option<LongOperation>,
}

/// The consumer-side settlement ledger, shared by every clone of one actor's handle. Owns the
/// per-path locks: two live mutations over one pathname would race each other's after-images,
/// so the second registration is refused, typed, before it can enqueue.
#[derive(Debug, Default)]
pub struct Inflight {
    state: Mutex<InflightState>,
}

#[derive(Debug, Default)]
struct InflightState {
    tickets: BTreeMap<u64, MarkTicket>,
    /// path → the request id whose live ticket owns it.
    locks: BTreeMap<PathBuf, u64>,
    long_op: Option<LongOperation>,
}

impl Inflight {
    fn locked(&self) -> std::sync::MutexGuard<'_, InflightState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Registers a mark ticket, refusing a duplicate request id or any path intersection with
    /// a live ticket. Never overwrites: the older entry always survives, and a refused
    /// newcomer comes back to its sender WHOLE.
    fn register_marks(&self, ticket: MarkTicket) -> std::result::Result<(), RefusedMarkSend> {
        let mut state = self.locked();
        if state.tickets.contains_key(&ticket.req.0)
            || state
                .long_op
                .as_ref()
                .is_some_and(|long| long.req == ticket.req)
        {
            return Err(RefusedMarkSend::Refused {
                reason: SendRefusal::RequestAlreadyLive,
                ticket,
            });
        }
        let conflict = ticket
            .paths
            .iter()
            .find(|path| state.locks.contains_key(*path))
            .cloned();
        if let Some(path) = conflict {
            return Err(RefusedMarkSend::Refused {
                reason: SendRefusal::PathAlreadyLive { path },
                ticket,
            });
        }
        for path in &ticket.paths {
            state.locks.insert(path.clone(), ticket.req.0);
        }
        state.tickets.insert(ticket.req.0, ticket);
        Ok(())
    }

    /// Registers the one long operation, refusing a second while one is live.
    fn register_long(&self, long: LongOperation) -> std::result::Result<(), SendRefusal> {
        let mut state = self.locked();
        if state.long_op.is_some() {
            return Err(SendRefusal::LongOperationLive);
        }
        if state.tickets.contains_key(&long.req.0) {
            return Err(SendRefusal::RequestAlreadyLive);
        }
        state.long_op = Some(long);
        Ok(())
    }

    /// Settles one request id: removes its ticket and releases every path lock it held, or
    /// takes the long operation if that is what the id names. A retry over the same paths
    /// succeeds after this.
    fn settle(&self, req: RequestId) -> Option<Settled> {
        let mut state = self.locked();
        if let Some(ticket) = state.tickets.remove(&req.0) {
            state.locks.retain(|_, owner| *owner != req.0);
            return Some(Settled::Marks(ticket));
        }
        if state.long_op.as_ref().is_some_and(|long| long.req == req) {
            return state.long_op.take().map(Settled::Long);
        }
        None
    }

    /// Takes everything at once — the retirement step after this actor's terminal.
    fn drain(&self) -> DrainedInflight {
        let mut state = self.locked();
        let tickets: Vec<MarkTicket> = std::mem::take(&mut state.tickets).into_values().collect();
        state.locks.clear();
        DrainedInflight {
            tickets,
            long_op: state.long_op.take(),
        }
    }

    /// Cancels the live long operation through its own stored token, if one is live.
    fn cancel_long(&self) -> bool {
        match &self.locked().long_op {
            Some(long) => {
                long.cancel.cancel();
                true
            }
            None => false,
        }
    }
}

/// The consumer's end of one actor: the request queue, the shared closing flag, the send gate
/// and the settlement ledger. Cheap to clone; every clone talks to the same actor and shares
/// the same gate, which is what makes closing linearizable against all of them.
///
/// Lock order, everywhere both locks are needed: **send gate → inflight mutex**. The gate is
/// taken by every enqueue, by `begin_close`, by settlement and by terminal drain; the inflight
/// mutex only ever nests inside it (or stands alone). No path takes them in reverse, so the
/// pair cannot deadlock — and, more importantly, no observer can see the intermediate state
/// «registered but not yet accepted/refused»: registration, the closing check, the channel
/// send and the rollback of a typed send all live inside ONE gate acquisition.
#[derive(Clone)]
pub struct BrowseHandle {
    actor: ActorId,
    tx: Sender<BrowseRequest>,
    closing: Arc<AtomicBool>,
    inflight: Arc<Inflight>,
    /// The one send gate — see the lock-order note above. Every request is linearized
    /// strictly before or strictly after the close: before → it sits in the queue ahead of
    /// the one `Shutdown` and receives its typed settlement; after → it is rejected to the
    /// caller and was never accepted. The `Empty`-then-drop loss window cannot exist, because
    /// nothing can enter the queue behind `Shutdown`.
    gate: Arc<Mutex<()>>,
    /// Test-only rendezvous fired between registration and the channel send, while the gate
    /// is held — the seam that lets a test PROVE terminal drain cannot pass in that window.
    #[cfg(test)]
    #[allow(clippy::type_complexity)] // the same seam-cell shape TestHooks uses
    typed_send_hook: Arc<Mutex<Option<Box<dyn FnMut() + Send>>>>,
}

impl BrowseHandle {
    pub fn actor(&self) -> ActorId {
        self.actor
    }

    fn gate_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The send step of an already-linearized caller: the closing check and the channel send,
    /// with the gate ALREADY held. Never takes a lock itself, so the typed entry points can
    /// keep one gate acquisition across registration, send and rollback.
    fn send_under_gate(
        &self,
        request: BrowseRequest,
    ) -> std::result::Result<(), (SendRefusal, BrowseRequest)> {
        if self.closing.load(Ordering::SeqCst) {
            return Err((SendRefusal::Closing, request));
        }
        self.tx
            .send(request)
            .map_err(|refused| (SendRefusal::Disconnected, refused.0))
    }

    #[cfg(test)]
    fn fire_typed_send_hook(&self) {
        if let Some(hook) = self
            .typed_send_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_mut()
        {
            hook();
        }
    }

    /// Test-only: installs the between-registration-and-send rendezvous.
    #[cfg(test)]
    pub(crate) fn on_typed_send(&self, hook: impl FnMut() + Send + 'static) {
        *self
            .typed_send_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Box::new(hook));
    }

    /// Enqueues a request that carries no consumer-side settlement state. `SetMarks` and
    /// `AutoSelect` are refused here by construction — they may only travel through the typed
    /// entry points that register their settlement state first — and `Shutdown` belongs to
    /// `begin_close` alone.
    pub fn send(&self, request: BrowseRequest) -> std::result::Result<(), SendRefusal> {
        match &request {
            BrowseRequest::SetMarks { .. } | BrowseRequest::AutoSelect { .. } => {
                return Err(SendRefusal::RequiresTicket)
            }
            BrowseRequest::Shutdown => return Err(SendRefusal::ShutdownReserved),
            _ => {}
        }
        let _linearized = self.gate_lock();
        self.send_under_gate(request).map_err(|(reason, _)| reason)
    }

    /// Test-only raw enqueue for exhaustive protocol routing: still gated, still refused
    /// after close, but without the tracking discipline. Production code has no such door.
    #[cfg(test)]
    pub(crate) fn send_raw(&self, request: BrowseRequest) -> bool {
        let _linearized = self.gate_lock();
        self.send_under_gate(request).is_ok()
    }

    /// Registers the ticket and enqueues the matching `SetMarks` under ONE gate acquisition:
    /// the closing check, the registration, the channel send and — on a send failure — the
    /// rollback are a single critical section, so a terminal drain can never observe (or
    /// steal) a ticket whose request was not yet accepted. Exactly three outcomes exist:
    /// accepted with the ticket retained until reply/terminal; rejected before registration
    /// because closing already won; or registered, send failed, registration removed and the
    /// COMPLETE ticket returned — all before terminal drain can pass the gate. The ledger
    /// keeps a clone and the sender keeps the original, so every refusal path returns the
    /// caller's own object without fabricating anything.
    pub fn send_set_marks(
        &self,
        act: Activation,
        req: RequestId,
        entries: Vec<FileEntry>,
        before: Vec<(PathBuf, Option<MarkIntent>)>,
    ) -> std::result::Result<(), RefusedMarkSend> {
        let paths: Vec<PathBuf> = entries.iter().map(|entry| entry.path.clone()).collect();
        let ticket = MarkTicket::new(act, req, paths, before)?;
        let _linearized = self.gate_lock();
        if self.closing.load(Ordering::SeqCst) {
            return Err(RefusedMarkSend::Refused {
                reason: SendRefusal::Closing,
                ticket,
            });
        }
        self.inflight.register_marks(ticket.clone())?;
        #[cfg(test)]
        self.fire_typed_send_hook();
        if let Err((reason, _request)) =
            self.send_under_gate(BrowseRequest::SetMarks { act, req, entries })
        {
            // Still inside the gate: the registration is removed before any drain can run,
            // and the sender's own original goes back whole.
            let _ = self.inflight.settle(req);
            return Err(RefusedMarkSend::Refused { reason, ticket });
        }
        Ok(())
    }

    /// Registers the long operation and enqueues the matching `AutoSelect` under the same
    /// single gate acquisition and rollback contract as `send_set_marks`. The ledger and the
    /// request each carry a clone of the caller's request-scoped token; every refusal returns
    /// the complete `LongOperation` built around the ORIGINAL token.
    pub fn send_auto_select(
        &self,
        act: Activation,
        req: RequestId,
        cancel: CancelToken,
    ) -> std::result::Result<(), RefusedAutoSelect> {
        let long_op = LongOperation { act, req, cancel };
        let _linearized = self.gate_lock();
        if self.closing.load(Ordering::SeqCst) {
            return Err(RefusedAutoSelect {
                reason: SendRefusal::Closing,
                long_op,
            });
        }
        if let Err(reason) = self.inflight.register_long(LongOperation {
            act,
            req,
            cancel: long_op.cancel.clone(),
        }) {
            return Err(RefusedAutoSelect { reason, long_op });
        }
        #[cfg(test)]
        self.fire_typed_send_hook();
        if let Err((reason, _request)) = self.send_under_gate(BrowseRequest::AutoSelect {
            act,
            req,
            cancel: long_op.cancel.clone(),
        }) {
            let _ = self.inflight.settle(req);
            return Err(RefusedAutoSelect { reason, long_op });
        }
        Ok(())
    }

    /// Test-only ledger seeding. Production has NO ungated registration seam: a ticket can
    /// only enter the ledger through `send_set_marks`' single gated critical section, so
    /// evidence without a future terminal owner is unrepresentable at runtime.
    #[cfg(test)]
    pub(crate) fn register_ticket(
        &self,
        ticket: MarkTicket,
    ) -> std::result::Result<(), RefusedMarkSend> {
        let _linearized = self.gate_lock();
        self.inflight.register_marks(ticket)
    }

    /// Settles one request id, releasing its ticket (and path locks) or the long operation.
    /// Takes the gate first — the one documented lock order — so settlement can never
    /// interleave with a typed send's registration window either.
    pub fn settle(&self, req: RequestId) -> Option<Settled> {
        let _linearized = self.gate_lock();
        self.inflight.settle(req)
    }

    /// Cancels the live long operation through its stored request-scoped token.
    pub fn cancel_long_operation(&self) -> bool {
        self.inflight.cancel_long()
    }

    /// Takes every unsettled ticket and the live long operation at once — the retirement step
    /// after this actor's terminal. Takes the gate first, so a retirement can only ever see a
    /// settled boundary: everything it drains was accepted, and everything a typed send rolled
    /// back is already gone.
    pub fn drain_tickets(&self) -> DrainedInflight {
        let _linearized = self.gate_lock();
        self.inflight.drain()
    }

    /// The closing half of the gate: marks closing and queues the one `Shutdown` in the same
    /// critical section, so every sender clone is linearized strictly before or after it.
    /// `false` means the receiver is already gone — the terminal path is then synthesised by
    /// the fleet, which owns exactly that case.
    fn begin_close_send(&self) -> bool {
        let _linearized = self.gate_lock();
        self.closing.store(true, Ordering::SeqCst);
        self.tx.send(BrowseRequest::Shutdown).is_ok()
    }
}

/// The request-id well. `checked_add` documents an invariant rather than a recoverable
/// condition: at one request per microsecond the space lasts ~584 000 years, and a silent wrap
/// would break «never reused».
#[derive(Debug, Default)]
pub struct RequestIds {
    next: u64,
}

impl RequestIds {
    pub fn allocate(&mut self) -> RequestId {
        self.next = self.next.checked_add(1).expect("RequestId space exhausted");
        RequestId(self.next)
    }

    /// Test-only: start the counter near the top so exhaustion is reachable.
    #[cfg(test)]
    pub(crate) fn starting_at(next: u64) -> Self {
        RequestIds { next }
    }
}

/// Actor ids come from one process-wide checked counter, because `BrowseActor::spawn` is the
/// only constructor and a second source of truth in the fleet would eventually disagree.
fn next_actor_id() -> ActorId {
    static NEXT_ACTOR: AtomicU64 = AtomicU64::new(0);
    let id = NEXT_ACTOR
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            current.checked_add(1)
        })
        .expect("ActorId space exhausted");
    ActorId(id + 1)
}

// ---------------------------------------------------------------------------------------------
// The request/event protocol — the complete inventory, no placeholder and no wildcard
// ---------------------------------------------------------------------------------------------

/// Everything the actor can be asked. Scan-scoped requests carry the activation they believe
/// is installed; connection-scoped requests carry it too, but the gate deliberately does not
/// compare it — they are the bootstrap that must work before any scan is open.
#[derive(Debug)]
pub enum BrowseRequest {
    Open {
        act: Activation,
        req: RequestId,
        scan_id: i64,
    },
    PanelData {
        act: Activation,
        req: RequestId,
        files: Vec<PathBuf>,
        dirs: Vec<PathBuf>,
    },
    GroupOpen {
        act: Activation,
        req: RequestId,
        id: GroupId,
        offset: usize,
        limit: usize,
    },
    GroupCount {
        act: Activation,
        req: RequestId,
        id: GroupId,
    },
    GroupOfPath {
        act: Activation,
        req: RequestId,
        path: PathBuf,
    },
    FileInfo {
        act: Activation,
        req: RequestId,
        path: PathBuf,
    },
    DirGroupAt {
        act: Activation,
        req: RequestId,
        dir: PathBuf,
    },
    OpenDirGroup {
        act: Activation,
        req: RequestId,
        signature: String,
    },
    MarkedCount {
        act: Activation,
        req: RequestId,
    },
    SetMarks {
        act: Activation,
        req: RequestId,
        entries: Vec<FileEntry>,
    },
    AutoSelect {
        act: Activation,
        req: RequestId,
        cancel: CancelToken,
    },
    BuildPlan {
        act: Activation,
        req: RequestId,
        requested: Vec<RequestedMark>,
    },
    ReconcileAfterBatch {
        act: Activation,
        req: RequestId,
        attempted: Vec<PathBuf>,
        cancelled: bool,
    },
    LatestScan {
        act: Activation,
        req: RequestId,
    },
    CoveringScan {
        act: Activation,
        req: RequestId,
        cwd: PathBuf,
    },
    ScanCreatedAt {
        act: Activation,
        req: RequestId,
        scan_id: i64,
    },
    CacheHash {
        act: Activation,
        req: RequestId,
        device: u64,
        inode: u64,
        size: u64,
        mtime: i64,
        digest: [u8; 32],
    },
    Shutdown,
}

/// Every reply the actor can give. Each accepted request settles with exactly one terminal
/// event of its declared variant, carrying the same `RequestId`; `Closed` alone carries no
/// activation, because it is routed by `ActorId` and must be deliverable at any time.
#[derive(Debug)]
pub enum BrowseEvent {
    OpenFinished {
        act: Activation,
        req: RequestId,
        result: std::result::Result<Box<OpenedBrowse>, BrowseOpenFailure>,
    },
    PanelData {
        act: Activation,
        req: RequestId,
        result: std::result::Result<Box<PanelData>, PanelFailure>,
    },
    Group {
        act: Activation,
        req: RequestId,
        result: std::result::Result<ResolvedGroup, MembershipMiss>,
    },
    GroupCount {
        act: Activation,
        req: RequestId,
        result: std::result::Result<u64, MembershipMiss>,
    },
    GroupOfPath {
        act: Activation,
        req: RequestId,
        result: std::result::Result<Option<GroupId>, MembershipMiss>,
    },
    FileInfo {
        act: Activation,
        req: RequestId,
        result: std::result::Result<Box<FileInfoAnswer>, StoreMiss>,
    },
    DirGroupAt {
        act: Activation,
        req: RequestId,
        result: std::result::Result<DirGroupAnswer, StoreMiss>,
    },
    DirGroupOpened {
        act: Activation,
        req: RequestId,
        result: std::result::Result<Option<Box<AttributedDirGroup>>, StoreMiss>,
    },
    MarkedCount {
        act: Activation,
        req: RequestId,
        result: std::result::Result<u64, StoreMiss>,
    },
    MarkAck {
        act: Activation,
        req: RequestId,
        outcome: MarkOutcome,
    },
    AutoSelectDone {
        act: Activation,
        req: RequestId,
        outcome: AutoSelectOutcome,
    },
    PlanReady {
        act: Activation,
        req: RequestId,
        plan: Box<ActionPlan>,
    },
    PlanRefused {
        act: Activation,
        req: RequestId,
        refusal: PlanRefusal,
    },
    ReconcileAck {
        act: Activation,
        req: RequestId,
        result: std::result::Result<(), StoreMiss>,
    },
    LatestScan {
        act: Activation,
        req: RequestId,
        result: std::result::Result<Option<i64>, StoreMiss>,
    },
    CoveringScan {
        act: Activation,
        req: RequestId,
        cwd: PathBuf,
        result: std::result::Result<Option<i64>, StoreMiss>,
    },
    ScanCreatedAt {
        act: Activation,
        req: RequestId,
        scan_id: i64,
        result: std::result::Result<Option<String>, StoreMiss>,
    },
    CacheHashAck {
        act: Activation,
        req: RequestId,
        result: std::result::Result<(), StoreMiss>,
    },
    /// Terminal. Exactly one per actor life, whatever the cause.
    Closed { actor: ActorId, cause: CloseCause },
}

/// Why a store-typed answer does not exist. Typed — no caller decides anything by parsing a
/// sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreMiss {
    /// No connection is established (and, after poisoning, none will be until `Open`).
    NotOpen,
    /// The actor is closing; the request was refused before touching the database.
    Closing,
    /// The database path was replaced. Only a fresh `Open` recovers.
    PathChanged {
        detail: String,
    },
    /// The connection exists but no scan is installed.
    NoActiveScan,
    /// The request belongs to an activation that is no longer installed.
    StaleActivation {
        expected: u64,
        found: u64,
    },
    /// A write was asked of an observer's read-only actor.
    ReadOnlyRole,
    NoSuchScan,
    /// The database read itself failed.
    Read {
        detail: String,
    },
}

/// Why a whole panel refresh did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanelFailure {
    NotOpen,
    Closing,
    PathChanged {
        detail: String,
    },
    NoActiveScan,
    StaleActivation {
        expected: u64,
        found: u64,
    },
    /// Creating the membership snapshot refused.
    Snapshot(MembershipMiss),
    /// The directory half (sizes or signatures) failed to read.
    Directories {
        detail: String,
    },
    /// The per-file half failed to read.
    Files {
        detail: String,
    },
}

/// How a `SetMarks` settled. `Settled`/`Failed` carry the durable after-image read inside the
/// same transaction; `Unreadable` means no authoritative after-image exists at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkOutcome {
    Settled {
        after: Vec<(PathBuf, Option<MarkIntent>)>,
    },
    Failed {
        error: MarkWriteError,
        after: Vec<(PathBuf, Option<MarkIntent>)>,
    },
    Unreadable {
        error: MarkWriteError,
    },
}

/// How an auto-select sweep ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoSelectOutcome {
    Completed {
        groups: u64,
        marks: u64,
    },
    /// At least one chunk is durably committed — `NonZeroU64` makes «partial with zero
    /// commits» unrepresentable rather than merely discouraged.
    Partial {
        committed_groups: NonZeroU64,
        last_committed_rank: i64,
        cancelled: bool,
        detail: String,
    },
    /// Exactly zero chunks committed.
    Refused(AutoSelectRefusal),
}

/// Why an auto-select sweep committed nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoSelectRefusal {
    Closing,
    NotOpen,
    PathChanged {
        detail: String,
    },
    ReadOnlyRole,
    NoActiveScan,
    StaleActivation {
        expected: u64,
        found: u64,
    },
    /// The scan has no membership authority.
    Unknown,
    /// The snapshot or summaries read refused before the first chunk.
    Snapshot(MembershipMiss),
    /// A group read failed before the first commit.
    Read {
        detail: String,
    },
    /// The first chunk's write failed; nothing is durable.
    FirstChunk(MarkWriteError),
    CancelledBeforeFirstCommit,
}

/// Why an actor's life ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseCause {
    Requested,
    Panicked(String),
}

/// Everything a successful `Open` installs, read through one actor so no two pieces describe
/// different databases.
#[derive(Debug)]
pub struct OpenedBrowse {
    pub scan_id: i64,
    pub status: ScanStatus,
    pub created_at: Option<String>,
    pub summary: ScanSummary,
    pub marked_count: u64,
    pub dir_groups: AttributedDirGroupSummaries,
    pub presentation: Presentation,
}

/// What the scan can show: published membership, or the typed candidate view of a scan with no
/// authority. There is deliberately no third shape.
#[derive(Debug)]
pub enum Presentation {
    Published(MembershipSummaries),
    Unpublished(CandidateView),
}

/// One panel refresh's answers, all from the same actor pass.
#[derive(Debug)]
pub struct PanelData {
    pub files: std::collections::HashMap<PathBuf, PanelFile>,
    pub dir_sizes: std::collections::HashMap<PathBuf, u64>,
    pub dir_signatures: std::collections::HashMap<PathBuf, LiveDirSignature>,
}

/// Why an `Open` did not install its scan. `PathChanged` is always failure class B (the actor
/// uninstalled both store and active scan); every other variant is class A (the previously
/// installed scan, if any, is untouched and still served).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowseOpenFailure {
    /// The connection itself could not be opened.
    Open {
        detail: String,
    },
    Role,
    Closing,
    /// The path changed during the open or during candidate construction. Always class B.
    PathChanged {
        detail: String,
    },
    Prepare {
        detail: String,
    },
    Snapshot(MembershipMiss),
    Summaries(MembershipMiss),
    ScanSummary {
        detail: String,
    },
    ScanStatus {
        detail: String,
    },
    CreatedAt {
        detail: String,
    },
    MarkedCount {
        detail: String,
    },
    DirGroups {
        detail: String,
    },
    Config {
        detail: String,
    },
    NoSuchScan,
}

// ---------------------------------------------------------------------------------------------
// The one typed poisoning surface
// ---------------------------------------------------------------------------------------------

/// The typed faces a database-path replacement can wear. One trait unifies them so exactly one
/// funnel makes the poisoning decision; error text takes no part in it.
pub(crate) trait PathMismatch {
    fn path_mismatch(&self) -> Option<&str>;
}

impl PathMismatch for AppError {
    fn path_mismatch(&self) -> Option<&str> {
        // Every arm written out: a variant added later fails to compile here instead of
        // silently answering `None`.
        match self {
            AppError::PathChanged { detail, .. } => Some(detail),
            AppError::Io(_) | AppError::Db(_) | AppError::Json(_) | AppError::Msg(_) => None,
        }
    }
}

impl PathMismatch for MembershipMiss {
    fn path_mismatch(&self) -> Option<&str> {
        match self {
            MembershipMiss::ReopenRequired { detail } => Some(detail),
            MembershipMiss::NoSuchScan
            | MembershipMiss::NoSuchGroup
            | MembershipMiss::Unknown
            | MembershipMiss::Stale { .. }
            | MembershipMiss::Inconsistent { .. }
            | MembershipMiss::Store { .. } => None,
        }
    }
}

impl PathMismatch for MarkWriteError {
    fn path_mismatch(&self) -> Option<&str> {
        match self {
            MarkWriteError::PathChanged { detail } => Some(detail),
            MarkWriteError::RequestContradictsItself { .. }
            | MarkWriteError::NotInManifest { .. }
            | MarkWriteError::Decode(_)
            | MarkWriteError::Store { .. } => None,
        }
    }
}

impl PathMismatch for StoreMiss {
    fn path_mismatch(&self) -> Option<&str> {
        match self {
            StoreMiss::PathChanged { detail } => Some(detail),
            StoreMiss::NotOpen
            | StoreMiss::Closing
            | StoreMiss::NoActiveScan
            | StoreMiss::StaleActivation { .. }
            | StoreMiss::ReadOnlyRole
            | StoreMiss::NoSuchScan
            | StoreMiss::Read { .. } => None,
        }
    }
}

impl PathMismatch for PanelFailure {
    fn path_mismatch(&self) -> Option<&str> {
        match self {
            PanelFailure::PathChanged { detail } => Some(detail),
            PanelFailure::Snapshot(miss) => miss.path_mismatch(),
            PanelFailure::NotOpen
            | PanelFailure::Closing
            | PanelFailure::NoActiveScan
            | PanelFailure::StaleActivation { .. }
            | PanelFailure::Directories { .. }
            | PanelFailure::Files { .. } => None,
        }
    }
}

impl PathMismatch for BrowseOpenFailure {
    /// Structurally `None` for every variant: the `Open` handler performs its class-B
    /// transition itself, before emitting, so the shared funnel poisoning must not fire again
    /// and cannot clear the state a recovery has just rebuilt.
    fn path_mismatch(&self) -> Option<&str> {
        match self {
            BrowseOpenFailure::Open { .. }
            | BrowseOpenFailure::Role
            | BrowseOpenFailure::Closing
            | BrowseOpenFailure::PathChanged { .. }
            | BrowseOpenFailure::Prepare { .. }
            | BrowseOpenFailure::Snapshot(_)
            | BrowseOpenFailure::Summaries(_)
            | BrowseOpenFailure::ScanSummary { .. }
            | BrowseOpenFailure::ScanStatus { .. }
            | BrowseOpenFailure::CreatedAt { .. }
            | BrowseOpenFailure::MarkedCount { .. }
            | BrowseOpenFailure::DirGroups { .. }
            | BrowseOpenFailure::Config { .. }
            | BrowseOpenFailure::NoSuchScan => None,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The fleet: at most one actor over the database, replacement strictly serialized
// ---------------------------------------------------------------------------------------------

/// What to spawn once the retiring actor is fully gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSpawn {
    pub role: BrowseRole,
    /// The scan to reopen in the successor, when one was installed.
    pub reopen: Option<i64>,
}

/// The fleet's lifecycle. `Draining` retains the whole retiring handle — and therefore its
/// tickets — until that actor's `Closed` arrives, is joined and is settled; only then may a
/// successor exist. There is no state in which an actor exists without its join handle.
pub(crate) enum FleetState {
    Idle,
    Live {
        actor: ActorId,
        handle: BrowseHandle,
        join: JoinHandle<()>,
    },
    Draining {
        actor: ActorId,
        handle: BrowseHandle,
        join: JoinHandle<()>,
    },
}

/// The fleet's phase, for callers that must not reach into `FleetState`'s owned handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetPhase {
    Idle,
    Live,
    Draining,
}

/// Owns the one browsing actor and the strictly serialized replacement protocol.
///
/// Dormant in this commit: `App` holds one, initialized `Idle`, and nothing in production
/// calls anything else on it until R4B-2c.
pub struct BrowseFleet {
    state: FleetState,
    /// The successor to spawn after the current terminal settles. Kept beside the state, not
    /// inside `Draining`, so a terminal that empties the state cannot drop it by accident —
    /// and so a panic terminal can clear it deliberately.
    pending: Option<PendingSpawn>,
    /// The request-id well the consumer draws from.
    requests: RequestIds,
}

impl Default for BrowseFleet {
    fn default() -> Self {
        Self::new()
    }
}

impl BrowseFleet {
    pub fn new() -> Self {
        BrowseFleet {
            state: FleetState::Idle,
            pending: None,
            requests: RequestIds::default(),
        }
    }

    pub fn phase(&self) -> FleetPhase {
        match self.state {
            FleetState::Idle => FleetPhase::Idle,
            FleetState::Live { .. } => FleetPhase::Live,
            FleetState::Draining { .. } => FleetPhase::Draining,
        }
    }

    /// True while an actor is closing and its terminal has not settled yet.
    pub fn busy(&self) -> bool {
        matches!(self.state, FleetState::Draining { .. })
    }

    /// True while some actor still owes exactly one terminal. The shutdown machine waits on
    /// nothing else.
    pub fn terminal_owed(&self) -> bool {
        matches!(
            self.state,
            FleetState::Live { .. } | FleetState::Draining { .. }
        )
    }

    pub fn next_request(&mut self) -> RequestId {
        self.requests.allocate()
    }

    /// The live handle, for enqueueing. `None` while `Idle` or `Draining` — a draining actor
    /// accepts nothing new.
    pub fn live(&self) -> Option<&BrowseHandle> {
        match &self.state {
            FleetState::Live { handle, .. } => Some(handle),
            FleetState::Idle | FleetState::Draining { .. } => None,
        }
    }

    /// Spawns the one actor. Refused (returns `None`) unless the fleet is `Idle`: at most one
    /// actor ever exists over the database, and replacement goes through `replace`.
    pub fn spawn(
        &mut self,
        db: PathBuf,
        role: BrowseRole,
        sink: Box<dyn BrowseSink>,
    ) -> Option<ActorId> {
        self.spawn_inner(db, role, sink, TestHooks::default())
    }

    #[cfg(test)]
    pub(crate) fn spawn_hooked(
        &mut self,
        db: PathBuf,
        role: BrowseRole,
        sink: Box<dyn BrowseSink>,
        hooks: TestHooks,
    ) -> Option<ActorId> {
        self.spawn_inner(db, role, sink, hooks)
    }

    fn spawn_inner(
        &mut self,
        db: PathBuf,
        role: BrowseRole,
        sink: Box<dyn BrowseSink>,
        hooks: TestHooks,
    ) -> Option<ActorId> {
        if !matches!(self.state, FleetState::Idle) {
            return None;
        }
        let (actor, handle, join) = BrowseActor::spawn_inner(db, role, sink, hooks);
        self.state = FleetState::Live {
            actor,
            handle,
            join,
        };
        Some(actor)
    }

    /// Starts closing the live actor. Under the handle's send gate the closing flag and the
    /// one `Shutdown` are one critical section, so every sender clone is linearized strictly
    /// before or strictly after the close.
    ///
    /// Normally returns `None` and the terminal arrives later as a `Closed` event. When the
    /// send itself fails the actor is already gone, so the ownership transition happens here:
    /// the complete retirement — handle with every unsettled ticket and the live long
    /// operation, plus the join handle — comes back to the caller, and the pending successor
    /// is dropped, because the cause of death is unknown at this point and spawning blind
    /// after a possible panic is what the panic policy forbids. Dropping the EVIDENCE is not
    /// part of that conservatism: it is returned whole.
    pub fn begin_close(&mut self) -> Option<RetiredActor> {
        match &self.state {
            FleetState::Idle | FleetState::Draining { .. } => None,
            FleetState::Live { handle, .. } => {
                let sent = handle.begin_close_send();
                let FleetState::Live {
                    actor,
                    handle,
                    join,
                } = std::mem::replace(&mut self.state, FleetState::Idle)
                else {
                    return None;
                };
                if sent {
                    self.state = FleetState::Draining {
                        actor,
                        handle,
                        join,
                    };
                    None
                } else {
                    self.pending = None;
                    Some(RetiredActor {
                        actor,
                        handle,
                        join,
                    })
                }
            }
        }
    }

    /// Asks for a serialized replacement: close the live actor now, remember what to spawn
    /// once its terminal settles. On an idle fleet it only records the wish. A send failure
    /// surfaces the synthesised retirement to the caller UNJOINED and UNDRAINED — settling
    /// the tickets, discovering a live long operation and joining exactly once belong to the
    /// caller, and nothing here may discard that evidence.
    pub fn replace(&mut self, role: BrowseRole, reopen: Option<i64>) -> Option<RetiredActor> {
        self.pending = Some(PendingSpawn { role, reopen });
        if matches!(self.state, FleetState::Live { .. }) {
            self.begin_close()
        } else {
            None
        }
    }

    pub fn cancel_pending_spawn(&mut self) {
        self.pending = None;
    }

    pub fn pending_spawn(&self) -> Option<&PendingSpawn> {
        self.pending.as_ref()
    }

    /// Consumes the one terminal an actor owes. Returns the complete retirement the FIRST
    /// time a terminal for `actor` is seen; `None` for a duplicate or an unknown id —
    /// idempotence is structural, because the state has already moved on. A `Panicked` cause
    /// additionally clears the pending successor: an actor that died of a panic never gets
    /// one.
    pub fn take_terminal(&mut self, actor: ActorId, cause: &CloseCause) -> Option<RetiredActor> {
        let matches_actor = match &self.state {
            FleetState::Live { actor: live, .. } => *live == actor,
            FleetState::Draining {
                actor: draining, ..
            } => *draining == actor,
            FleetState::Idle => false,
        };
        if !matches_actor {
            return None;
        }
        if matches!(cause, CloseCause::Panicked(_)) {
            self.pending = None;
        }
        match std::mem::replace(&mut self.state, FleetState::Idle) {
            FleetState::Live { handle, join, .. } | FleetState::Draining { handle, join, .. } => {
                Some(RetiredActor {
                    actor,
                    handle,
                    join,
                })
            }
            FleetState::Idle => None,
        }
    }
}

/// The one-owner retirement of an actor: the handle still holding every unsettled ticket and
/// the live long operation, plus the join handle to be joined exactly once. Whichever route
/// produced it — a consumed `Closed`, a shutdown-send failure — the first observer owns it
/// whole, and every later observation of the same terminal is a `None`. R4B-2c settles
/// optimistic UI state from exactly this; the actor-only checkpoint proves it survives.
pub struct RetiredActor {
    pub actor: ActorId,
    pub handle: BrowseHandle,
    pub join: JoinHandle<()>,
}

// ---------------------------------------------------------------------------------------------
// Actor state and the pre-dispatch gate
// ---------------------------------------------------------------------------------------------

/// The connection slot. A third state beside «no connection yet» and «connection held» is
/// what lets two frozen rules coexist: connection-scoped requests may bootstrap lazily from
/// `Absent`, while after a path mismatch every non-`Open` request must refuse until a fresh
/// `Open` — so `Poisoned` must be distinguishable from plain absence.
enum Slot {
    Absent,
    /// Boxed: the door owns a whole `ScanStore`, and the slot's other states are a word.
    Open(Box<guarded::BrowsingStore>),
    Poisoned {
        detail: String,
    },
}

/// The scan a successful `Open` installed.
struct ActiveScan {
    scan_id: i64,
    act: Activation,
    /// Cached at `Open` from the scan's config, so a panel refresh spends no statement on it.
    dir_sig_algo: DirSigAlgo,
}

/// Everything the actor thread owns.
struct ActorState {
    actor: ActorId,
    db: PathBuf,
    role: BrowseRole,
    closing: Arc<AtomicBool>,
    slot: Slot,
    active: Option<ActiveScan>,
    /// Deterministic observation seams; empty and free outside `cfg(test)`.
    hooks: TestHooks,
}

impl ActorState {
    fn closing(&self) -> bool {
        self.closing.load(Ordering::SeqCst)
    }

    /// The one poisoning transition: both the connection and the active scan are dropped
    /// BEFORE the refusal that reports it leaves the actor. Only `Open` recovers.
    fn poison(&mut self, detail: &str) {
        tracing::warn!(%detail, "browsing store poisoned: the database path changed");
        self.slot = Slot::Poisoned {
            detail: detail.to_string(),
        };
        self.active = None;
    }

    /// The connection, opening lazily by the actor's own immutable role. This is the
    /// bootstrap that makes `LatestScan` answerable before any scan was ever opened. A
    /// poisoned slot refuses instead — recovery belongs to `Open` alone.
    fn door(&mut self) -> Result<&mut guarded::BrowsingStore, StoreMiss> {
        match &mut self.slot {
            Slot::Poisoned { detail } => {
                return Err(StoreMiss::PathChanged {
                    detail: detail.clone(),
                })
            }
            Slot::Open(_) => {}
            Slot::Absent => match guarded::BrowsingStore::open(&self.db, self.role) {
                Ok(door) => self.slot = Slot::Open(Box::new(door)),
                Err(err) => {
                    return Err(match err.path_mismatch() {
                        Some(detail) => StoreMiss::PathChanged {
                            detail: detail.to_string(),
                        },
                        None => StoreMiss::Read {
                            detail: err.to_string(),
                        },
                    })
                }
            },
        }
        match &mut self.slot {
            Slot::Open(door) => Ok(&mut **door),
            // The `Open` arm above either installed the door or returned; `Poisoned` returned
            // first. Refusing keeps this total without a panic.
            Slot::Absent | Slot::Poisoned { .. } => Err(StoreMiss::NotOpen),
        }
    }

    /// The gate for connection-scoped requests. Refusals decidable from actor state alone —
    /// a poisoned slot, a write asked of an observer — fire BEFORE any open: a refused
    /// request must never establish a directory, create a database or run a migration as a
    /// side effect. Only after them may a request bootstrap the lazy connection. Deliberately
    /// NO activation comparison and NO filesystem identity probe — identity is the store's
    /// invariant, paid inside each door method.
    fn connection_gate(&mut self, write: bool) -> Result<(), StoreMiss> {
        if let Slot::Poisoned { detail } = &self.slot {
            return Err(StoreMiss::PathChanged {
                detail: detail.clone(),
            });
        }
        if write && self.role == BrowseRole::Observer {
            return Err(StoreMiss::ReadOnlyRole);
        }
        self.door()?;
        Ok(())
    }

    /// The gate for scan-scoped requests, decided entirely from in-memory state: poisoned
    /// slot, immutable role, installed scan, exact activation — in that order, all of it
    /// before any store method can run. A request this gate refuses opens nothing, creates
    /// nothing, migrates nothing and probes nothing. Returns the installed scan id so the
    /// arm cannot accidentally use the request's own idea of it.
    fn scan_gate(&mut self, act: Activation, write: bool) -> Result<i64, StoreMiss> {
        if let Slot::Poisoned { detail } = &self.slot {
            return Err(StoreMiss::PathChanged {
                detail: detail.clone(),
            });
        }
        if write && self.role == BrowseRole::Observer {
            return Err(StoreMiss::ReadOnlyRole);
        }
        let (scan_id, installed) = match &self.active {
            None => return Err(StoreMiss::NoActiveScan),
            Some(active) => (active.scan_id, active.act),
        };
        if installed != act {
            return Err(StoreMiss::StaleActivation {
                expected: installed.0,
                found: act.0,
            });
        }
        // An installed scan implies a held connection — `Open` installs both together and
        // poisoning drops both together — so this match is totality, never a bootstrap: a
        // scan-scoped request does not open the database.
        match &self.slot {
            Slot::Open(_) => Ok(scan_id),
            Slot::Absent | Slot::Poisoned { .. } => Err(StoreMiss::NotOpen),
        }
    }

    /// The installed dir-signature algorithm; the scan gate has already proven `active`.
    fn dir_sig_algo(&self) -> DirSigAlgo {
        self.active
            .as_ref()
            .map(|active| active.dir_sig_algo)
            .unwrap_or(DirSigAlgo::Old)
    }
}

/// Auto-select chunk boundaries, for the deterministic test seams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChunkPhase {
    /// About to write chunk `k` (1-based).
    BeforeWrite(usize),
    /// Chunk `k` committed durably.
    AfterCommit(usize),
}

/// Deterministic observation seams for the tests: a rendezvous before every dispatch, one
/// before each `Open` candidate step, and one at auto-select chunk boundaries. They observe
/// and may act from OUTSIDE (cancel a token, swap a file, panic) — nothing here gives the
/// actor a behaviour production lacks.
#[derive(Clone, Default)]
#[allow(clippy::type_complexity)] // test-only seam cells; a named alias would outlive its one use
pub(crate) struct TestHooks {
    #[cfg(test)]
    dispatch: Arc<Mutex<Option<Box<dyn FnMut() + Send>>>>,
    #[cfg(test)]
    open_step: Arc<Mutex<Option<Box<dyn FnMut(&'static str) + Send>>>>,
    #[cfg(test)]
    chunk: Arc<Mutex<Option<Box<dyn FnMut(ChunkPhase) + Send>>>>,
}

impl TestHooks {
    fn fire_dispatch(&self) {
        #[cfg(test)]
        if let Some(hook) = self
            .dispatch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_mut()
        {
            hook();
        }
    }

    fn fire_open_step(&self, step: &'static str) {
        let _ = &step;
        #[cfg(test)]
        if let Some(hook) = self
            .open_step
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_mut()
        {
            hook(step);
        }
    }

    fn fire_chunk(&self, phase: ChunkPhase) {
        let _ = &phase;
        #[cfg(test)]
        if let Some(hook) = self
            .chunk
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_mut()
        {
            hook(phase);
        }
    }
}

#[cfg(test)]
impl TestHooks {
    pub(crate) fn on_dispatch(&self, hook: impl FnMut() + Send + 'static) {
        *self
            .dispatch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Box::new(hook));
    }

    pub(crate) fn on_open_step(&self, hook: impl FnMut(&'static str) + Send + 'static) {
        *self
            .open_step
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Box::new(hook));
    }

    pub(crate) fn on_chunk(&self, hook: impl FnMut(ChunkPhase) + Send + 'static) {
        *self
            .chunk
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Box::new(hook));
    }
}

// ---------------------------------------------------------------------------------------------
// Spawn and the run loop
// ---------------------------------------------------------------------------------------------

/// The actor's only constructor. The join handle is returned beside the sender handle, so a
/// live actor without a join handle is not constructible.
pub struct BrowseActor;

impl BrowseActor {
    pub fn spawn(
        db: PathBuf,
        role: BrowseRole,
        sink: Box<dyn BrowseSink>,
    ) -> (ActorId, BrowseHandle, JoinHandle<()>) {
        Self::spawn_inner(db, role, sink, TestHooks::default())
    }

    #[cfg(test)]
    pub(crate) fn spawn_with_hooks(
        db: PathBuf,
        role: BrowseRole,
        sink: Box<dyn BrowseSink>,
        hooks: TestHooks,
    ) -> (ActorId, BrowseHandle, JoinHandle<()>) {
        Self::spawn_inner(db, role, sink, hooks)
    }

    fn spawn_inner(
        db: PathBuf,
        role: BrowseRole,
        sink: Box<dyn BrowseSink>,
        hooks: TestHooks,
    ) -> (ActorId, BrowseHandle, JoinHandle<()>) {
        let actor = next_actor_id();
        let (tx, rx) = crossbeam_channel::unbounded::<BrowseRequest>();
        let closing = Arc::new(AtomicBool::new(false));
        let handle = BrowseHandle {
            actor,
            tx,
            closing: closing.clone(),
            inflight: Arc::new(Inflight::default()),
            gate: Arc::new(Mutex::new(())),
            #[cfg(test)]
            typed_send_hook: Arc::new(Mutex::new(None)),
        };
        let join = std::thread::Builder::new()
            .name("dedcom-browse".to_string())
            .spawn(move || {
                let emitter = emit::Emitter::new(sink);
                let mut state = ActorState {
                    actor,
                    db,
                    role,
                    closing,
                    slot: Slot::Absent,
                    active: None,
                    hooks,
                };
                // One panic contract: a panic anywhere in the loop is caught HERE, after the
                // process-wide hook ran, and becomes this actor's one `Closed(Panicked)`. The
                // receiver is owned by `run`, so by the time any `Closed` is observable the
                // queue is already unreachable and a late `send` fails rather than lingers.
                let outcome = crate::panics::guard_value("the browsing actor", || {
                    run(&mut state, rx, &emitter)
                });
                if let Err(text) = outcome {
                    emitter.closed(actor, CloseCause::Panicked(text));
                }
            })
            .expect("the browsing actor thread must start");
        (actor, handle, join)
    }
}

/// The dispatch loop. Owns the receiver: normal shutdown drops it BEFORE emitting `Closed`,
/// and a panic unwinds it before the guard reports — either way, an observable `Closed`
/// means no new request can be queued any more.
///
/// There is deliberately no post-`Shutdown` drain: every enqueue and `begin_close` share one
/// send gate, so a request is either in the queue AHEAD of the one `Shutdown` — and settles
/// through the closing check above — or was rejected to its caller and never entered. Nothing
/// can sit behind `Shutdown`, and an accepted request can never be left unanswered.
fn run(state: &mut ActorState, rx: Receiver<BrowseRequest>, emitter: &emit::Emitter) {
    while let Ok(request) = rx.recv() {
        if matches!(request, BrowseRequest::Shutdown) {
            break;
        }
        if state.closing() {
            arms::refuse_closing(state, emitter, request);
            continue;
        }
        state.hooks.fire_dispatch();
        arms::handle(state, emitter, request);
    }
    let actor = state.actor;
    drop(rx);
    emitter.closed(actor, CloseCause::Requested);
}

// ---------------------------------------------------------------------------------------------
// guarded — the only door from the actor to the store
// ---------------------------------------------------------------------------------------------

mod guarded {
    use super::BrowseRole;
    use crate::error::Result;
    use crate::model::duplicate::{AttributedDirGroup, DirSigAlgo, FileEntry};
    use crate::model::plan::{ActionPlan, MarkIntent, PlanResult, RequestedMark};
    use crate::model::scan::{ScanConfig, ScanStatus, ScanSummary};
    use crate::state::store::{
        AttributedDirGroupSummaries, LiveDirSignature, MarkWriteError, MembershipMiss,
        MembershipSnapshot, ScanStore,
    };
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    /// The ONLY door from the actor to the store. `inner` is private to this module, so a
    /// request handler cannot reach a store method that is not exposed here, and no method
    /// exposes `&ScanStore`, `&Connection` or the field itself.
    ///
    /// Identity-probe ownership, per method class (this is the whole contract, and the tests
    /// pin it):
    /// - `membership_snapshot`, `prepare_legacy_for_viewing` and `save_marks_settled` own
    ///   their probe inside the store already — the door adds nothing;
    /// - every legacy store operation R4B-2a deliberately left unguarded gets exactly one
    ///   `ensure_current_path()` here, immediately before the call;
    /// - snapshot readers pay nothing — their snapshot already did;
    /// - the open bracket around `Connection::open*` stays the store's own.
    ///
    /// The door adds no SECOND check anywhere: it is a visibility fence plus the single probe
    /// the store does not carry itself.
    pub(crate) struct BrowsingStore {
        inner: ScanStore,
    }

    impl BrowsingStore {
        /// Opens by the actor's own immutable role — never `ScanStore::open`, which reads the
        /// mutable process-global observer flag at open time.
        pub(crate) fn open(db: &Path, role: BrowseRole) -> Result<Self> {
            let inner = match role {
                BrowseRole::Operator => ScanStore::open_writable(db)?,
                BrowseRole::Observer => ScanStore::open_read_only(db)?,
            };
            Ok(BrowsingStore { inner })
        }

        /// The reuse check of the `Open` bracket: does the configured path still name the
        /// file this connection opened? One probe, no SQL.
        pub(crate) fn identity_check(&self) -> Result<()> {
            self.inner.ensure_current_path()
        }

        // ---- self-guarded operations: the store already owns their probe ----

        pub(crate) fn membership_snapshot(
            &self,
            scan_id: i64,
        ) -> std::result::Result<MembershipSnapshot<'_>, MembershipMiss> {
            self.inner.membership_snapshot(scan_id)
        }

        pub(crate) fn prepare_legacy_for_viewing(&mut self, scan_id: i64) -> Result<()> {
            self.inner.prepare_legacy_for_viewing(scan_id)
        }

        pub(crate) fn save_marks_settled(
            &mut self,
            scan_id: i64,
            files: &[FileEntry],
        ) -> std::result::Result<Vec<(PathBuf, Option<MarkIntent>)>, MarkWriteError> {
            self.inner.save_marks_settled(scan_id, files)
        }

        // ---- legacy operations: the door pays their one probe ----

        pub(crate) fn load_config(&self, scan_id: i64) -> Result<ScanConfig> {
            self.inner.ensure_current_path()?;
            self.inner.load_config(scan_id)
        }

        pub(crate) fn scan_status(&self, scan_id: i64) -> Result<ScanStatus> {
            self.inner.ensure_current_path()?;
            self.inner.scan_status(scan_id)
        }

        pub(crate) fn scan_summary(&self, scan_id: i64) -> Result<ScanSummary> {
            self.inner.ensure_current_path()?;
            self.inner.scan_summary(scan_id)
        }

        pub(crate) fn scan_created_at(&self, scan_id: i64) -> Result<Option<String>> {
            self.inner.ensure_current_path()?;
            self.inner.scan_created_at(scan_id)
        }

        pub(crate) fn marked_count(&self, scan_id: i64) -> Result<u64> {
            self.inner.ensure_current_path()?;
            self.inner.marked_count(scan_id)
        }

        pub(crate) fn latest_scan_id(&self) -> Result<Option<i64>> {
            self.inner.ensure_current_path()?;
            self.inner.latest_scan_id()
        }

        pub(crate) fn latest_scan_covering(&self, cwd: &Path) -> Result<Option<i64>> {
            self.inner.ensure_current_path()?;
            self.inner.latest_scan_covering(cwd)
        }

        pub(crate) fn attributed_dir_group_summaries(
            &self,
            scan_id: i64,
        ) -> Result<AttributedDirGroupSummaries> {
            self.inner.ensure_current_path()?;
            self.inner.attributed_dir_group_summaries(scan_id)
        }

        pub(crate) fn attributed_dir_group(
            &self,
            scan_id: i64,
            signature: &str,
        ) -> Result<Option<AttributedDirGroup>> {
            self.inner.ensure_current_path()?;
            self.inner.attributed_dir_group(scan_id, signature)
        }

        pub(crate) fn dir_sizes_under(
            &self,
            scan_id: i64,
            dirs: &[PathBuf],
        ) -> Result<HashMap<PathBuf, u64>> {
            self.inner.ensure_current_path()?;
            self.inner.dir_sizes_under(scan_id, dirs)
        }

        pub(crate) fn dir_signatures_under(
            &self,
            scan_id: i64,
            dirs: &[PathBuf],
            algo: DirSigAlgo,
        ) -> Result<HashMap<PathBuf, LiveDirSignature>> {
            self.inner.ensure_current_path()?;
            self.inner.dir_signatures_under(scan_id, dirs, algo)
        }

        pub(crate) fn reconcile_marks_after_batch(
            &mut self,
            scan_id: i64,
            attempted: &[PathBuf],
            cancelled: bool,
        ) -> Result<()> {
            self.inner.ensure_current_path()?;
            self.inner
                .reconcile_marks_after_batch(scan_id, attempted, cancelled)
        }

        pub(crate) fn upsert_hash(
            &mut self,
            device: u64,
            inode: u64,
            size: u64,
            mtime: i64,
            hash: &[u8; 32],
        ) -> Result<()> {
            self.inner.ensure_current_path()?;
            self.inner.upsert_hash(device, inode, size, mtime, hash)
        }

        /// The plan builder still runs its own transaction inside the store; R4B-2c moves it
        /// onto the snapshot. The outer error is the door's probe — typed, so the funnel can
        /// poison from it — and the inner result is the plan's own accept/refuse.
        pub(crate) fn build_action_plan(
            &self,
            scan_id: i64,
            requested: &[RequestedMark],
        ) -> Result<PlanResult<ActionPlan>> {
            self.inner.ensure_current_path()?;
            Ok(self.inner.build_action_plan(scan_id, requested))
        }

        // ---- test-only counters, so the probe matrix is pinned by numbers, not prose ----

        #[cfg(test)]
        pub(crate) fn identity_probes(&self) -> u64 {
            self.inner.identity_probes()
        }

        #[cfg(test)]
        pub(crate) fn full_validation_count(&self) -> u64 {
            self.inner.full_validation_count()
        }
    }
}

// ---------------------------------------------------------------------------------------------
// emit — the only way a handler's result leaves the actor
// ---------------------------------------------------------------------------------------------

mod emit {
    use super::{
        Activation, ActorId, ActorState, AutoSelectOutcome, AutoSelectRefusal, BrowseEvent,
        BrowseSink, CloseCause, MarkOutcome, PathMismatch, RequestId, SweepFailure,
    };
    use std::num::NonZeroU64;

    /// Owns the sink. The field is private to this module, so no request handler can emit any
    /// way but through the funnels below — and the funnels are where the poisoning decision
    /// lives, so an arm that forgets to poison cannot exist.
    pub(crate) struct Emitter {
        sink: Box<dyn BrowseSink>,
    }

    impl Emitter {
        pub(crate) fn new(sink: Box<dyn BrowseSink>) -> Self {
            Emitter { sink }
        }

        fn event(&self, event: BrowseEvent) {
            self.sink.emit(event);
        }

        /// The generic funnel: poison on a typed path mismatch, THEN construct and emit the
        /// terminal event. State is mutated before the result leaves, so no ordering is left
        /// to each arm's discipline.
        pub(crate) fn finish<T, E: PathMismatch>(
            &self,
            state: &mut ActorState,
            result: std::result::Result<T, E>,
            into: impl FnOnce(std::result::Result<T, E>) -> BrowseEvent,
        ) {
            if let Err(err) = &result {
                if let Some(detail) = err.path_mismatch() {
                    let detail = detail.to_string();
                    state.poison(&detail);
                }
            }
            self.event(into(result));
        }

        /// The mark funnel: the outcome's own typed error decides the poisoning.
        pub(crate) fn mark_ack(
            &self,
            state: &mut ActorState,
            act: Activation,
            req: RequestId,
            outcome: MarkOutcome,
        ) {
            let mismatch = match &outcome {
                MarkOutcome::Failed { error, .. } | MarkOutcome::Unreadable { error } => {
                    error.path_mismatch().map(str::to_owned)
                }
                MarkOutcome::Settled { .. } => None,
            };
            if let Some(detail) = mismatch {
                state.poison(&detail);
            }
            self.event(BrowseEvent::MarkAck { act, req, outcome });
        }

        /// Auto-select outcomes that did not come from a typed error (success, cancellation,
        /// gate refusals). A refusal that CARRIES a typed mismatch still poisons — the gate
        /// case arrives here already poisoned, and re-poisoning is idempotent.
        pub(crate) fn auto_select_done(
            &self,
            state: &mut ActorState,
            act: Activation,
            req: RequestId,
            outcome: AutoSelectOutcome,
        ) {
            let mismatch = match &outcome {
                AutoSelectOutcome::Refused(AutoSelectRefusal::PathChanged { detail }) => {
                    Some(detail.clone())
                }
                AutoSelectOutcome::Refused(AutoSelectRefusal::FirstChunk(error)) => {
                    error.path_mismatch().map(str::to_owned)
                }
                AutoSelectOutcome::Refused(AutoSelectRefusal::Snapshot(miss)) => {
                    miss.path_mismatch().map(str::to_owned)
                }
                _ => None,
            };
            if let Some(detail) = mismatch {
                state.poison(&detail);
            }
            self.event(BrowseEvent::AutoSelectDone { act, req, outcome });
        }

        /// The sweep-failure funnel: one place turns a typed mid-sweep error into the honest
        /// outcome AND makes the poisoning decision from the same typed value — a `Partial`
        /// whose cause was a path change cannot skip the poison, because the cause reaches
        /// this funnel typed, not as a sentence inside `detail`.
        pub(crate) fn auto_select_failed(
            &self,
            state: &mut ActorState,
            act: Activation,
            req: RequestId,
            committed: Option<(NonZeroU64, i64)>,
            failure: SweepFailure,
        ) {
            let mismatch = failure.path_mismatch().map(str::to_owned);
            if let Some(detail) = &mismatch {
                state.poison(detail);
            }
            let outcome = match committed {
                Some((committed_groups, last_committed_rank)) => AutoSelectOutcome::Partial {
                    committed_groups,
                    last_committed_rank,
                    cancelled: false,
                    detail: failure.text(),
                },
                None => AutoSelectOutcome::Refused(match failure {
                    SweepFailure::Write(error) => match mismatch {
                        Some(detail) => AutoSelectRefusal::PathChanged { detail },
                        None => AutoSelectRefusal::FirstChunk(error),
                    },
                    SweepFailure::Snapshot(miss) => AutoSelectRefusal::Snapshot(miss),
                    SweepFailure::Read { rank, miss } => AutoSelectRefusal::Read {
                        detail: format!("group rank {rank}: {}", super::miss_text(&miss)),
                    },
                }),
            };
            self.event(BrowseEvent::AutoSelectDone { act, req, outcome });
        }

        /// The one terminal. Deliberately not routed through `finish`: it may be emitted
        /// after the state is gone (the panic path), and it must never poison anything.
        pub(crate) fn closed(&self, actor: ActorId, cause: CloseCause) {
            self.event(BrowseEvent::Closed { actor, cause });
        }
    }
}

/// A typed mid-sweep failure, carried whole to the emit funnel so the outcome and the
/// poisoning decision are made in one place from one value.
pub(crate) enum SweepFailure {
    /// The snapshot or its summaries refused before any group was read.
    Snapshot(MembershipMiss),
    /// One group's member read refused.
    Read { rank: i64, miss: MembershipMiss },
    /// A chunk's durable write refused.
    Write(MarkWriteError),
}

impl SweepFailure {
    fn path_mismatch(&self) -> Option<&str> {
        match self {
            SweepFailure::Snapshot(miss) | SweepFailure::Read { miss, .. } => miss.path_mismatch(),
            SweepFailure::Write(error) => error.path_mismatch(),
        }
    }

    fn text(&self) -> String {
        match self {
            SweepFailure::Snapshot(miss) => format!("membership refused: {}", miss_text(miss)),
            SweepFailure::Read { rank, miss } => {
                format!("group rank {rank} refused: {}", miss_text(miss))
            }
            SweepFailure::Write(error) => format!("mark write refused: {error:?}"),
        }
    }
}

/// One sentence for a typed miss — display only, never control flow. The store keeps its own
/// copy private; duplicating four lines here is cheaper than widening the frozen store surface.
fn miss_text(miss: &MembershipMiss) -> String {
    match miss {
        MembershipMiss::NoSuchScan => "no such scan".into(),
        MembershipMiss::NoSuchGroup => "no such group".into(),
        MembershipMiss::Unknown => "the scan has no membership authority".into(),
        MembershipMiss::Stale { expected, found } => {
            format!("generation {expected} is no longer current ({found} is)")
        }
        MembershipMiss::Inconsistent { detail }
        | MembershipMiss::ReopenRequired { detail }
        | MembershipMiss::Store { detail } => detail.clone(),
    }
}

// ---------------------------------------------------------------------------------------------
// arms — the request handlers
// ---------------------------------------------------------------------------------------------

mod arms {
    use super::emit::Emitter;
    use super::{
        Activation, ActiveScan, ActorState, AutoSelectOutcome, AutoSelectRefusal, BrowseEvent,
        BrowseOpenFailure, BrowseRequest, BrowseRole, CancelToken, ChunkPhase, MarkOutcome,
        OpenedBrowse, PanelData, PanelFailure, PathMismatch, Presentation, RequestId, Slot,
        StoreMiss, SweepFailure,
    };
    use crate::error::AppError;
    use crate::model::duplicate::FileEntry;
    use crate::model::plan::{ActionPlan, GroupId, PlanRefusal, RequestedMark};
    use crate::state::store::{MarkWriteError, MembershipMiss, MembershipMode};
    use std::convert::Infallible;
    use std::num::NonZeroU64;
    use std::path::{Path, PathBuf};

    /// Groups per durable auto-select chunk — the same boundary the wizard's sweep uses
    /// today, kept so cancellation latency and transaction size do not change underfoot.
    const SAVE_CHUNK_GROUPS: usize = 500;

    /// One request, one terminal event. The match is exhaustive on purpose: a variant added
    /// later refuses to compile until it gets a real arm, instead of vanishing into a `_`.
    pub(super) fn handle(state: &mut ActorState, emitter: &Emitter, request: BrowseRequest) {
        match request {
            BrowseRequest::Open { act, req, scan_id } => open(state, emitter, act, req, scan_id),
            BrowseRequest::PanelData {
                act,
                req,
                files,
                dirs,
            } => panel_data(state, emitter, act, req, files, dirs),
            BrowseRequest::GroupOpen {
                act,
                req,
                id,
                offset,
                limit,
            } => group_open(state, emitter, act, req, id, offset, limit),
            BrowseRequest::GroupCount { act, req, id } => group_count(state, emitter, act, req, id),
            BrowseRequest::GroupOfPath { act, req, path } => {
                group_of_path(state, emitter, act, req, path)
            }
            BrowseRequest::FileInfo { act, req, path } => file_info(state, emitter, act, req, path),
            BrowseRequest::DirGroupAt { act, req, dir } => {
                dir_group_at(state, emitter, act, req, dir)
            }
            BrowseRequest::OpenDirGroup {
                act,
                req,
                signature,
            } => open_dir_group(state, emitter, act, req, signature),
            BrowseRequest::MarkedCount { act, req } => marked_count(state, emitter, act, req),
            BrowseRequest::SetMarks { act, req, entries } => {
                set_marks(state, emitter, act, req, entries)
            }
            BrowseRequest::AutoSelect { act, req, cancel } => {
                auto_select(state, emitter, act, req, cancel)
            }
            BrowseRequest::BuildPlan {
                act,
                req,
                requested,
            } => build_plan(state, emitter, act, req, requested),
            BrowseRequest::ReconcileAfterBatch {
                act,
                req,
                attempted,
                cancelled,
            } => reconcile(state, emitter, act, req, attempted, cancelled),
            BrowseRequest::LatestScan { act, req } => latest_scan(state, emitter, act, req),
            BrowseRequest::CoveringScan { act, req, cwd } => {
                covering_scan(state, emitter, act, req, cwd)
            }
            BrowseRequest::ScanCreatedAt { act, req, scan_id } => {
                scan_created_at(state, emitter, act, req, scan_id)
            }
            BrowseRequest::CacheHash {
                act,
                req,
                device,
                inode,
                size,
                mtime,
                digest,
            } => cache_hash(state, emitter, act, req, device, inode, size, mtime, digest),
            // Intercepted by the run loop, which breaks before dispatch; the arm exists so no
            // wildcard can ever hide a new variant.
            BrowseRequest::Shutdown => {}
        }
    }

    /// The typed terminal refusal each request receives once the actor is closing. Queued
    /// requests behind a shutdown run through this instead of the database — every one of
    /// them is a terminal reply for its request id, which is what keeps tickets drainable.
    pub(super) fn refuse_closing(
        state: &mut ActorState,
        emitter: &Emitter,
        request: BrowseRequest,
    ) {
        match request {
            BrowseRequest::Open { act, req, .. } => emitter.finish(
                state,
                Err::<Box<OpenedBrowse>, _>(BrowseOpenFailure::Closing),
                |result| BrowseEvent::OpenFinished { act, req, result },
            ),
            BrowseRequest::PanelData { act, req, .. } => emitter.finish(
                state,
                Err::<Box<PanelData>, _>(PanelFailure::Closing),
                |result| BrowseEvent::PanelData { act, req, result },
            ),
            BrowseRequest::GroupOpen { act, req, .. } => emitter.finish(
                state,
                Err::<super::ResolvedGroup, _>(closing_miss()),
                |result| BrowseEvent::Group { act, req, result },
            ),
            BrowseRequest::GroupCount { act, req, .. } => {
                emitter.finish(state, Err::<u64, _>(closing_miss()), |result| {
                    BrowseEvent::GroupCount { act, req, result }
                })
            }
            BrowseRequest::GroupOfPath { act, req, .. } => {
                emitter.finish(state, Err::<Option<GroupId>, _>(closing_miss()), |result| {
                    BrowseEvent::GroupOfPath { act, req, result }
                })
            }
            BrowseRequest::FileInfo { act, req, .. } => emitter.finish(
                state,
                Err::<Box<super::FileInfoAnswer>, _>(StoreMiss::Closing),
                |result| BrowseEvent::FileInfo { act, req, result },
            ),
            BrowseRequest::DirGroupAt { act, req, .. } => emitter.finish(
                state,
                Err::<super::DirGroupAnswer, _>(StoreMiss::Closing),
                |result| BrowseEvent::DirGroupAt { act, req, result },
            ),
            BrowseRequest::OpenDirGroup { act, req, .. } => emitter.finish(
                state,
                Err::<Option<Box<super::AttributedDirGroup>>, _>(StoreMiss::Closing),
                |result| BrowseEvent::DirGroupOpened { act, req, result },
            ),
            BrowseRequest::MarkedCount { act, req } => {
                emitter.finish(state, Err::<u64, _>(StoreMiss::Closing), |result| {
                    BrowseEvent::MarkedCount { act, req, result }
                })
            }
            BrowseRequest::SetMarks { act, req, .. } => emitter.mark_ack(
                state,
                act,
                req,
                MarkOutcome::Unreadable {
                    error: MarkWriteError::Store {
                        detail: "browsing stopped".to_string(),
                    },
                },
            ),
            BrowseRequest::AutoSelect { act, req, .. } => emitter.auto_select_done(
                state,
                act,
                req,
                AutoSelectOutcome::Refused(AutoSelectRefusal::Closing),
            ),
            BrowseRequest::BuildPlan { act, req, .. } => {
                emitter.finish(state, Err::<Infallible, _>(StoreMiss::Closing), |result| {
                    let refusal = match result {
                        Ok(never) => match never {},
                        Err(_) => PlanRefusal::Store {
                            detail: "browsing stopped".to_string(),
                        },
                    };
                    BrowseEvent::PlanRefused { act, req, refusal }
                })
            }
            BrowseRequest::ReconcileAfterBatch { act, req, .. } => {
                emitter.finish(state, Err::<(), _>(StoreMiss::NotOpen), |result| {
                    BrowseEvent::ReconcileAck { act, req, result }
                })
            }
            BrowseRequest::CacheHash { act, req, .. } => {
                emitter.finish(state, Err::<(), _>(StoreMiss::NotOpen), |result| {
                    BrowseEvent::CacheHashAck { act, req, result }
                })
            }
            BrowseRequest::LatestScan { act, req } => {
                emitter.finish(state, Err::<Option<i64>, _>(StoreMiss::Closing), |result| {
                    BrowseEvent::LatestScan { act, req, result }
                })
            }
            BrowseRequest::CoveringScan { act, req, cwd } => {
                emitter.finish(state, Err::<Option<i64>, _>(StoreMiss::Closing), |result| {
                    BrowseEvent::CoveringScan {
                        act,
                        req,
                        cwd,
                        result,
                    }
                })
            }
            BrowseRequest::ScanCreatedAt { act, req, scan_id } => emitter.finish(
                state,
                Err::<Option<String>, _>(StoreMiss::Closing),
                |result| BrowseEvent::ScanCreatedAt {
                    act,
                    req,
                    scan_id,
                    result,
                },
            ),
            BrowseRequest::Shutdown => {}
        }
    }

    /// PlanRefusal impls `Error`, so `Store { detail }` renders itself; the mark and
    /// membership domains need explicit sentences for the same refusal.
    fn closing_miss() -> MembershipMiss {
        MembershipMiss::Store {
            detail: "browsing stopped".to_string(),
        }
    }

    // ---- typed refusal mappings, one per event error domain, all exhaustive ----

    fn miss_to_membership(miss: StoreMiss) -> MembershipMiss {
        match miss {
            StoreMiss::NotOpen => MembershipMiss::Store {
                detail: "the browsing store is not open".to_string(),
            },
            StoreMiss::Closing => closing_miss(),
            // A poisoned connection IS the reopen-required state, and keeping the typed
            // carrier lets the funnel re-poison idempotently.
            StoreMiss::PathChanged { detail } => MembershipMiss::ReopenRequired { detail },
            StoreMiss::NoActiveScan => MembershipMiss::Store {
                detail: "no scan is installed for browsing".to_string(),
            },
            StoreMiss::StaleActivation { expected, found } => MembershipMiss::Store {
                detail: format!("stale activation: expected {expected}, found {found}"),
            },
            StoreMiss::ReadOnlyRole => MembershipMiss::Store {
                detail: "the observer role may not write".to_string(),
            },
            StoreMiss::NoSuchScan => MembershipMiss::NoSuchScan,
            StoreMiss::Read { detail } => MembershipMiss::Store { detail },
        }
    }

    fn membership_to_miss(miss: MembershipMiss) -> StoreMiss {
        match miss {
            MembershipMiss::ReopenRequired { detail } => StoreMiss::PathChanged { detail },
            MembershipMiss::NoSuchScan => StoreMiss::NoSuchScan,
            MembershipMiss::NoSuchGroup
            | MembershipMiss::Unknown
            | MembershipMiss::Stale { .. }
            | MembershipMiss::Inconsistent { .. }
            | MembershipMiss::Store { .. } => StoreMiss::Read {
                detail: super::miss_text(&miss),
            },
        }
    }

    fn app_to_miss(err: AppError) -> StoreMiss {
        match err.path_mismatch() {
            Some(detail) => StoreMiss::PathChanged {
                detail: detail.to_string(),
            },
            None => StoreMiss::Read {
                detail: err.to_string(),
            },
        }
    }

    fn miss_to_panel(miss: StoreMiss) -> PanelFailure {
        match miss {
            StoreMiss::NotOpen => PanelFailure::NotOpen,
            StoreMiss::Closing => PanelFailure::Closing,
            StoreMiss::PathChanged { detail } => PanelFailure::PathChanged { detail },
            StoreMiss::NoActiveScan => PanelFailure::NoActiveScan,
            StoreMiss::StaleActivation { expected, found } => {
                PanelFailure::StaleActivation { expected, found }
            }
            StoreMiss::ReadOnlyRole => PanelFailure::Snapshot(MembershipMiss::Store {
                detail: "the observer role may not write".to_string(),
            }),
            StoreMiss::NoSuchScan => PanelFailure::Snapshot(MembershipMiss::NoSuchScan),
            StoreMiss::Read { detail } => PanelFailure::Snapshot(MembershipMiss::Store { detail }),
        }
    }

    fn miss_to_mark(miss: StoreMiss) -> MarkWriteError {
        match miss {
            StoreMiss::PathChanged { detail } => MarkWriteError::PathChanged { detail },
            StoreMiss::Closing => MarkWriteError::Store {
                detail: "browsing stopped".to_string(),
            },
            StoreMiss::NotOpen => MarkWriteError::Store {
                detail: "the browsing store is not open".to_string(),
            },
            StoreMiss::NoActiveScan => MarkWriteError::Store {
                detail: "no scan is installed for browsing".to_string(),
            },
            StoreMiss::StaleActivation { expected, found } => MarkWriteError::Store {
                detail: format!("stale activation: expected {expected}, found {found}"),
            },
            StoreMiss::ReadOnlyRole => MarkWriteError::Store {
                detail: "the observer role may not write marks".to_string(),
            },
            StoreMiss::NoSuchScan => MarkWriteError::Store {
                detail: "no such scan".to_string(),
            },
            StoreMiss::Read { detail } => MarkWriteError::Store { detail },
        }
    }

    fn miss_to_auto(miss: StoreMiss) -> AutoSelectRefusal {
        match miss {
            StoreMiss::Closing => AutoSelectRefusal::Closing,
            StoreMiss::NotOpen => AutoSelectRefusal::NotOpen,
            StoreMiss::PathChanged { detail } => AutoSelectRefusal::PathChanged { detail },
            StoreMiss::NoActiveScan => AutoSelectRefusal::NoActiveScan,
            StoreMiss::StaleActivation { expected, found } => {
                AutoSelectRefusal::StaleActivation { expected, found }
            }
            StoreMiss::ReadOnlyRole => AutoSelectRefusal::ReadOnlyRole,
            StoreMiss::NoSuchScan => AutoSelectRefusal::Snapshot(MembershipMiss::NoSuchScan),
            StoreMiss::Read { detail } => {
                AutoSelectRefusal::Snapshot(MembershipMiss::Store { detail })
            }
        }
    }

    fn miss_to_plan(miss: StoreMiss) -> PlanRefusal {
        PlanRefusal::Store {
            detail: match miss {
                StoreMiss::Closing => "browsing stopped".to_string(),
                StoreMiss::NotOpen => "the browsing store is not open".to_string(),
                StoreMiss::PathChanged { detail } => detail,
                StoreMiss::NoActiveScan => "no scan is installed for browsing".to_string(),
                StoreMiss::StaleActivation { expected, found } => {
                    format!("stale activation: expected {expected}, found {found}")
                }
                StoreMiss::ReadOnlyRole => "the observer role may not write".to_string(),
                StoreMiss::NoSuchScan => "no such scan".to_string(),
                StoreMiss::Read { detail } => detail,
            },
        }
    }

    // ---- the Open arm ----

    /// A candidate step's failure, classified from the TYPE of its error: a path mismatch has
    /// exactly one destination (class B), everything else keeps the previously installed
    /// scan (class A).
    enum CandidateFail {
        Typed(BrowseOpenFailure),
        Mismatch { detail: String },
    }

    fn classify_app(
        err: AppError,
        into: impl FnOnce(String) -> BrowseOpenFailure,
    ) -> CandidateFail {
        match err.path_mismatch() {
            Some(detail) => CandidateFail::Mismatch {
                detail: detail.to_string(),
            },
            None => CandidateFail::Typed(into(err.to_string())),
        }
    }

    fn classify_miss(
        miss: MembershipMiss,
        into: impl FnOnce(MembershipMiss) -> BrowseOpenFailure,
    ) -> CandidateFail {
        match &miss {
            MembershipMiss::ReopenRequired { detail } => CandidateFail::Mismatch {
                detail: detail.clone(),
            },
            MembershipMiss::NoSuchScan => CandidateFail::Typed(BrowseOpenFailure::NoSuchScan),
            _ => CandidateFail::Typed(into(miss)),
        }
    }

    struct Candidate {
        payload: OpenedBrowse,
        algo: crate::model::duplicate::DirSigAlgo,
    }

    /// `Open`: reuse-or-open by the actor's own role, then build the COMPLETE candidate
    /// without touching `active`, then install atomically. Failure never leaves the two
    /// sides describing different scans: class A changes nothing, class B uninstalls both —
    /// and once a typed mismatch has discarded the previous pair, EVERY later failure of
    /// this `Open` is class B, because no previous state is left for class A to keep.
    fn open(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        scan_id: i64,
    ) {
        // 1. The reuse-or-open bracket. The typed mismatch that discards a live pair is
        //    RETAINED, never reduced to a boolean: it decides the class of every failure
        //    below. `Open` is the one request allowed to rebuild from a poisoned slot, which
        //    is exactly why it is exempt from the gate.
        let retained: Option<String> = match &state.slot {
            Slot::Open(door) => match door.identity_check() {
                Ok(()) => None,
                Err(err) => Some(match err.path_mismatch() {
                    Some(detail) => detail.to_string(),
                    // `ensure_current_path` refuses only through `PathChanged` today; should
                    // a different shape ever reach here, the identity is still unproven, and
                    // an unproven identity discards exactly like a proven mismatch.
                    None => err.to_string(),
                }),
            },
            Slot::Poisoned { detail } => Some(detail.clone()),
            Slot::Absent => None,
        };
        let healthy_reuse = matches!(&state.slot, Slot::Open(_)) && retained.is_none();
        if !healthy_reuse {
            state.active = None;
            state.slot = Slot::Absent;
            match super::guarded::BrowsingStore::open(&state.db, state.role) {
                Ok(door) => state.slot = Slot::Open(Box::new(door)),
                Err(err) => {
                    // No connection could be established. With a retained mismatch this is
                    // class B whatever the open error says: the pair is already gone, and
                    // the pathname holds something that is not the checkpoint. The fresh
                    // context rides along for diagnostics only — the class comes from the
                    // retained type, never from error text.
                    let failure = match (err.path_mismatch(), &retained) {
                        (Some(detail), _) => {
                            let detail = detail.to_string();
                            state.poison(&detail);
                            BrowseOpenFailure::PathChanged { detail }
                        }
                        (None, Some(mismatch)) => {
                            let detail = format!("{mismatch}; reopening also failed: {err}");
                            state.poison(&detail);
                            BrowseOpenFailure::PathChanged { detail }
                        }
                        // Nothing was installed and nothing was discarded: an ordinary
                        // class-A open failure over an empty slot.
                        (None, None) => BrowseOpenFailure::Open {
                            detail: err.to_string(),
                        },
                    };
                    emitter.finish(state, Err::<Box<OpenedBrowse>, _>(failure), |result| {
                        BrowseEvent::OpenFinished { act, req, result }
                    });
                    return;
                }
            }
        }
        // 2. The complete candidate, before any installation.
        let built = build_candidate(state, scan_id);
        // 3. Exactly one of: install, class-A refusal, class-B uninstall. A retained
        //    mismatch turns even a typed candidate refusal into class B: the reopened
        //    checkpoint may be healthy, but the pair this `Open` discarded is not coming
        //    back, and class A would tell the consumer to keep serving it.
        match (built, retained) {
            (Ok(candidate), _) => {
                state.active = Some(ActiveScan {
                    scan_id,
                    act,
                    dir_sig_algo: candidate.algo,
                });
                emitter.finish(
                    state,
                    Ok::<_, BrowseOpenFailure>(Box::new(candidate.payload)),
                    |result| BrowseEvent::OpenFinished { act, req, result },
                );
            }
            (Err(CandidateFail::Typed(failure)), None) => {
                emitter.finish(state, Err::<Box<OpenedBrowse>, _>(failure), |result| {
                    BrowseEvent::OpenFinished { act, req, result }
                });
            }
            (Err(CandidateFail::Typed(failure)), Some(mismatch)) => {
                let detail =
                    format!("{mismatch}; the reopened checkpoint then refused: {failure:?}");
                state.poison(&detail);
                emitter.finish(
                    state,
                    Err::<Box<OpenedBrowse>, _>(BrowseOpenFailure::PathChanged { detail }),
                    |result| BrowseEvent::OpenFinished { act, req, result },
                );
            }
            (Err(CandidateFail::Mismatch { detail }), _) => {
                state.poison(&detail);
                emitter.finish(
                    state,
                    Err::<Box<OpenedBrowse>, _>(BrowseOpenFailure::PathChanged { detail }),
                    |result| BrowseEvent::OpenFinished { act, req, result },
                );
            }
        }
    }

    /// Every read the open payload needs, in the probe order the report tables. The one
    /// honest gap is `prepare_legacy_for_viewing`: the store wraps its inner refusals in
    /// `AppError::Msg`, so a path replaced exactly between the bracket and `prepare` is
    /// classified A here — and caught typed by the very next request's probe. The window is
    /// stated rather than papered over; retyping `prepare` means changing the frozen store.
    fn build_candidate(state: &mut ActorState, scan_id: i64) -> Result<Candidate, CandidateFail> {
        let role = state.role;
        let hooks = state.hooks.clone();
        let step = |name: &'static str| hooks.fire_open_step(name);
        let Slot::Open(door) = &mut state.slot else {
            return Err(CandidateFail::Typed(BrowseOpenFailure::Open {
                detail: "the browsing store is not open".to_string(),
            }));
        };
        if role == BrowseRole::Operator {
            step("prepare");
            door.prepare_legacy_for_viewing(scan_id)
                .map_err(|err| classify_app(err, |detail| BrowseOpenFailure::Prepare { detail }))?;
        }
        step("snapshot");
        let presentation = {
            let snapshot = door
                .membership_snapshot(scan_id)
                .map_err(|miss| classify_miss(miss, BrowseOpenFailure::Snapshot))?;
            if snapshot.mode() == MembershipMode::Unknown {
                let candidates = snapshot
                    .unknown_candidates()
                    .map_err(|miss| classify_miss(miss, BrowseOpenFailure::Summaries))?;
                match candidates {
                    Some(view) => Presentation::Unpublished(view),
                    // Unreachable by construction — the mode WAS Unknown — refused rather
                    // than papered over with an empty view.
                    None => {
                        return Err(CandidateFail::Typed(BrowseOpenFailure::Summaries(
                            MembershipMiss::Store {
                                detail: "the candidate view is missing for an Unknown scan"
                                    .to_string(),
                            },
                        )))
                    }
                }
            } else {
                Presentation::Published(
                    snapshot
                        .summaries()
                        .map_err(|miss| classify_miss(miss, BrowseOpenFailure::Summaries))?,
                )
            }
        };
        step("config");
        let config = door
            .load_config(scan_id)
            .map_err(|err| classify_app(err, |detail| BrowseOpenFailure::Config { detail }))?;
        step("status");
        let status = door
            .scan_status(scan_id)
            .map_err(|err| classify_app(err, |detail| BrowseOpenFailure::ScanStatus { detail }))?;
        step("summary");
        let summary = door
            .scan_summary(scan_id)
            .map_err(|err| classify_app(err, |detail| BrowseOpenFailure::ScanSummary { detail }))?;
        step("created_at");
        let created_at = door
            .scan_created_at(scan_id)
            .map_err(|err| classify_app(err, |detail| BrowseOpenFailure::CreatedAt { detail }))?;
        step("marked");
        let marked_count = door
            .marked_count(scan_id)
            .map_err(|err| classify_app(err, |detail| BrowseOpenFailure::MarkedCount { detail }))?;
        step("dir_groups");
        let dir_groups = door
            .attributed_dir_group_summaries(scan_id)
            .map_err(|err| classify_app(err, |detail| BrowseOpenFailure::DirGroups { detail }))?;
        Ok(Candidate {
            payload: OpenedBrowse {
                scan_id,
                status,
                created_at,
                summary,
                marked_count,
                dir_groups,
                presentation,
            },
            algo: config.dir_sig_algo,
        })
    }

    // ---- scan-scoped readers ----

    fn panel_data(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        files: Vec<PathBuf>,
        dirs: Vec<PathBuf>,
    ) {
        let scan_id = match state.scan_gate(act, false) {
            Ok(scan_id) => scan_id,
            Err(miss) => {
                let failure = miss_to_panel(miss);
                emitter.finish(state, Err::<Box<PanelData>, _>(failure), |result| {
                    BrowseEvent::PanelData { act, req, result }
                });
                return;
            }
        };
        let algo = state.dir_sig_algo();
        let step = {
            let Slot::Open(door) = &mut state.slot else {
                emitter.finish(
                    state,
                    Err::<Box<PanelData>, _>(PanelFailure::NotOpen),
                    |result| BrowseEvent::PanelData { act, req, result },
                );
                return;
            };
            (|| {
                let file_answers = {
                    let snapshot = door
                        .membership_snapshot(scan_id)
                        .map_err(PanelFailure::Snapshot)?;
                    let refs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
                    snapshot.panel_files(&refs).map_err(|miss| {
                        // The batch itself refused (per-row misses are typed INSIDE the
                        // answers) — that is the file half failing, with the miss preserved
                        // where it carries a reopen.
                        match miss {
                            MembershipMiss::ReopenRequired { detail } => {
                                PanelFailure::PathChanged { detail }
                            }
                            other => PanelFailure::Files {
                                detail: super::miss_text(&other),
                            },
                        }
                    })?
                };
                let dir_fail = |err: AppError| match err.path_mismatch() {
                    Some(detail) => PanelFailure::PathChanged {
                        detail: detail.to_string(),
                    },
                    None => PanelFailure::Directories {
                        detail: err.to_string(),
                    },
                };
                let dir_sizes = door.dir_sizes_under(scan_id, &dirs).map_err(dir_fail)?;
                let dir_signatures = door
                    .dir_signatures_under(scan_id, &dirs, algo)
                    .map_err(dir_fail)?;
                Ok(PanelData {
                    files: file_answers,
                    dir_sizes,
                    dir_signatures,
                })
            })()
        };
        emitter.finish(state, step, |result| BrowseEvent::PanelData {
            act,
            req,
            result: result.map(Box::new),
        });
    }

    fn group_open(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        id: GroupId,
        offset: usize,
        limit: usize,
    ) {
        let step = match state.scan_gate(act, false) {
            Err(miss) => Err(miss_to_membership(miss)),
            Ok(scan_id) => match state.slot {
                Slot::Open(ref door) => door
                    .membership_snapshot(scan_id)
                    .and_then(|snapshot| snapshot.group_page(&id, offset, limit)),
                Slot::Absent | Slot::Poisoned { .. } => Err(miss_to_membership(StoreMiss::NotOpen)),
            },
        };
        emitter.finish(state, step, |result| BrowseEvent::Group {
            act,
            req,
            result,
        });
    }

    fn group_count(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        id: GroupId,
    ) {
        let step = match state.scan_gate(act, false) {
            Err(miss) => Err(miss_to_membership(miss)),
            Ok(scan_id) => match state.slot {
                Slot::Open(ref door) => door
                    .membership_snapshot(scan_id)
                    .and_then(|snapshot| snapshot.group_member_count(&id)),
                Slot::Absent | Slot::Poisoned { .. } => Err(miss_to_membership(StoreMiss::NotOpen)),
            },
        };
        emitter.finish(state, step, |result| BrowseEvent::GroupCount {
            act,
            req,
            result,
        });
    }

    fn group_of_path(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        path: PathBuf,
    ) {
        let step = match state.scan_gate(act, false) {
            Err(miss) => Err(miss_to_membership(miss)),
            Ok(scan_id) => match state.slot {
                Slot::Open(ref door) => door
                    .membership_snapshot(scan_id)
                    .and_then(|snapshot| snapshot.group_of_path(&path)),
                Slot::Absent | Slot::Poisoned { .. } => Err(miss_to_membership(StoreMiss::NotOpen)),
            },
        };
        emitter.finish(state, step, |result| BrowseEvent::GroupOfPath {
            act,
            req,
            result,
        });
    }

    fn file_info(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        path: PathBuf,
    ) {
        let step = match state.scan_gate(act, false) {
            Err(miss) => Err(miss),
            Ok(scan_id) => match state.slot {
                Slot::Open(ref door) => door
                    .membership_snapshot(scan_id)
                    .and_then(|snapshot| snapshot.file_info(&path))
                    .map_err(membership_to_miss),
                Slot::Absent | Slot::Poisoned { .. } => Err(StoreMiss::NotOpen),
            },
        };
        emitter.finish(state, step, |result| BrowseEvent::FileInfo {
            act,
            req,
            result: result.map(Box::new),
        });
    }

    fn dir_group_at(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        dir: PathBuf,
    ) {
        let step = match state.scan_gate(act, false) {
            Err(miss) => Err(miss),
            Ok(scan_id) => match state.slot {
                Slot::Open(ref door) => door
                    .membership_snapshot(scan_id)
                    .and_then(|snapshot| snapshot.dir_group_at(&dir))
                    .map_err(membership_to_miss),
                Slot::Absent | Slot::Poisoned { .. } => Err(StoreMiss::NotOpen),
            },
        };
        emitter.finish(state, step, |result| BrowseEvent::DirGroupAt {
            act,
            req,
            result,
        });
    }

    fn open_dir_group(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        signature: String,
    ) {
        let step = match state.scan_gate(act, false) {
            Err(miss) => Err(miss),
            Ok(scan_id) => match state.slot {
                Slot::Open(ref door) => door
                    .attributed_dir_group(scan_id, &signature)
                    .map_err(app_to_miss)
                    .map(|group| group.map(Box::new)),
                Slot::Absent | Slot::Poisoned { .. } => Err(StoreMiss::NotOpen),
            },
        };
        emitter.finish(state, step, |result| BrowseEvent::DirGroupOpened {
            act,
            req,
            result,
        });
    }

    fn marked_count(state: &mut ActorState, emitter: &Emitter, act: Activation, req: RequestId) {
        let step = match state.scan_gate(act, false) {
            Err(miss) => Err(miss),
            Ok(scan_id) => match state.slot {
                Slot::Open(ref door) => door.marked_count(scan_id).map_err(app_to_miss),
                Slot::Absent | Slot::Poisoned { .. } => Err(StoreMiss::NotOpen),
            },
        };
        emitter.finish(state, step, |result| BrowseEvent::MarkedCount {
            act,
            req,
            result,
        });
    }

    // ---- mutators ----

    fn set_marks(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        entries: Vec<FileEntry>,
    ) {
        let outcome = match state.scan_gate(act, true) {
            Err(miss) => MarkOutcome::Unreadable {
                error: miss_to_mark(miss),
            },
            Ok(scan_id) => match state.slot {
                Slot::Open(ref mut door) => match door.save_marks_settled(scan_id, &entries) {
                    Ok(after) => MarkOutcome::Settled { after },
                    Err(error) => MarkOutcome::Unreadable { error },
                },
                Slot::Absent | Slot::Poisoned { .. } => MarkOutcome::Unreadable {
                    error: miss_to_mark(StoreMiss::NotOpen),
                },
            },
        };
        emitter.mark_ack(state, act, req, outcome);
    }

    /// Keeps the newest file; on an mtime tie the shorter pathname wins — the same choice the
    /// wizard's sweep makes today, so the cutover cannot silently change which file survives.
    fn pick_keeper(files: &[FileEntry]) -> usize {
        files
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| {
                a.mtime
                    .cmp(&b.mtime)
                    .then_with(|| b.path.as_os_str().len().cmp(&a.path.as_os_str().len()))
            })
            .map(|(index, _)| index)
            .unwrap_or(0)
    }

    fn auto_select(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        cancel: CancelToken,
    ) {
        let scan_id = match state.scan_gate(act, true) {
            Ok(scan_id) => scan_id,
            Err(miss) => {
                let refusal = miss_to_auto(miss);
                emitter.auto_select_done(state, act, req, AutoSelectOutcome::Refused(refusal));
                return;
            }
        };
        let closing = state.closing.clone();
        let hooks = state.hooks.clone();
        let sweep = {
            let Slot::Open(door) = &mut state.slot else {
                emitter.auto_select_done(
                    state,
                    act,
                    req,
                    AutoSelectOutcome::Refused(AutoSelectRefusal::NotOpen),
                );
                return;
            };
            run_sweep(door, scan_id, &cancel, &closing, &hooks)
        };
        match sweep {
            SweepEnd::Unknown => emitter.auto_select_done(
                state,
                act,
                req,
                AutoSelectOutcome::Refused(AutoSelectRefusal::Unknown),
            ),
            SweepEnd::Done { groups, marks } => emitter.auto_select_done(
                state,
                act,
                req,
                AutoSelectOutcome::Completed { groups, marks },
            ),
            SweepEnd::CancelledEarly => emitter.auto_select_done(
                state,
                act,
                req,
                AutoSelectOutcome::Refused(AutoSelectRefusal::CancelledBeforeFirstCommit),
            ),
            SweepEnd::CancelledAfter { groups, last_rank } => emitter.auto_select_done(
                state,
                act,
                req,
                AutoSelectOutcome::Partial {
                    committed_groups: groups,
                    last_committed_rank: last_rank,
                    cancelled: true,
                    detail: "cancelled by the operator".to_string(),
                },
            ),
            SweepEnd::Failed { committed, failure } => {
                emitter.auto_select_failed(state, act, req, committed, failure)
            }
        }
    }

    enum SweepEnd {
        Unknown,
        Done {
            groups: u64,
            marks: u64,
        },
        CancelledEarly,
        CancelledAfter {
            groups: NonZeroU64,
            last_rank: i64,
        },
        Failed {
            committed: Option<(NonZeroU64, i64)>,
            failure: SweepFailure,
        },
    }

    /// The auto-select sweep: trusted membership only, durable in chunks, cancellable at
    /// every chunk boundary.
    ///
    /// Each chunk takes its own snapshot, because a snapshot's read transaction and the
    /// chunk's own write cannot coexist on the one connection — the first chunk reuses the
    /// snapshot that read the summaries, so a single-chunk sweep spends exactly one snapshot
    /// and one write. A group whose read refuses stops the sweep whole: skipping it would
    /// filter corruption into a smaller sweep that looks entirely valid.
    fn run_sweep(
        door: &mut super::guarded::BrowsingStore,
        scan_id: i64,
        cancel: &CancelToken,
        closing: &std::sync::Arc<std::sync::atomic::AtomicBool>,
        hooks: &super::TestHooks,
    ) -> SweepEnd {
        use std::sync::atomic::Ordering;
        let stop = |cancel: &CancelToken| cancel.cancelled() || closing.load(Ordering::SeqCst);
        // The group list, in rank order, from the same snapshot kind every trusted reader
        // uses. Read once; each chunk re-resolves its own members against a fresh snapshot.
        let ids: Vec<GroupId> = {
            let snapshot = match door.membership_snapshot(scan_id) {
                Ok(snapshot) => snapshot,
                Err(miss) => {
                    return SweepEnd::Failed {
                        committed: None,
                        failure: SweepFailure::Snapshot(miss),
                    }
                }
            };
            if snapshot.mode() == MembershipMode::Unknown {
                return SweepEnd::Unknown;
            }
            match snapshot.summaries() {
                Ok(summaries) => summaries.groups.iter().map(|(id, _)| *id).collect(),
                Err(miss) => {
                    return SweepEnd::Failed {
                        committed: None,
                        failure: SweepFailure::Snapshot(miss),
                    }
                }
            }
        };
        let mut committed_groups: u64 = 0;
        let mut last_rank: i64 = 0;
        let mut marks: u64 = 0;
        let committed_so_far =
            |groups: u64, rank: i64| NonZeroU64::new(groups).map(|nonzero| (nonzero, rank));
        let mut chunk_index = 0usize;
        for chunk in ids.chunks(SAVE_CHUNK_GROUPS) {
            chunk_index += 1;
            if stop(cancel) {
                return match committed_so_far(committed_groups, last_rank) {
                    None => SweepEnd::CancelledEarly,
                    Some((groups, rank)) => SweepEnd::CancelledAfter {
                        groups,
                        last_rank: rank,
                    },
                };
            }
            let mut batch: Vec<FileEntry> = Vec::new();
            let mut chunk_marks: u64 = 0;
            {
                let snapshot = match door.membership_snapshot(scan_id) {
                    Ok(snapshot) => snapshot,
                    Err(miss) => {
                        return SweepEnd::Failed {
                            committed: committed_so_far(committed_groups, last_rank),
                            failure: SweepFailure::Snapshot(miss),
                        }
                    }
                };
                for id in chunk {
                    let group = match snapshot.group(id) {
                        Ok(group) => group,
                        Err(miss) => {
                            return SweepEnd::Failed {
                                committed: committed_so_far(committed_groups, last_rank),
                                failure: SweepFailure::Read {
                                    rank: id.rank,
                                    miss,
                                },
                            }
                        }
                    };
                    let mut members = group.members;
                    if members.is_empty() {
                        continue;
                    }
                    let keeper = pick_keeper(&members);
                    for (index, file) in members.iter_mut().enumerate() {
                        file.is_keeper = index == keeper;
                        file.action = if index == keeper {
                            None
                        } else {
                            chunk_marks += 1;
                            Some(crate::model::action::ActionKind::Delete)
                        };
                    }
                    batch.append(&mut members);
                }
            }
            hooks.fire_chunk(ChunkPhase::BeforeWrite(chunk_index));
            if let Err(error) = door.save_marks_settled(scan_id, &batch) {
                return SweepEnd::Failed {
                    committed: committed_so_far(committed_groups, last_rank),
                    failure: SweepFailure::Write(error),
                };
            }
            hooks.fire_chunk(ChunkPhase::AfterCommit(chunk_index));
            committed_groups += chunk.len() as u64;
            marks += chunk_marks;
            if let Some(last) = chunk.last() {
                last_rank = last.rank;
            }
        }
        SweepEnd::Done {
            groups: committed_groups,
            marks,
        }
    }

    fn build_plan(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        requested: Vec<RequestedMark>,
    ) {
        // A gate refusal travels typed through the funnel — a lazily-opened connection that
        // died of a path mismatch must poison here exactly as it does for every other arm —
        // and only then becomes the plan's own refusal wording.
        let scan_id = match state.scan_gate(act, false) {
            Ok(scan_id) => scan_id,
            Err(miss) => {
                emitter.finish(state, Err::<Infallible, _>(miss), |result| {
                    let refusal = match result {
                        Ok(never) => match never {},
                        Err(miss) => miss_to_plan(miss),
                    };
                    BrowseEvent::PlanRefused { act, req, refusal }
                });
                return;
            }
        };
        let step: Result<crate::model::plan::PlanResult<ActionPlan>, AppError> = match state.slot {
            Slot::Open(ref door) => door.build_action_plan(scan_id, &requested),
            Slot::Absent | Slot::Poisoned { .. } => Ok(Err(miss_to_plan(StoreMiss::NotOpen))),
        };
        emitter.finish(state, step, |result| match result {
            Ok(Ok(plan)) => BrowseEvent::PlanReady {
                act,
                req,
                plan: Box::new(plan),
            },
            Ok(Err(refusal)) => BrowseEvent::PlanRefused { act, req, refusal },
            Err(err) => BrowseEvent::PlanRefused {
                act,
                req,
                refusal: PlanRefusal::Store {
                    detail: err.to_string(),
                },
            },
        });
    }

    fn reconcile(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        attempted: Vec<PathBuf>,
        cancelled: bool,
    ) {
        let step = match state.scan_gate(act, true) {
            Err(miss) => Err(miss),
            Ok(scan_id) => match state.slot {
                Slot::Open(ref mut door) => door
                    .reconcile_marks_after_batch(scan_id, &attempted, cancelled)
                    .map_err(app_to_miss),
                Slot::Absent | Slot::Poisoned { .. } => Err(StoreMiss::NotOpen),
            },
        };
        emitter.finish(state, step, |result| BrowseEvent::ReconcileAck {
            act,
            req,
            result,
        });
    }

    // ---- connection-scoped requests: the frozen exemption list ----

    fn latest_scan(state: &mut ActorState, emitter: &Emitter, act: Activation, req: RequestId) {
        let step = match state.connection_gate(false) {
            Err(miss) => Err(miss),
            Ok(()) => match state.slot {
                Slot::Open(ref door) => door.latest_scan_id().map_err(app_to_miss),
                Slot::Absent | Slot::Poisoned { .. } => Err(StoreMiss::NotOpen),
            },
        };
        emitter.finish(state, step, |result| BrowseEvent::LatestScan {
            act,
            req,
            result,
        });
    }

    fn covering_scan(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        cwd: PathBuf,
    ) {
        let step = match state.connection_gate(false) {
            Err(miss) => Err(miss),
            Ok(()) => match state.slot {
                Slot::Open(ref door) => door.latest_scan_covering(&cwd).map_err(app_to_miss),
                Slot::Absent | Slot::Poisoned { .. } => Err(StoreMiss::NotOpen),
            },
        };
        emitter.finish(state, step, |result| BrowseEvent::CoveringScan {
            act,
            req,
            cwd,
            result,
        });
    }

    fn scan_created_at(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        scan_id: i64,
    ) {
        let step = match state.connection_gate(false) {
            Err(miss) => Err(miss),
            Ok(()) => match state.slot {
                Slot::Open(ref door) => door.scan_created_at(scan_id).map_err(app_to_miss),
                Slot::Absent | Slot::Poisoned { .. } => Err(StoreMiss::NotOpen),
            },
        };
        emitter.finish(state, step, |result| BrowseEvent::ScanCreatedAt {
            act,
            req,
            scan_id,
            result,
        });
    }

    #[allow(clippy::too_many_arguments)] // the frozen protocol carries the full identity key
    fn cache_hash(
        state: &mut ActorState,
        emitter: &Emitter,
        act: Activation,
        req: RequestId,
        device: u64,
        inode: u64,
        size: u64,
        mtime: i64,
        digest: [u8; 32],
    ) {
        let step = match state.connection_gate(true) {
            Err(miss) => Err(miss),
            Ok(()) => match state.slot {
                Slot::Open(ref mut door) => door
                    .upsert_hash(device, inode, size, mtime, &digest)
                    .map_err(app_to_miss),
                Slot::Absent | Slot::Poisoned { .. } => Err(StoreMiss::NotOpen),
            },
        };
        emitter.finish(state, step, |result| BrowseEvent::CacheHashAck {
            act,
            req,
            result,
        });
    }
}

// ---------------------------------------------------------------------------------------------
// Tests — the only driver of this module until R4B-2c
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::action::ActionKind;
    use crate::model::scan::ScanConfig;
    use crate::state::store::{ManifestRow, PublishMode, ScanStore};
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::time::Duration;

    // ---- fixtures -------------------------------------------------------------------------

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "dedcom_browse_{tag}_{}_{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn manifest_row(path: &Path) -> ManifestRow {
        let meta = std::fs::symlink_metadata(path).unwrap();
        ManifestRow {
            path: path.to_path_buf(),
            size: meta.size(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            device: meta.dev(),
            inode: meta.ino(),
            nlink: meta.nlink(),
        }
    }

    /// A scan whose digests this build verified against the files — the only kind the plan
    /// evidence accepts.
    fn seed_verified(store: &mut ScanStore, root: &Path, files: &[(PathBuf, [u8; 32])]) -> i64 {
        let scan_id = store
            .begin_scan(&ScanConfig::new(vec![root.to_path_buf()]))
            .unwrap();
        let rows: Vec<ManifestRow> = files.iter().map(|(path, _)| manifest_row(path)).collect();
        store.record_files(scan_id, &rows).unwrap();
        let verified: Vec<(ManifestRow, [u8; 32])> = files
            .iter()
            .map(|(path, digest)| (manifest_row(path), *digest))
            .collect();
        store.record_hashes_verified(scan_id, &verified).unwrap();
        // A finished scan, as browsing meets one: `latest_scan_covering` only covers a
        // completed status, and an open payload reports it.
        store
            .set_status(scan_id, crate::model::scan::ScanStatus::Complete)
            .unwrap();
        scan_id
    }

    fn publish_explicit(store: &mut ScanStore, scan_id: i64) {
        let verified =
            crate::pipeline::verify::verify_groups(store.duplicate_groups(scan_id).unwrap())
                .unwrap();
        store
            .publish_results(scan_id, PublishMode::Explicit(&verified))
            .unwrap();
    }

    /// Two byte-equal pairs → two published Explicit groups.
    fn seeded_db(tag: &str) -> (PathBuf, PathBuf, i64, [PathBuf; 4]) {
        let dir = temp_dir(tag);
        let db = dir.join("dedcom.db");
        let a1 = write(&dir, "a1.bin", b"AAAA");
        let a2 = write(&dir, "a2.bin", b"AAAA");
        let b1 = write(&dir, "b1.bin", b"BBBBBB");
        let b2 = write(&dir, "b2.bin", b"BBBBBB");
        let mut store = ScanStore::open_writable(&db).unwrap();
        let scan_id = seed_verified(
            &mut store,
            &dir,
            &[
                (a1.clone(), [0xAAu8; 32]),
                (a2.clone(), [0xAAu8; 32]),
                (b1.clone(), [0xBBu8; 32]),
                (b2.clone(), [0xBBu8; 32]),
            ],
        );
        publish_explicit(&mut store, scan_id);
        drop(store);
        (dir, db, scan_id, [a1, a2, b1, b2])
    }

    /// `pairs` byte-equal pairs → that many published Explicit groups, for multi-chunk sweeps.
    fn many_groups_db(tag: &str, pairs: usize) -> (PathBuf, PathBuf, i64) {
        let dir = temp_dir(tag);
        let db = dir.join("dedcom.db");
        let mut files: Vec<(PathBuf, [u8; 32])> = Vec::with_capacity(pairs * 2);
        for index in 0..pairs {
            let payload = format!("payload {index:05}");
            let mut digest = [0u8; 32];
            digest[..8].copy_from_slice(&(index as u64).to_le_bytes());
            digest[31] = 1;
            let first = write(&dir, &format!("g{index:05}_a.bin"), payload.as_bytes());
            let second = write(&dir, &format!("g{index:05}_b.bin"), payload.as_bytes());
            files.push((first, digest));
            files.push((second, digest));
        }
        let mut store = ScanStore::open_writable(&db).unwrap();
        let scan_id = seed_verified(&mut store, &dir, &files);
        publish_explicit(&mut store, scan_id);
        drop(store);
        (dir, db, scan_id)
    }

    /// An ordinary operator replacement: the checkpoint moves aside, something else takes the
    /// pathname.
    fn swap_away(db: &Path) -> PathBuf {
        let aside = db.with_extension("aside");
        std::fs::rename(db, &aside).unwrap();
        std::fs::write(db, b"not the checkpoint").unwrap();
        aside
    }

    fn swap_back(db: &Path, aside: &Path) {
        std::fs::remove_file(db).unwrap();
        std::fs::rename(aside, db).unwrap();
    }

    struct ChannelSink(Sender<BrowseEvent>);

    impl BrowseSink for ChannelSink {
        fn emit(&self, event: BrowseEvent) {
            let _ = self.0.send(event);
        }
    }

    fn sink() -> (Box<dyn BrowseSink>, Receiver<BrowseEvent>) {
        let (tx, rx) = crossbeam_channel::unbounded();
        (Box::new(ChannelSink(tx)), rx)
    }

    /// One spawned actor over one seeded database, plus everything a test needs to drive it.
    struct Rig {
        dir: PathBuf,
        db: PathBuf,
        scan_id: i64,
        files: [PathBuf; 4],
        actor: ActorId,
        handle: BrowseHandle,
        join: Option<JoinHandle<()>>,
        events: Receiver<BrowseEvent>,
        hooks: TestHooks,
        ids: RequestIds,
    }

    impl Rig {
        fn new(tag: &str, role: BrowseRole) -> Rig {
            let (dir, db, scan_id, files) = seeded_db(tag);
            Rig::over(dir, db, scan_id, files, role)
        }

        fn over(
            dir: PathBuf,
            db: PathBuf,
            scan_id: i64,
            files: [PathBuf; 4],
            role: BrowseRole,
        ) -> Rig {
            let hooks = TestHooks::default();
            let (sink, events) = sink();
            let (actor, handle, join) =
                BrowseActor::spawn_with_hooks(db.clone(), role, sink, hooks.clone());
            Rig {
                dir,
                db,
                scan_id,
                files,
                actor,
                handle,
                join: Some(join),
                events,
                hooks,
                ids: RequestIds::default(),
            }
        }

        fn req(&mut self) -> RequestId {
            self.ids.allocate()
        }

        fn recv(&self) -> BrowseEvent {
            self.events
                .recv_timeout(Duration::from_secs(10))
                .expect("the actor must settle every request")
        }

        fn open(&mut self, act: u64) -> Box<OpenedBrowse> {
            let req = self.req();
            assert!(self.handle.send_raw(BrowseRequest::Open {
                act: Activation(act),
                req,
                scan_id: self.scan_id,
            }));
            match self.recv() {
                BrowseEvent::OpenFinished {
                    req: got,
                    result: Ok(payload),
                    ..
                } => {
                    assert_eq!(got, req);
                    payload
                }
                other => panic!("open must succeed: {other:?}"),
            }
        }

        fn published_ids(payload: &OpenedBrowse) -> Vec<GroupId> {
            match &payload.presentation {
                Presentation::Published(summaries) => {
                    summaries.groups.iter().map(|(id, _)| *id).collect()
                }
                Presentation::Unpublished(_) => panic!("the fixture publishes"),
            }
        }

        /// Marked count through the actor itself, so the assertion needs no second connection.
        fn marked(&mut self, act: u64) -> u64 {
            let req = self.req();
            assert!(self.handle.send_raw(BrowseRequest::MarkedCount {
                act: Activation(act),
                req,
            }));
            match self.recv() {
                BrowseEvent::MarkedCount {
                    req: got,
                    result: Ok(count),
                    ..
                } => {
                    assert_eq!(got, req);
                    count
                }
                other => panic!("marked_count must answer: {other:?}"),
            }
        }

        fn shutdown(mut self) {
            assert!(self.handle.send_raw(BrowseRequest::Shutdown));
            match self.recv() {
                BrowseEvent::Closed {
                    actor,
                    cause: CloseCause::Requested,
                } => assert_eq!(actor, self.actor),
                other => panic!("shutdown must close: {other:?}"),
            }
            self.join.take().unwrap().join().unwrap();
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    fn keeper_entry(path: &Path) -> FileEntry {
        FileEntry {
            path: path.to_path_buf(),
            is_keeper: true,
            action: None,
            ..FileEntry::default()
        }
    }

    fn delete_entry(path: &Path) -> FileEntry {
        FileEntry {
            path: path.to_path_buf(),
            is_keeper: false,
            action: Some(ActionKind::Delete),
            ..FileEntry::default()
        }
    }

    fn kind(event: &BrowseEvent) -> (&'static str, Option<RequestId>) {
        match event {
            BrowseEvent::OpenFinished { req, .. } => ("OpenFinished", Some(*req)),
            BrowseEvent::PanelData { req, .. } => ("PanelData", Some(*req)),
            BrowseEvent::Group { req, .. } => ("Group", Some(*req)),
            BrowseEvent::GroupCount { req, .. } => ("GroupCount", Some(*req)),
            BrowseEvent::GroupOfPath { req, .. } => ("GroupOfPath", Some(*req)),
            BrowseEvent::FileInfo { req, .. } => ("FileInfo", Some(*req)),
            BrowseEvent::DirGroupAt { req, .. } => ("DirGroupAt", Some(*req)),
            BrowseEvent::DirGroupOpened { req, .. } => ("DirGroupOpened", Some(*req)),
            BrowseEvent::MarkedCount { req, .. } => ("MarkedCount", Some(*req)),
            BrowseEvent::MarkAck { req, .. } => ("MarkAck", Some(*req)),
            BrowseEvent::AutoSelectDone { req, .. } => ("AutoSelectDone", Some(*req)),
            BrowseEvent::PlanReady { req, .. } => ("PlanReady", Some(*req)),
            BrowseEvent::PlanRefused { req, .. } => ("PlanRefused", Some(*req)),
            BrowseEvent::ReconcileAck { req, .. } => ("ReconcileAck", Some(*req)),
            BrowseEvent::LatestScan { req, .. } => ("LatestScan", Some(*req)),
            BrowseEvent::CoveringScan { req, .. } => ("CoveringScan", Some(*req)),
            BrowseEvent::ScanCreatedAt { req, .. } => ("ScanCreatedAt", Some(*req)),
            BrowseEvent::CacheHashAck { req, .. } => ("CacheHashAck", Some(*req)),
            BrowseEvent::Closed { .. } => ("Closed", None),
        }
    }

    // ---- 1. exhaustive routing --------------------------------------------------------------

    /// Every request variant settles with exactly one terminal event of its declared variant,
    /// carrying the same request id, in dispatch order. The list below is built by matching
    /// `BrowseRequest` exhaustively at compile time: a variant added later breaks this test's
    /// builder before any wildcard could swallow it.
    #[test]
    fn every_request_settles_with_exactly_one_event_of_its_variant() {
        let mut rig = Rig::new("routing", BrowseRole::Operator);
        let payload = rig.open(1);
        let ids = Rig::published_ids(&payload);
        assert_eq!(ids.len(), 2, "the fixture publishes two groups");
        let act = Activation(1);
        let [a1, a2, ..] = rig.files.clone();
        let dir = rig.dir.clone();
        let scan_id = rig.scan_id;

        let mut sent: Vec<(&'static str, RequestId)> = Vec::new();
        let mut push =
            |rig: &mut Rig, expected: &'static str, req: RequestId, request: BrowseRequest| {
                assert!(rig.handle.send_raw(request));
                sent.push((expected, req));
            };
        // One of each, in one queue. Each constructor names the event variant it must settle
        // with; `expected_request_inventory` below proves this list covers the whole enum.
        let req = rig.req();
        push(
            &mut rig,
            "PanelData",
            req,
            BrowseRequest::PanelData {
                act,
                req,
                files: vec![a1.clone()],
                dirs: vec![dir.clone()],
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "Group",
            req,
            BrowseRequest::GroupOpen {
                act,
                req,
                id: ids[0],
                offset: 0,
                limit: 10,
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "GroupCount",
            req,
            BrowseRequest::GroupCount {
                act,
                req,
                id: ids[0],
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "GroupOfPath",
            req,
            BrowseRequest::GroupOfPath {
                act,
                req,
                path: a1.clone(),
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "FileInfo",
            req,
            BrowseRequest::FileInfo {
                act,
                req,
                path: a1.clone(),
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "DirGroupAt",
            req,
            BrowseRequest::DirGroupAt {
                act,
                req,
                dir: dir.clone(),
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "DirGroupOpened",
            req,
            BrowseRequest::OpenDirGroup {
                act,
                req,
                signature: "0000".to_string(),
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "MarkedCount",
            req,
            BrowseRequest::MarkedCount { act, req },
        );
        let req = rig.req();
        push(
            &mut rig,
            "MarkAck",
            req,
            BrowseRequest::SetMarks {
                act,
                req,
                entries: vec![keeper_entry(&a1), delete_entry(&a2)],
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "PlanReady",
            req,
            BrowseRequest::BuildPlan {
                act,
                req,
                requested: vec![
                    RequestedMark::keeper(a1.clone()),
                    RequestedMark::acting(a2.clone(), ActionKind::Delete),
                ],
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "AutoSelectDone",
            req,
            BrowseRequest::AutoSelect {
                act,
                req,
                cancel: CancelToken::new(),
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "ReconcileAck",
            req,
            BrowseRequest::ReconcileAfterBatch {
                act,
                req,
                attempted: Vec::new(),
                cancelled: false,
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "LatestScan",
            req,
            BrowseRequest::LatestScan { act, req },
        );
        let req = rig.req();
        push(
            &mut rig,
            "CoveringScan",
            req,
            BrowseRequest::CoveringScan {
                act,
                req,
                cwd: dir.clone(),
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "ScanCreatedAt",
            req,
            BrowseRequest::ScanCreatedAt { act, req, scan_id },
        );
        let req = rig.req();
        push(
            &mut rig,
            "CacheHashAck",
            req,
            BrowseRequest::CacheHash {
                act,
                req,
                device: 1,
                inode: 2,
                size: 3,
                mtime: 4,
                digest: [7u8; 32],
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "OpenFinished",
            req,
            BrowseRequest::Open {
                act: Activation(2),
                req,
                scan_id,
            },
        );

        for (expected, expected_req) in &sent {
            let event = rig.recv();
            let (got, got_req) = kind(&event);
            assert_eq!(&got, expected, "wrong terminal for {expected}: {event:?}");
            assert_eq!(
                got_req,
                Some(*expected_req),
                "wrong request id on {expected}"
            );
        }
        rig.shutdown();
    }

    /// The compile-time half of the routing claim: constructing one of EVERY request variant
    /// through an exhaustive match, so a new variant fails here before it can hide.
    #[test]
    fn expected_request_inventory_is_exhaustive() {
        fn expected(request: &BrowseRequest) -> &'static str {
            match request {
                BrowseRequest::Open { .. } => "OpenFinished",
                BrowseRequest::PanelData { .. } => "PanelData",
                BrowseRequest::GroupOpen { .. } => "Group",
                BrowseRequest::GroupCount { .. } => "GroupCount",
                BrowseRequest::GroupOfPath { .. } => "GroupOfPath",
                BrowseRequest::FileInfo { .. } => "FileInfo",
                BrowseRequest::DirGroupAt { .. } => "DirGroupAt",
                BrowseRequest::OpenDirGroup { .. } => "DirGroupOpened",
                BrowseRequest::MarkedCount { .. } => "MarkedCount",
                BrowseRequest::SetMarks { .. } => "MarkAck",
                BrowseRequest::AutoSelect { .. } => "AutoSelectDone",
                BrowseRequest::BuildPlan { .. } => "PlanReady|PlanRefused",
                BrowseRequest::ReconcileAfterBatch { .. } => "ReconcileAck",
                BrowseRequest::LatestScan { .. } => "LatestScan",
                BrowseRequest::CoveringScan { .. } => "CoveringScan",
                BrowseRequest::ScanCreatedAt { .. } => "ScanCreatedAt",
                BrowseRequest::CacheHash { .. } => "CacheHashAck",
                BrowseRequest::Shutdown => "Closed",
            }
        }
        let probe = BrowseRequest::Shutdown;
        assert_eq!(expected(&probe), "Closed");
    }

    // ---- 2. legal connection/active state ----------------------------------------------------

    #[test]
    fn connection_scoped_requests_bootstrap_before_any_open() {
        let mut rig = Rig::new("bootstrap", BrowseRole::Observer);
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::LatestScan {
            act: Activation(0),
            req,
        }));
        match rig.recv() {
            BrowseEvent::LatestScan {
                result: Ok(Some(found)),
                ..
            } => assert_eq!(found, rig.scan_id),
            other => panic!("the latest scan must be answerable before any Open: {other:?}"),
        }
        let cwd = rig.dir.clone();
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::CoveringScan {
            act: Activation(0),
            req,
            cwd,
        }));
        match rig.recv() {
            BrowseEvent::CoveringScan {
                result: Ok(Some(found)),
                ..
            } => assert_eq!(found, rig.scan_id),
            other => panic!("the covering scan must be answerable before any Open: {other:?}"),
        }
        rig.shutdown();
    }

    #[test]
    fn scan_scoped_requests_refuse_typed_without_an_active_scan() {
        let mut rig = Rig::new("no_active", BrowseRole::Operator);
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::MarkedCount {
            act: Activation(1),
            req,
        }));
        match rig.recv() {
            BrowseEvent::MarkedCount {
                result: Err(StoreMiss::NoActiveScan),
                ..
            } => {}
            other => panic!("a scan-scoped read needs an installed scan: {other:?}"),
        }
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::SetMarks {
            act: Activation(1),
            req,
            entries: Vec::new(),
        }));
        match rig.recv() {
            BrowseEvent::MarkAck {
                outcome:
                    MarkOutcome::Unreadable {
                        error: MarkWriteError::Store { .. },
                    },
                ..
            } => {}
            other => panic!("a scan-scoped mutator needs an installed scan: {other:?}"),
        }
        rig.shutdown();
    }

    #[test]
    fn a_write_is_refused_for_the_observer_role() {
        let mut rig = Rig::new("observer_write", BrowseRole::Observer);
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::CacheHash {
            act: Activation(0),
            req,
            device: 1,
            inode: 2,
            size: 3,
            mtime: 4,
            digest: [1u8; 32],
        }));
        match rig.recv() {
            BrowseEvent::CacheHashAck {
                result: Err(StoreMiss::ReadOnlyRole),
                ..
            } => {}
            other => panic!("an observer must not write the hash cache: {other:?}"),
        }
        rig.shutdown();
    }

    // ---- R4B-2b1 correction A: refusal before any database access ----------------------------

    /// Red on `df0319d`: the lazy bootstrap ran ahead of the scan gate, so an Operator's
    /// refused pre-open request had already established the state directory, created
    /// dedcom.db, enabled WAL and migrated it.
    #[test]
    fn a_refused_scan_request_creates_no_database() {
        let scratch = temp_dir("gate_no_side_effect");
        let parent = scratch.join("state");
        let db = parent.join("dedcom.db");
        let (sink_box, events) = sink();
        let (actor, handle, join) = BrowseActor::spawn_with_hooks(
            db.clone(),
            BrowseRole::Operator,
            sink_box,
            TestHooks::default(),
        );
        assert!(handle.send_raw(BrowseRequest::MarkedCount {
            act: Activation(1),
            req: RequestId(1),
        }));
        match events.recv_timeout(Duration::from_secs(10)).unwrap() {
            BrowseEvent::MarkedCount {
                result: Err(StoreMiss::NoActiveScan),
                ..
            } => {}
            other => panic!("a pre-open read is refused from actor state alone: {other:?}"),
        }
        assert!(handle.send_raw(BrowseRequest::SetMarks {
            act: Activation(1),
            req: RequestId(2),
            entries: Vec::new(),
        }));
        match events.recv_timeout(Duration::from_secs(10)).unwrap() {
            BrowseEvent::MarkAck {
                outcome:
                    MarkOutcome::Unreadable {
                        error: MarkWriteError::Store { .. },
                    },
                ..
            } => {}
            other => panic!("a pre-open mutation is refused from actor state alone: {other:?}"),
        }
        assert!(
            !parent.exists(),
            "a refused request must not establish the state directory"
        );
        assert!(
            !db.exists()
                && !parent.join("dedcom.db-wal").exists()
                && !parent.join("dedcom.db-shm").exists(),
            "a refused request must not create the database or its sidecars"
        );
        assert!(handle.send_raw(BrowseRequest::Shutdown));
        match events.recv_timeout(Duration::from_secs(10)).unwrap() {
            BrowseEvent::Closed {
                actor: got,
                cause: CloseCause::Requested,
            } => assert_eq!(got, actor),
            other => panic!("shutdown must close: {other:?}"),
        }
        join.join().unwrap();
        std::fs::remove_dir_all(&scratch).ok();
    }

    /// Red on `df0319d`: the observer's write refusal came AFTER the lazy open, so over an
    /// unavailable path it surfaced as an open/read error instead of the role refusal.
    #[test]
    fn an_observer_write_refuses_before_opening_anything() {
        let scratch = temp_dir("observer_no_open");
        let parent = scratch.join("state");
        let db = parent.join("dedcom.db");
        let (sink_box, events) = sink();
        let (actor, handle, join) =
            BrowseActor::spawn_with_hooks(db, BrowseRole::Observer, sink_box, TestHooks::default());
        assert!(handle.send_raw(BrowseRequest::CacheHash {
            act: Activation(0),
            req: RequestId(1),
            device: 1,
            inode: 2,
            size: 3,
            mtime: 4,
            digest: [1u8; 32],
        }));
        match events.recv_timeout(Duration::from_secs(10)).unwrap() {
            BrowseEvent::CacheHashAck {
                result: Err(StoreMiss::ReadOnlyRole),
                ..
            } => {}
            other => {
                panic!("the role refusal must not depend on the path being openable: {other:?}")
            }
        }
        assert!(
            !parent.exists(),
            "the refused observer write must not touch the path at all"
        );
        assert!(handle.send_raw(BrowseRequest::Shutdown));
        match events.recv_timeout(Duration::from_secs(10)).unwrap() {
            BrowseEvent::Closed {
                actor: got,
                cause: CloseCause::Requested,
            } => assert_eq!(got, actor),
            other => panic!("shutdown must close: {other:?}"),
        }
        join.join().unwrap();
        std::fs::remove_dir_all(&scratch).ok();
    }

    /// The gate itself, driven directly over an installed pair: a stale or scan-less request
    /// is decided from memory, spending zero identity probes and zero validations. The
    /// actor-level behavioural control stays in `stale_activation_settles_typed_and_touches_
    /// no_row`.
    #[test]
    fn a_gate_refusal_spends_no_probe_and_no_validation() {
        let (dir, db, scan_id, _files) = seeded_db("gate_counters");
        let door = guarded::BrowsingStore::open(&db, BrowseRole::Operator).unwrap();
        let mut state = ActorState {
            actor: ActorId(999_000),
            db: db.clone(),
            role: BrowseRole::Operator,
            closing: Arc::new(AtomicBool::new(false)),
            slot: Slot::Open(Box::new(door)),
            active: Some(ActiveScan {
                scan_id,
                act: Activation(1),
                dir_sig_algo: DirSigAlgo::Old,
            }),
            hooks: TestHooks::default(),
        };
        let counters = |state: &ActorState| match &state.slot {
            Slot::Open(door) => (door.identity_probes(), door.full_validation_count()),
            _ => panic!("the fixture holds an open slot"),
        };
        let before = counters(&state);
        assert!(matches!(
            state.scan_gate(Activation(0), false),
            Err(StoreMiss::StaleActivation {
                expected: 1,
                found: 0
            })
        ));
        assert!(matches!(
            state.scan_gate(Activation(0), true),
            Err(StoreMiss::StaleActivation { .. })
        ));
        state.active = None;
        assert!(matches!(
            state.scan_gate(Activation(1), false),
            Err(StoreMiss::NoActiveScan)
        ));
        assert!(matches!(
            state.scan_gate(Activation(1), true),
            Err(StoreMiss::NoActiveScan)
        ));
        assert_eq!(
            counters(&state),
            before,
            "a gate refusal pays no probe and no validation"
        );
        drop(state);
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- R4B-2b1 correction B: class B survives a failed reopen -------------------------------

    /// Red on `df0319d`: the reuse identity check was reduced to `.is_ok()`, so when the
    /// replacement at the pathname was a regular but invalid SQLite file, the actor dropped
    /// the installed pair and then reported class-A `Open { .. }` — telling the consumer to
    /// keep state the actor no longer has.
    #[test]
    fn a_replacement_by_an_invalid_file_is_still_class_b() {
        let mut rig = Rig::new("class_b_invalid", BrowseRole::Operator);
        rig.open(1);
        let aside = swap_away(&rig.db);
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::Open {
            act: Activation(2),
            req,
            scan_id: rig.scan_id,
        }));
        match rig.recv() {
            BrowseEvent::OpenFinished {
                result: Err(BrowseOpenFailure::PathChanged { .. }),
                ..
            } => {}
            other => panic!(
                "the discarded pair makes this class B even though the reopen failed: {other:?}"
            ),
        }
        // Activation A is dead and the actor is poisoned, not merely empty.
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::MarkedCount {
            act: Activation(1),
            req,
        }));
        match rig.recv() {
            BrowseEvent::MarkedCount {
                result: Err(StoreMiss::PathChanged { .. }),
                ..
            } => {}
            other => panic!("activation A must be unusable after the class-B reply: {other:?}"),
        }
        // A later Open over a restored checkpoint recovers normally.
        swap_back(&rig.db, &aside);
        let payload = rig.open(3);
        assert_eq!(payload.scan_id, rig.scan_id);
        assert_eq!(rig.marked(3), 0);
        rig.shutdown();
    }

    /// Red on `df0319d`: with a VALID second checkpoint at the pathname the fresh open
    /// succeeds, and a typed candidate refusal (`NoSuchScan`) was then emitted as class A —
    /// although the pair this `Open` had discarded was not coming back.
    #[test]
    fn a_candidate_refusal_after_a_replacement_is_still_class_b() {
        let mut rig = Rig::new("class_b_candidate", BrowseRole::Observer);
        rig.open(1);
        let second = rig.dir.join("second.db");
        let c1 = write(&rig.dir, "c1.bin", b"CCCC");
        let c2 = write(&rig.dir, "c2.bin", b"CCCC");
        let mut store = ScanStore::open_writable(&second).unwrap();
        let second_scan = seed_verified(
            &mut store,
            &rig.dir,
            &[(c1, [0xCCu8; 32]), (c2, [0xCCu8; 32])],
        );
        publish_explicit(&mut store, second_scan);
        drop(store);
        let gone = rig.db.with_extension("gone");
        std::fs::rename(&rig.db, &gone).unwrap();
        std::fs::rename(&second, &rig.db).unwrap();
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::Open {
            act: Activation(2),
            req,
            scan_id: 9_999,
        }));
        match rig.recv() {
            BrowseEvent::OpenFinished {
                result: Err(BrowseOpenFailure::PathChanged { .. }),
                ..
            } => {}
            other => panic!(
                "a typed candidate refusal after a discarding mismatch is class B: {other:?}"
            ),
        }
        // Recovery: the checkpoint now at the pathname opens by its own scan id.
        rig.scan_id = second_scan;
        let payload = rig.open(3);
        assert_eq!(payload.scan_id, second_scan);
        rig.shutdown();
    }

    // ---- 3. Open: install, class A, class B, recovery ---------------------------------------

    #[test]
    fn a_successful_open_installs_the_complete_payload() {
        let mut rig = Rig::new("open_ok", BrowseRole::Operator);
        let payload = rig.open(1);
        assert_eq!(payload.scan_id, rig.scan_id);
        assert!(payload.status.is_completed());
        assert!(payload.created_at.is_some());
        assert_eq!(payload.marked_count, 0);
        assert_eq!(Rig::published_ids(&payload).len(), 2);
        assert_eq!(rig.marked(1), 0, "the installed activation answers");
        rig.shutdown();
    }

    #[test]
    fn a_failed_reopen_keeps_the_previous_scan_served() {
        let mut rig = Rig::new("class_a", BrowseRole::Observer);
        rig.open(1);
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::Open {
            act: Activation(2),
            req,
            scan_id: 9_999,
        }));
        match rig.recv() {
            BrowseEvent::OpenFinished {
                result: Err(BrowseOpenFailure::NoSuchScan),
                ..
            } => {}
            other => panic!("a missing scan is a typed class-A failure: {other:?}"),
        }
        // The previously installed activation is untouched and still served: both sides
        // still describe the same scan.
        assert_eq!(rig.marked(1), 0);
        rig.shutdown();
    }

    #[test]
    fn a_swap_before_the_first_candidate_read_uninstalls_both_and_only_open_recovers() {
        let mut rig = Rig::new("class_b_first", BrowseRole::Observer);
        rig.open(1);
        // A second real checkpoint that will take over the pathname mid-Open.
        let second = rig.dir.join("second.db");
        let c1 = write(&rig.dir, "c1.bin", b"CCCC");
        let c2 = write(&rig.dir, "c2.bin", b"CCCC");
        let mut store = ScanStore::open_writable(&second).unwrap();
        let second_scan = seed_verified(
            &mut store,
            &rig.dir,
            &[(c1, [0xCCu8; 32]), (c2, [0xCCu8; 32])],
        );
        publish_explicit(&mut store, second_scan);
        drop(store);
        let db = rig.db.clone();
        let mut fired = false;
        rig.hooks.on_open_step(move |step| {
            // The first candidate read for an observer is the snapshot; the swap lands
            // exactly between the reuse check and that read.
            if step == "snapshot" && !fired {
                fired = true;
                let aside = db.with_extension("gone");
                std::fs::rename(&db, &aside).unwrap();
                std::fs::rename(db.with_file_name("second.db"), &db).unwrap();
            }
        });
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::Open {
            act: Activation(2),
            req,
            scan_id: rig.scan_id,
        }));
        match rig.recv() {
            BrowseEvent::OpenFinished {
                result: Err(BrowseOpenFailure::PathChanged { .. }),
                ..
            } => {}
            other => panic!("a swap during Open is class B: {other:?}"),
        }
        // Both store and active are gone: even the old activation refuses, and so does a
        // connection-scoped read — nothing is served from a database nobody is looking at.
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::MarkedCount {
            act: Activation(1),
            req,
        }));
        match rig.recv() {
            BrowseEvent::MarkedCount {
                result: Err(StoreMiss::PathChanged { .. }),
                ..
            } => {}
            other => panic!("a poisoned actor must refuse: {other:?}"),
        }
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::LatestScan {
            act: Activation(0),
            req,
        }));
        match rig.recv() {
            BrowseEvent::LatestScan {
                result: Err(StoreMiss::PathChanged { .. }),
                ..
            } => {}
            other => panic!("poisoning covers connection-scoped requests too: {other:?}"),
        }
        // Recovery is Open and only Open — on the checkpoint now at the pathname.
        rig.scan_id = second_scan;
        let payload = rig.open(3);
        assert_eq!(payload.scan_id, second_scan);
        rig.shutdown();
    }

    #[test]
    fn a_swap_during_candidate_construction_uninstalls_both() {
        let mut rig = Rig::new("class_b_late", BrowseRole::Operator);
        rig.open(1);
        let db = rig.db.clone();
        let mut fired = false;
        rig.hooks.on_open_step(move |step| {
            // After the snapshot was taken and dropped, before the dir-group summaries read.
            if step == "dir_groups" && !fired {
                fired = true;
                let aside = db.with_extension("gone");
                std::fs::rename(&db, &aside).unwrap();
                std::fs::write(&db, b"not the checkpoint").unwrap();
            }
        });
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::Open {
            act: Activation(2),
            req,
            scan_id: rig.scan_id,
        }));
        match rig.recv() {
            BrowseEvent::OpenFinished {
                result: Err(BrowseOpenFailure::PathChanged { .. }),
                ..
            } => {}
            other => panic!("a swap during candidate construction is class B: {other:?}"),
        }
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::MarkedCount {
            act: Activation(1),
            req,
        }));
        match rig.recv() {
            BrowseEvent::MarkedCount {
                result: Err(StoreMiss::PathChanged { .. }),
                ..
            } => {}
            other => panic!("class B must uninstall the old activation: {other:?}"),
        }
        rig.shutdown();
    }

    /// The one typed-blind window, pinned rather than papered over: `prepare_legacy_for_viewing`
    /// wraps its inner refusals in plain text, so a swap landing exactly before it classifies
    /// as class A — and the very next request's own probe poisons the actor anyway. No stale
    /// answer escapes the window; only the FIRST classification is softer than ideal.
    #[test]
    fn the_operator_prepare_window_is_class_a_and_poisons_on_the_next_touch() {
        let mut rig = Rig::new("prepare_window", BrowseRole::Operator);
        rig.open(1);
        let db = rig.db.clone();
        let mut fired = false;
        rig.hooks.on_open_step(move |step| {
            if step == "prepare" && !fired {
                fired = true;
                let aside = db.with_extension("gone");
                std::fs::rename(&db, &aside).unwrap();
                std::fs::write(&db, b"not the checkpoint").unwrap();
            }
        });
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::Open {
            act: Activation(2),
            req,
            scan_id: rig.scan_id,
        }));
        match rig.recv() {
            BrowseEvent::OpenFinished {
                result: Err(BrowseOpenFailure::Prepare { .. }),
                ..
            } => {}
            other => panic!("the prepare window classifies as class A today: {other:?}"),
        }
        // The stale pair survived the class-A refusal — and the next touch refuses typed and
        // poisons, so the window closes one request later.
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::MarkedCount {
            act: Activation(1),
            req,
        }));
        match rig.recv() {
            BrowseEvent::MarkedCount {
                result: Err(StoreMiss::PathChanged { .. }),
                ..
            } => {}
            other => panic!("the next request must refuse typed: {other:?}"),
        }
        rig.shutdown();
    }

    // ---- 4. the three poisoning surfaces ------------------------------------------------------

    #[test]
    fn a_reader_probe_path_change_poisons_until_open() {
        let mut rig = Rig::new("poison_reader", BrowseRole::Operator);
        rig.open(1);
        let aside = swap_away(&rig.db);
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::MarkedCount {
            act: Activation(1),
            req,
        }));
        match rig.recv() {
            BrowseEvent::MarkedCount {
                result: Err(StoreMiss::PathChanged { .. }),
                ..
            } => {}
            other => panic!("the door probe must refuse a replaced path: {other:?}"),
        }
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::LatestScan {
            act: Activation(0),
            req,
        }));
        match rig.recv() {
            BrowseEvent::LatestScan {
                result: Err(StoreMiss::PathChanged { .. }),
                ..
            } => {}
            other => panic!("every later non-Open request refuses: {other:?}"),
        }
        // Only Open recovers — the original checkpoint returns to its pathname.
        swap_back(&rig.db, &aside);
        let payload = rig.open(2);
        assert_eq!(payload.scan_id, rig.scan_id);
        assert_eq!(rig.marked(2), 0);
        rig.shutdown();
    }

    #[test]
    fn a_snapshot_reopen_required_poisons() {
        let mut rig = Rig::new("poison_snapshot", BrowseRole::Operator);
        let payload = rig.open(1);
        let ids = Rig::published_ids(&payload);
        let _aside = swap_away(&rig.db);
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::GroupCount {
            act: Activation(1),
            req,
            id: ids[0],
        }));
        match rig.recv() {
            BrowseEvent::GroupCount {
                result: Err(MembershipMiss::ReopenRequired { .. }),
                ..
            } => {}
            other => panic!("the snapshot surface must refuse typed: {other:?}"),
        }
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::LatestScan {
            act: Activation(0),
            req,
        }));
        match rig.recv() {
            BrowseEvent::LatestScan {
                result: Err(StoreMiss::PathChanged { .. }),
                ..
            } => {}
            other => panic!("the reopen-required surface must poison: {other:?}"),
        }
        rig.shutdown();
    }

    #[test]
    fn a_mark_write_path_change_poisons_and_the_original_rows_survive() {
        let mut rig = Rig::new("poison_write", BrowseRole::Operator);
        rig.open(1);
        let [a1, a2, ..] = rig.files.clone();
        let aside = swap_away(&rig.db);
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::SetMarks {
            act: Activation(1),
            req,
            entries: vec![keeper_entry(&a1), delete_entry(&a2)],
        }));
        match rig.recv() {
            BrowseEvent::MarkAck {
                outcome:
                    MarkOutcome::Unreadable {
                        error: MarkWriteError::PathChanged { .. },
                    },
                ..
            } => {}
            other => panic!("the write surface must refuse typed: {other:?}"),
        }
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::MarkedCount {
            act: Activation(1),
            req,
        }));
        match rig.recv() {
            BrowseEvent::MarkedCount {
                result: Err(StoreMiss::PathChanged { .. }),
                ..
            } => {}
            other => panic!("the write surface must poison: {other:?}"),
        }
        // The original checkpoint was byte-untouched by the refused write.
        swap_back(&rig.db, &aside);
        {
            let store = ScanStore::open_writable(&rig.db).unwrap();
            assert_eq!(store.marked_count(rig.scan_id).unwrap(), 0);
        }
        rig.shutdown();
    }

    // ---- 5. stale activation -----------------------------------------------------------------

    #[test]
    fn stale_activation_settles_typed_and_touches_no_row() {
        let mut rig = Rig::new("stale", BrowseRole::Operator);
        rig.open(1);
        let [a1, a2, b1, b2] = rig.files.clone();
        // A durable baseline so the "no row changed" half is observable.
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::SetMarks {
            act: Activation(1),
            req,
            entries: vec![keeper_entry(&a1), delete_entry(&a2)],
        }));
        match rig.recv() {
            BrowseEvent::MarkAck {
                outcome: MarkOutcome::Settled { .. },
                ..
            } => {}
            other => panic!("the baseline write must settle: {other:?}"),
        }
        assert_eq!(rig.marked(1), 1);
        // A stale read settles typed.
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::MarkedCount {
            act: Activation(0),
            req,
        }));
        match rig.recv() {
            BrowseEvent::MarkedCount {
                result:
                    Err(StoreMiss::StaleActivation {
                        expected: 1,
                        found: 0,
                    }),
                ..
            } => {}
            other => panic!("a stale read must refuse typed: {other:?}"),
        }
        // A stale mutator settles typed and reaches no row.
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::SetMarks {
            act: Activation(0),
            req,
            entries: vec![keeper_entry(&b1), delete_entry(&b2)],
        }));
        match rig.recv() {
            BrowseEvent::MarkAck {
                outcome:
                    MarkOutcome::Unreadable {
                        error: MarkWriteError::Store { .. },
                    },
                ..
            } => {}
            other => panic!("a stale mutator must refuse before the database: {other:?}"),
        }
        assert_eq!(rig.marked(1), 1, "the stale mutator changed nothing");
        rig.shutdown();
    }

    // ---- 6. role immutability ------------------------------------------------------------------

    #[test]
    fn the_actor_keeps_its_open_role_when_the_global_flips() {
        let _role = crate::state::store::role_guard();
        let mut rig = Rig::new("role_pin", BrowseRole::Operator);
        rig.open(1);
        let [a1, a2, ..] = rig.files.clone();
        // The process-global observer flag flips AFTER the spawn; the actor's capability must
        // not move, because it opened by its own immutable role.
        crate::state::set_observer_role(true);
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::SetMarks {
            act: Activation(1),
            req,
            entries: vec![keeper_entry(&a1), delete_entry(&a2)],
        }));
        let outcome = match rig.recv() {
            BrowseEvent::MarkAck { outcome, .. } => outcome,
            other => panic!("the write must settle: {other:?}"),
        };
        crate::state::set_observer_role(false);
        match outcome {
            MarkOutcome::Settled { .. } => {}
            other => panic!("an operator actor stays writable after a global flip: {other:?}"),
        }
        rig.shutdown();

        // And the mirror: an observer actor stays read-only even as an operator globally.
        let mut rig = Rig::new("role_pin_observer", BrowseRole::Observer);
        rig.open(1);
        let [a1, a2, ..] = rig.files.clone();
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::SetMarks {
            act: Activation(1),
            req,
            entries: vec![keeper_entry(&a1), delete_entry(&a2)],
        }));
        match rig.recv() {
            BrowseEvent::MarkAck {
                outcome:
                    MarkOutcome::Unreadable {
                        error: MarkWriteError::Store { .. },
                    },
                ..
            } => {}
            other => panic!("an observer actor must refuse writes: {other:?}"),
        }
        assert_eq!(rig.marked(1), 0);
        rig.shutdown();
    }

    // ---- 7. cancellation before handler entry; checked request ids -----------------------------

    #[test]
    fn an_escape_between_enqueue_and_handler_entry_cancels() {
        let mut rig = Rig::new("esc_window", BrowseRole::Operator);
        rig.open(1);
        // Park the actor immediately before handler entry, deterministically. One-shot: the
        // later `marked` probe must dispatch without a rendezvous partner.
        let (at_gate_tx, at_gate) = crossbeam_channel::bounded::<()>(1);
        let (go_tx, go) = crossbeam_channel::bounded::<()>(1);
        let mut fired = false;
        rig.hooks.on_dispatch(move || {
            if fired {
                return;
            }
            fired = true;
            let _ = at_gate_tx.send(());
            let _ = go.recv();
        });
        let cancel = CancelToken::new();
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::AutoSelect {
            act: Activation(1),
            req,
            cancel: cancel.clone(),
        }));
        at_gate
            .recv_timeout(Duration::from_secs(10))
            .expect("the actor must reach the dispatch gate");
        // The Esc lands while the request is enqueued but before its handler runs — the
        // window a consumer-side reset used to erase.
        cancel.cancel();
        go_tx.send(()).unwrap();
        match rig.recv() {
            BrowseEvent::AutoSelectDone {
                outcome: AutoSelectOutcome::Refused(AutoSelectRefusal::CancelledBeforeFirstCommit),
                ..
            } => {}
            other => panic!("the pre-handler Esc must cancel: {other:?}"),
        }
        assert_eq!(rig.marked(1), 0, "nothing was written");
        rig.shutdown();
    }

    #[test]
    fn request_ids_are_checked_and_never_wrap() {
        let mut ids = RequestIds::starting_at(u64::MAX - 1);
        assert_eq!(ids.allocate(), RequestId(u64::MAX));
        let _lock = crate::panics::test_lock();
        let exhausted =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || ids.allocate()));
        assert!(exhausted.is_err(), "exhaustion must be loud, never a wrap");
    }

    // ---- 8. marks: after-image, auto-select, reconcile, cache --------------------------------

    #[test]
    fn set_marks_returns_the_authoritative_after_image() {
        let mut rig = Rig::new("after_image", BrowseRole::Operator);
        rig.open(1);
        let [a1, a2, ..] = rig.files.clone();
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::SetMarks {
            act: Activation(1),
            req,
            entries: vec![keeper_entry(&a1), delete_entry(&a2)],
        }));
        match rig.recv() {
            BrowseEvent::MarkAck {
                outcome: MarkOutcome::Settled { after },
                ..
            } => {
                assert_eq!(
                    after,
                    vec![
                        (a1.clone(), Some(MarkIntent::Keeper)),
                        (a2.clone(), Some(MarkIntent::Act(ActionKind::Delete))),
                    ],
                    "the after-image is the durable truth, in request order"
                );
            }
            other => panic!("the write must settle with its after-image: {other:?}"),
        }
        // A request that contradicts itself is refused whole, and the durable rows survive.
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::SetMarks {
            act: Activation(1),
            req,
            entries: vec![keeper_entry(&a1), delete_entry(&a1)],
        }));
        match rig.recv() {
            BrowseEvent::MarkAck {
                outcome:
                    MarkOutcome::Unreadable {
                        error: MarkWriteError::RequestContradictsItself { .. },
                    },
                ..
            } => {}
            other => panic!("a self-contradicting request is refused whole: {other:?}"),
        }
        assert_eq!(rig.marked(1), 1);
        rig.shutdown();
    }

    #[test]
    fn auto_select_completes_and_the_count_is_durable() {
        let mut rig = Rig::new("auto_ok", BrowseRole::Operator);
        rig.open(1);
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::AutoSelect {
            act: Activation(1),
            req,
            cancel: CancelToken::new(),
        }));
        match rig.recv() {
            BrowseEvent::AutoSelectDone {
                outcome: AutoSelectOutcome::Completed { groups, marks },
                ..
            } => {
                assert_eq!(groups, 2);
                assert_eq!(marks, 2, "one non-keeper per pair");
            }
            other => panic!("the sweep must complete: {other:?}"),
        }
        assert_eq!(rig.marked(1), 2, "the durable count agrees with the report");
        rig.shutdown();
    }

    #[test]
    fn auto_select_cancelled_after_a_chunk_reports_partial() {
        let (dir, db, scan_id) = many_groups_db("auto_partial", 501);
        let files = [
            dir.join("g00000_a.bin"),
            dir.join("g00000_b.bin"),
            dir.join("g00001_a.bin"),
            dir.join("g00001_b.bin"),
        ];
        let mut rig = Rig::over(dir, db, scan_id, files, BrowseRole::Operator);
        rig.open(1);
        let cancel = CancelToken::new();
        let observed = cancel.clone();
        rig.hooks.on_chunk(move |phase| {
            // The cancel lands exactly at the first durable boundary — no sleeps, no races.
            if phase == ChunkPhase::AfterCommit(1) {
                observed.cancel();
            }
        });
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::AutoSelect {
            act: Activation(1),
            req,
            cancel,
        }));
        match rig.recv() {
            BrowseEvent::AutoSelectDone {
                outcome:
                    AutoSelectOutcome::Partial {
                        committed_groups,
                        last_committed_rank,
                        cancelled: true,
                        ..
                    },
                ..
            } => {
                assert_eq!(committed_groups.get(), 500, "exactly the committed chunk");
                assert!(last_committed_rank > 0);
            }
            other => panic!("a cancel after a commit is Partial, never silence: {other:?}"),
        }
        assert_eq!(rig.marked(1), 500, "one delete mark per committed pair");
        rig.shutdown();
    }

    #[test]
    fn auto_select_first_chunk_path_change_refuses_typed_and_poisons() {
        let mut rig = Rig::new("auto_first_chunk", BrowseRole::Operator);
        rig.open(1);
        let db = rig.db.clone();
        rig.hooks.on_chunk(move |phase| {
            if phase == ChunkPhase::BeforeWrite(1) {
                let aside = db.with_extension("gone");
                std::fs::rename(&db, &aside).unwrap();
                std::fs::write(&db, b"not the checkpoint").unwrap();
            }
        });
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::AutoSelect {
            act: Activation(1),
            req,
            cancel: CancelToken::new(),
        }));
        match rig.recv() {
            BrowseEvent::AutoSelectDone {
                outcome: AutoSelectOutcome::Refused(AutoSelectRefusal::PathChanged { .. }),
                ..
            } => {}
            other => panic!("a zero-commit path change is a typed refusal: {other:?}"),
        }
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::LatestScan {
            act: Activation(0),
            req,
        }));
        match rig.recv() {
            BrowseEvent::LatestScan {
                result: Err(StoreMiss::PathChanged { .. }),
                ..
            } => {}
            other => panic!("the failed sweep must poison: {other:?}"),
        }
        rig.shutdown();
    }

    #[test]
    fn reconcile_and_cache_hash_settle_typed() {
        let mut rig = Rig::new("reconcile", BrowseRole::Operator);
        rig.open(1);
        let [a1, a2, ..] = rig.files.clone();
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::SetMarks {
            act: Activation(1),
            req,
            entries: vec![keeper_entry(&a1), delete_entry(&a2)],
        }));
        let _ = rig.recv();
        assert_eq!(rig.marked(1), 1);
        // A finished batch spends the whole plan.
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::ReconcileAfterBatch {
            act: Activation(1),
            req,
            attempted: vec![a2.clone()],
            cancelled: false,
        }));
        match rig.recv() {
            BrowseEvent::ReconcileAck { result: Ok(()), .. } => {}
            other => panic!("the settlement must acknowledge: {other:?}"),
        }
        assert_eq!(rig.marked(1), 0, "the batch spent the marks");
        let req = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::CacheHash {
            act: Activation(1),
            req,
            device: 11,
            inode: 22,
            size: 33,
            mtime: 44,
            digest: [5u8; 32],
        }));
        match rig.recv() {
            BrowseEvent::CacheHashAck { result: Ok(()), .. } => {}
            other => panic!("the cache write must acknowledge: {other:?}"),
        }
        rig.shutdown();
    }

    // ---- 9. closing refuses the queue, then exactly one Closed --------------------------------

    #[test]
    fn closing_refuses_every_queued_request_with_one_settlement_each() {
        let mut rig = Rig::new("closing_queue", BrowseRole::Operator);
        let payload = rig.open(1);
        let ids = Rig::published_ids(&payload);
        let act = Activation(1);
        let [a1, a2, ..] = rig.files.clone();
        let dir = rig.dir.clone();
        let scan_id = rig.scan_id;
        // Park the actor before it can dispatch the probe, then pile the whole battery of
        // requests behind it and set the closing flag — exactly what `begin_close` does.
        let (at_gate_tx, at_gate) = crossbeam_channel::bounded::<()>(1);
        let (go_tx, go) = crossbeam_channel::bounded::<()>(1);
        rig.hooks.on_dispatch(move || {
            let _ = at_gate_tx.send(());
            let _ = go.recv();
        });
        let probe = rig.req();
        assert!(rig
            .handle
            .send_raw(BrowseRequest::MarkedCount { act, req: probe }));
        at_gate
            .recv_timeout(Duration::from_secs(10))
            .expect("the actor must reach the dispatch gate");
        let mut queued: Vec<(&'static str, RequestId)> = Vec::new();
        let mut push =
            |rig: &mut Rig, name: &'static str, req: RequestId, request: BrowseRequest| {
                assert!(rig.handle.send_raw(request));
                queued.push((name, req));
            };
        let req = rig.req();
        push(
            &mut rig,
            "OpenFinished",
            req,
            BrowseRequest::Open {
                act: Activation(2),
                req,
                scan_id,
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "PanelData",
            req,
            BrowseRequest::PanelData {
                act,
                req,
                files: vec![a1.clone()],
                dirs: vec![dir.clone()],
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "Group",
            req,
            BrowseRequest::GroupOpen {
                act,
                req,
                id: ids[0],
                offset: 0,
                limit: 10,
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "GroupCount",
            req,
            BrowseRequest::GroupCount {
                act,
                req,
                id: ids[0],
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "GroupOfPath",
            req,
            BrowseRequest::GroupOfPath {
                act,
                req,
                path: a1.clone(),
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "FileInfo",
            req,
            BrowseRequest::FileInfo {
                act,
                req,
                path: a1.clone(),
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "DirGroupAt",
            req,
            BrowseRequest::DirGroupAt {
                act,
                req,
                dir: dir.clone(),
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "DirGroupOpened",
            req,
            BrowseRequest::OpenDirGroup {
                act,
                req,
                signature: "0000".to_string(),
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "MarkedCount",
            req,
            BrowseRequest::MarkedCount { act, req },
        );
        let req = rig.req();
        push(
            &mut rig,
            "MarkAck",
            req,
            BrowseRequest::SetMarks {
                act,
                req,
                entries: vec![keeper_entry(&a1), delete_entry(&a2)],
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "AutoSelectDone",
            req,
            BrowseRequest::AutoSelect {
                act,
                req,
                cancel: CancelToken::new(),
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "PlanRefused",
            req,
            BrowseRequest::BuildPlan {
                act,
                req,
                requested: vec![RequestedMark::keeper(a1.clone())],
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "ReconcileAck",
            req,
            BrowseRequest::ReconcileAfterBatch {
                act,
                req,
                attempted: Vec::new(),
                cancelled: false,
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "CacheHashAck",
            req,
            BrowseRequest::CacheHash {
                act,
                req,
                device: 1,
                inode: 2,
                size: 3,
                mtime: 4,
                digest: [9u8; 32],
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "LatestScan",
            req,
            BrowseRequest::LatestScan { act, req },
        );
        let req = rig.req();
        push(
            &mut rig,
            "CoveringScan",
            req,
            BrowseRequest::CoveringScan {
                act,
                req,
                cwd: dir.clone(),
            },
        );
        let req = rig.req();
        push(
            &mut rig,
            "ScanCreatedAt",
            req,
            BrowseRequest::ScanCreatedAt { act, req, scan_id },
        );
        // The closing flag and the one Shutdown, in the gate's single critical section —
        // exactly what the fleet's `begin_close` performs.
        assert!(rig.handle.begin_close_send());
        go_tx.send(()).unwrap();
        // The in-flight probe was already past the closing check and completes normally.
        match rig.recv() {
            BrowseEvent::MarkedCount {
                req, result: Ok(0), ..
            } => assert_eq!(req, probe),
            other => panic!("the in-flight request completes: {other:?}"),
        }
        for (name, expected_req) in &queued {
            let event = rig.recv();
            let (got, got_req) = kind(&event);
            assert_eq!(&got, name, "closing refusal variant for {name}: {event:?}");
            assert_eq!(got_req, Some(*expected_req));
        }
        match rig.recv() {
            BrowseEvent::Closed {
                actor,
                cause: CloseCause::Requested,
            } => assert_eq!(actor, rig.actor),
            other => panic!("exactly one Closed after the refusals: {other:?}"),
        }
        rig.join.take().unwrap().join().unwrap();
        // Nothing behind the closing flag reached the database.
        let store = ScanStore::open_writable(&rig.db).unwrap();
        assert_eq!(store.marked_count(rig.scan_id).unwrap(), 0);
        drop(store);
        std::fs::remove_dir_all(&rig.dir).ok();
    }

    // ---- 10. one terminal per actor: close, panic, send failure, duplicate ---------------------

    #[test]
    fn a_normal_close_joins_exactly_once() {
        let (dir, db, _scan_id, _files) = seeded_db("fleet_close");
        let mut fleet = BrowseFleet::new();
        let (sink_box, events) = sink();
        let actor = fleet
            .spawn(db, BrowseRole::Observer, sink_box)
            .expect("an idle fleet spawns");
        assert_eq!(fleet.phase(), FleetPhase::Live);
        assert!(fleet.terminal_owed());
        assert!(!fleet.busy(), "a live actor is not draining yet");
        assert!(
            fleet.begin_close().is_none(),
            "the terminal arrives as an event"
        );
        assert_eq!(fleet.phase(), FleetPhase::Draining);
        assert!(fleet.busy());
        let cause = match events.recv_timeout(Duration::from_secs(10)).unwrap() {
            BrowseEvent::Closed { actor: got, cause } => {
                assert_eq!(got, actor);
                cause
            }
            other => panic!("the close must emit its terminal: {other:?}"),
        };
        assert_eq!(cause, CloseCause::Requested);
        let retired = fleet
            .take_terminal(actor, &cause)
            .expect("the first terminal returns the retirement");
        let drained = retired.handle.drain_tickets();
        assert!(drained.tickets.is_empty() && drained.long_op.is_none());
        retired.join.join().unwrap();
        assert_eq!(fleet.phase(), FleetPhase::Idle);
        assert!(!fleet.terminal_owed());
        assert!(
            fleet.take_terminal(actor, &cause).is_none(),
            "a duplicate terminal is a no-op"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_panicking_dispatch_reports_closed_panicked_and_spawns_no_successor() {
        let _lock = crate::panics::test_lock();
        let (dir, db, scan_id, _files) = seeded_db("fleet_panic");
        let mut fleet = BrowseFleet::new();
        let (sink_box, events) = sink();
        let hooks = TestHooks::default();
        // The panic fires inside the dispatch of an in-flight request while the fleet is
        // draining a replacement — the one moment a pending successor exists to be cleared.
        let (at_gate_tx, at_gate) = crossbeam_channel::bounded::<()>(1);
        let (go_tx, go) = crossbeam_channel::bounded::<()>(1);
        hooks.on_dispatch(move || {
            let _ = at_gate_tx.send(());
            let _ = go.recv();
            panic!("boom in the browsing actor");
        });
        let actor = fleet
            .spawn_hooked(db, BrowseRole::Observer, sink_box, hooks)
            .expect("an idle fleet spawns");
        let handle = fleet.live().expect("live").clone();
        let req = RequestId(1);
        handle
            .register_ticket(mark_ticket(1, 1, Path::new("/x/panic-ticket.bin")))
            .expect("the ticket registers");
        assert!(handle.send_raw(BrowseRequest::LatestScan {
            act: Activation(0),
            req,
        }));
        at_gate
            .recv_timeout(Duration::from_secs(10))
            .expect("the actor must reach the dispatch gate");
        assert!(
            fleet.replace(BrowseRole::Operator, Some(scan_id)).is_none(),
            "the parked actor is alive, so the terminal arrives as an event"
        );
        assert!(fleet.pending_spawn().is_some(), "the successor is pending");
        assert_eq!(fleet.phase(), FleetPhase::Draining);
        go_tx.send(()).unwrap();
        let cause = match events.recv_timeout(Duration::from_secs(10)).unwrap() {
            BrowseEvent::Closed { actor: got, cause } => {
                assert_eq!(got, actor);
                cause
            }
            other => panic!("a panic must still yield the one terminal: {other:?}"),
        };
        match &cause {
            CloseCause::Panicked(text) => assert!(
                text.contains("boom in the browsing actor"),
                "the terminal names the panic: {text}"
            ),
            other => panic!("the cause must be the panic: {other:?}"),
        }
        let retired = fleet.take_terminal(actor, &cause).expect("first terminal");
        let drained = retired.handle.drain_tickets();
        assert_eq!(
            drained.tickets.len(),
            1,
            "the retired ticket is still there to settle"
        );
        assert_eq!(drained.tickets[0].req, req);
        retired.join.join().unwrap();
        assert_eq!(fleet.phase(), FleetPhase::Idle);
        assert!(
            fleet.pending_spawn().is_none(),
            "an actor that died of a panic never gets a successor"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The actor already panicked with its `Closed` queued but unconsumed, one mark ticket
    /// and one long-operation record live. `replace()` hits the send failure — and the
    /// synthesised retirement preserves BOTH records whole, joins exactly once, clears the
    /// pending successor, and the late real `Closed` is a no-op.
    #[test]
    fn a_send_failure_returns_the_retirement_with_all_evidence() {
        let _lock = crate::panics::test_lock();
        let (dir, db, _scan_id, files) = seeded_db("fleet_send_fail");
        let mut fleet = BrowseFleet::new();
        let (sink_box, events) = sink();
        let hooks = TestHooks::default();
        hooks.on_dispatch(|| panic!("boom before the queue drains"));
        let actor = fleet
            .spawn_hooked(db, BrowseRole::Operator, sink_box, hooks)
            .expect("an idle fleet spawns");
        let handle = fleet.live().expect("live").clone();
        handle
            .register_ticket(mark_ticket(1, 7, &files[0]))
            .expect("the ticket registers");
        let token = CancelToken::new();
        handle
            .send_auto_select(Activation(1), RequestId(8), token)
            .expect("the long operation registers and enqueues");
        // Dispatching that sweep panics the actor: its Closed(Panicked) is in the sink, the
        // receiver is gone, and both records are still unsettled. The fleet knows nothing.
        let late = events.recv_timeout(Duration::from_secs(10)).unwrap();
        let retired = fleet
            .replace(BrowseRole::Observer, None)
            .expect("the send failure surfaces the synthesised retirement");
        assert!(
            fleet.pending_spawn().is_none(),
            "a synthesised terminal never spawns blind"
        );
        assert_eq!(
            fleet.phase(),
            FleetPhase::Idle,
            "the ownership transition happened inline"
        );
        let drained = retired.handle.drain_tickets();
        assert_eq!(
            drained.tickets.len(),
            1,
            "the mark ticket survives retirement"
        );
        assert_eq!(drained.tickets[0].req, RequestId(7));
        assert_eq!(
            drained.tickets[0].before,
            vec![(files[0].clone(), None)],
            "the before-image survives whole"
        );
        let long = drained
            .long_op
            .expect("the in-flight sweep is discoverable at retirement");
        assert_eq!(long.req, RequestId(8));
        retired.join.join().unwrap();
        // The real terminal arrives late and finds the state already moved on.
        match late {
            BrowseEvent::Closed { actor: got, cause } => {
                assert_eq!(got, actor);
                assert!(
                    fleet.take_terminal(got, &cause).is_none(),
                    "the late real Closed finds the ownership already transferred"
                );
            }
            other => panic!("the sink holds the one Closed: {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- 11. serialized replacement -----------------------------------------------------------

    /// Normal replacement retains every ticket, before-image and long-operation record until
    /// the first `Closed`, then releases the whole retirement exactly once — before any
    /// successor can exist.
    #[test]
    fn replacement_is_serialized_and_settles_old_tickets_first() {
        let (dir, db, scan_id, files) = seeded_db("fleet_replace");
        let mut fleet = BrowseFleet::new();
        let (sink_box, events) = sink();
        let hooks = TestHooks::default();
        // Park the sweep before its handler so a live long operation spans the replacement.
        let (at_gate_tx, at_gate) = crossbeam_channel::bounded::<()>(1);
        let (go_tx, go) = crossbeam_channel::bounded::<()>(1);
        let mut fired = false;
        hooks.on_dispatch(move || {
            if fired {
                return;
            }
            fired = true;
            let _ = at_gate_tx.send(());
            let _ = go.recv();
        });
        let first = fleet
            .spawn_hooked(db.clone(), BrowseRole::Operator, sink_box, hooks)
            .expect("an idle fleet spawns");
        let handle = fleet.live().expect("live").clone();
        handle
            .register_ticket(mark_ticket(1, 41, &files[0]))
            .expect("the ticket registers");
        handle
            .send_auto_select(Activation(1), RequestId(42), CancelToken::new())
            .expect("the sweep registers and enqueues");
        at_gate
            .recv_timeout(Duration::from_secs(10))
            .expect("the actor must reach the dispatch gate");
        assert!(
            fleet.replace(BrowseRole::Observer, Some(scan_id)).is_none(),
            "the actor is alive, so the terminal arrives as an event"
        );
        assert_eq!(fleet.phase(), FleetPhase::Draining);
        // No second actor can exist while the first drains.
        let (denied_sink, _denied_events) = sink();
        assert!(
            fleet
                .spawn(db.clone(), BrowseRole::Observer, denied_sink)
                .is_none(),
            "spawning over a draining fleet is refused"
        );
        go_tx.send(()).unwrap();
        // The parked sweep observes closing and settles typed; the ledger is deliberately
        // NOT settled here — retention until the terminal is the claim under test.
        match events.recv_timeout(Duration::from_secs(10)).unwrap() {
            BrowseEvent::AutoSelectDone { req, .. } => assert_eq!(req, RequestId(42)),
            other => panic!("the sweep settles typed: {other:?}"),
        }
        let cause = match events.recv_timeout(Duration::from_secs(10)).unwrap() {
            BrowseEvent::Closed { actor, cause } => {
                assert_eq!(actor, first);
                cause
            }
            other => panic!("the retiring actor owes its terminal: {other:?}"),
        };
        let retired = fleet.take_terminal(first, &cause).expect("first terminal");
        let drained = retired.handle.drain_tickets();
        assert_eq!(
            drained.tickets.len(),
            1,
            "the ticket is retained until the terminal"
        );
        assert_eq!(drained.tickets[0].req, RequestId(41));
        assert_eq!(drained.tickets[0].before, vec![(files[0].clone(), None)]);
        assert_eq!(
            drained.long_op.expect("the long-op record is retained").req,
            RequestId(42)
        );
        retired.join.join().unwrap();
        assert_eq!(fleet.phase(), FleetPhase::Idle);
        let plan = fleet.pending_spawn().cloned().expect("the wish survived");
        assert_eq!(plan.role, BrowseRole::Observer);
        assert_eq!(plan.reopen, Some(scan_id));
        let (second_sink, second_events) = sink();
        let second = fleet
            .spawn(db, plan.role, second_sink)
            .expect("the successor spawns only now");
        fleet.cancel_pending_spawn();
        assert!(second > first, "actor ids are never reused");
        assert!(fleet.begin_close().is_none());
        match second_events.recv_timeout(Duration::from_secs(10)).unwrap() {
            BrowseEvent::Closed { actor, cause } => {
                assert_eq!(actor, second);
                let retired = fleet.take_terminal(actor, &cause).expect("terminal");
                retired.join.join().unwrap();
            }
            other => panic!("the successor closes cleanly: {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- R4B-2b2: lossless inflight, one send gate, evidence-preserving retirement -----------

    /// A one-path ticket with a `None` before-image — the smallest valid settlement record.
    fn mark_ticket(act: u64, req: u64, path: &Path) -> MarkTicket {
        MarkTicket::new(
            Activation(act),
            RequestId(req),
            vec![path.to_path_buf()],
            vec![(path.to_path_buf(), None)],
        )
        .expect("a one-path ticket is valid")
    }

    /// Mandate 3: the constructor refuses halves that disagree — a ticket that could settle a
    /// path it never covered, or forget one it did, must be unbuildable.
    #[test]
    fn the_ticket_constructor_rejects_disagreeing_halves() {
        let a = PathBuf::from("/x/a.bin");
        let b = PathBuf::from("/x/b.bin");
        let dup = MarkTicket::new(
            Activation(1),
            RequestId(1),
            vec![a.clone(), a.clone()],
            vec![(a.clone(), None)],
        )
        .expect_err("a duplicated pathname is refused");
        assert_eq!(
            *dup.reason(),
            SendRefusal::DuplicatePath { path: a.clone() }
        );
        let missing = MarkTicket::new(
            Activation(7),
            RequestId(9),
            vec![a.clone(), b.clone()],
            vec![(a.clone(), None)],
        )
        .expect_err("a before-image that skips a path is refused");
        assert_eq!(
            *missing.reason(),
            SendRefusal::BeforeImageMismatch { path: b.clone() }
        );
        // The rejected-input carrier discards NOTHING the caller supplied.
        match &missing {
            RefusedMarkSend::Invalid { inputs, .. } => {
                assert_eq!(inputs.act, Activation(7));
                assert_eq!(inputs.req, RequestId(9));
                assert_eq!(inputs.paths, vec![a.clone(), b.clone()]);
                assert_eq!(inputs.before, vec![(a.clone(), None)]);
            }
            other => panic!("a constructor refusal carries the raw inputs: {other:?}"),
        }
        let extra = MarkTicket::new(
            Activation(1),
            RequestId(1),
            vec![a.clone()],
            vec![(a.clone(), None), (b.clone(), Some(MarkIntent::Keeper))],
        )
        .expect_err("a before-image that invents a path is refused");
        assert_eq!(
            *extra.reason(),
            SendRefusal::BeforeImageMismatch { path: b.clone() }
        );
        assert_eq!(
            extra.before().to_vec(),
            vec![(a.clone(), None), (b.clone(), Some(MarkIntent::Keeper))],
            "the before-image comes back with the refusal"
        );
        let doubled = MarkTicket::new(
            Activation(1),
            RequestId(1),
            vec![a.clone()],
            vec![(a.clone(), None), (a.clone(), None)],
        )
        .expect_err("a doubled before-image row is refused");
        assert_eq!(*doubled.reason(), SendRefusal::DuplicatePath { path: a });
    }

    /// Mandates 1 and 2: an intersecting path set and a duplicate request id are refused
    /// typed, the older entry survives untouched, and settling releases the locks so a retry
    /// succeeds.
    #[test]
    fn conflicting_registrations_are_refused_without_overwriting() {
        let mut rig = Rig::new("inflight_conflicts", BrowseRole::Operator);
        rig.open(1);
        let [a1, a2, ..] = rig.files.clone();
        // Park the actor so the first mutation stays in flight while the conflicts land.
        let (at_gate_tx, at_gate) = crossbeam_channel::bounded::<()>(1);
        let (go_tx, go) = crossbeam_channel::bounded::<()>(1);
        let mut fired = false;
        rig.hooks.on_dispatch(move || {
            if fired {
                return;
            }
            fired = true;
            let _ = at_gate_tx.send(());
            let _ = go.recv();
        });
        let first = rig.req();
        rig.handle
            .send_set_marks(
                Activation(1),
                first,
                vec![keeper_entry(&a1), delete_entry(&a2)],
                vec![(a1.clone(), None), (a2.clone(), None)],
            )
            .expect("the first mutation registers and enqueues");
        at_gate
            .recv_timeout(Duration::from_secs(10))
            .expect("the actor must reach the dispatch gate");
        let second = rig.req();
        let refused = rig
            .handle
            .send_set_marks(
                Activation(1),
                second,
                vec![delete_entry(&a2)],
                vec![(a2.clone(), Some(MarkIntent::Keeper))],
            )
            .expect_err("a live path must refuse the second registration");
        // The refused newcomer comes back COMPLETE and unchanged.
        match &refused {
            RefusedMarkSend::Refused { reason, ticket } => {
                assert_eq!(*reason, SendRefusal::PathAlreadyLive { path: a2.clone() });
                assert_eq!(ticket.act, Activation(1));
                assert_eq!(ticket.req, second);
                assert_eq!(ticket.paths, vec![a2.clone()]);
                assert_eq!(ticket.before, vec![(a2.clone(), Some(MarkIntent::Keeper))]);
            }
            other => panic!("a conflict returns the whole newcomer ticket: {other:?}"),
        }
        let elsewhere = rig.dir.join("elsewhere.bin");
        let dup = rig
            .handle
            .register_ticket(mark_ticket(1, first.0, &elsewhere))
            .expect_err("a live request id must refuse a second ticket");
        match &dup {
            RefusedMarkSend::Refused { reason, ticket } => {
                assert_eq!(*reason, SendRefusal::RequestAlreadyLive);
                assert_eq!(ticket.req, first, "the newcomer comes back whole");
                assert_eq!(ticket.paths, vec![elsewhere.clone()]);
            }
            other => panic!("a duplicate id returns the whole newcomer ticket: {other:?}"),
        }
        go_tx.send(()).unwrap();
        match rig.recv() {
            BrowseEvent::MarkAck {
                req,
                outcome: MarkOutcome::Settled { .. },
                ..
            } => assert_eq!(req, first),
            other => panic!("the first mutation settles: {other:?}"),
        }
        // The original ticket outlived the refused newcomers, before-image intact.
        match rig.handle.settle(first) {
            Some(Settled::Marks(ticket)) => {
                assert_eq!(ticket.req, first);
                assert_eq!(ticket.before, vec![(a1.clone(), None), (a2.clone(), None)]);
            }
            other => panic!("the original ticket must survive untouched: {other:?}"),
        }
        // Its locks went with it: the refused retry now succeeds end to end.
        let retry = rig.req();
        rig.handle
            .send_set_marks(
                Activation(1),
                retry,
                vec![delete_entry(&a2)],
                vec![(a2.clone(), Some(MarkIntent::Keeper))],
            )
            .expect("settlement releases the path locks");
        match rig.recv() {
            BrowseEvent::MarkAck { req, .. } => assert_eq!(req, retry),
            other => panic!("the retry settles: {other:?}"),
        }
        assert!(rig.handle.settle(retry).is_some());
        rig.shutdown();
    }

    /// Mandate 4: however fast the reply races back, the ticket was registered before the
    /// enqueue, so the observer of the event always finds it settleable.
    #[test]
    fn the_ticket_exists_before_its_event_can_be_observed() {
        let mut rig = Rig::new("ticket_before_event", BrowseRole::Operator);
        rig.open(1);
        let [a1, a2, ..] = rig.files.clone();
        let req = rig.req();
        rig.handle
            .send_set_marks(
                Activation(1),
                req,
                vec![keeper_entry(&a1), delete_entry(&a2)],
                vec![(a1.clone(), None), (a2.clone(), None)],
            )
            .expect("the mutation registers and enqueues");
        match rig.recv() {
            BrowseEvent::MarkAck {
                req: got,
                outcome: MarkOutcome::Settled { .. },
                ..
            } => assert_eq!(got, req),
            other => panic!("the mutation settles: {other:?}"),
        }
        match rig.handle.settle(req) {
            Some(Settled::Marks(ticket)) => assert_eq!(ticket.paths, vec![a1, a2]),
            other => panic!("the registration preceded the enqueue: {other:?}"),
        }
        rig.shutdown();
    }

    /// Mandate 5: a failed enqueue rolls the registration back whole — the before-image comes
    /// back, and no path lock or long-operation slot leaks.
    #[test]
    fn a_failed_enqueue_rolls_the_registration_back_whole() {
        let mut rig = Rig::new("rollback", BrowseRole::Operator);
        rig.open(1);
        let [a1, ..] = rig.files.clone();
        assert!(rig.handle.begin_close_send());
        let req = rig.req();
        let refused = rig
            .handle
            .send_set_marks(
                Activation(1),
                req,
                vec![keeper_entry(&a1)],
                vec![(a1.clone(), Some(MarkIntent::Keeper))],
            )
            .expect_err("a post-close mutation is never accepted");
        match &refused {
            RefusedMarkSend::Refused { reason, ticket } => {
                assert_eq!(*reason, SendRefusal::Closing);
                assert_eq!(ticket.req, req);
                assert_eq!(ticket.paths, vec![a1.clone()]);
                assert_eq!(ticket.before, vec![(a1.clone(), Some(MarkIntent::Keeper))]);
            }
            other => panic!("the complete ticket comes back on Closing: {other:?}"),
        }
        // No lock leaked: the same path registers cleanly again.
        rig.handle
            .register_ticket(mark_ticket(1, req.0 + 10, &a1))
            .expect("the rollback released the path lock");
        // The long-operation slot rolls back the same way: the second refusal is Closing,
        // not LongOperationLive.
        let denied = rig
            .handle
            .send_auto_select(Activation(1), RequestId(req.0 + 20), CancelToken::new())
            .expect_err("a post-close sweep is never accepted");
        assert_eq!(denied.reason, SendRefusal::Closing);
        assert_eq!(
            denied.long_op.req,
            RequestId(req.0 + 20),
            "the refusal carries the complete long operation"
        );
        let again = rig
            .handle
            .send_auto_select(Activation(1), RequestId(req.0 + 21), CancelToken::new())
            .expect_err("still closing");
        assert_eq!(
            again.reason,
            SendRefusal::Closing,
            "the refused long operation did not stick in the slot"
        );
        match rig.recv() {
            BrowseEvent::Closed {
                cause: CloseCause::Requested,
                ..
            } => {}
            other => panic!("the close settles: {other:?}"),
        }
        rig.join.take().unwrap().join().unwrap();
        std::fs::remove_dir_all(&rig.dir).ok();
    }

    /// Mandate 6: the long operation is retained with its own token, cancellable through the
    /// ledger, refused while live, settled by its event, and free again afterwards.
    #[test]
    fn the_long_operation_is_cancellable_settled_and_refused_while_live() {
        let mut rig = Rig::new("long_op", BrowseRole::Operator);
        rig.open(1);
        let (at_gate_tx, at_gate) = crossbeam_channel::bounded::<()>(1);
        let (go_tx, go) = crossbeam_channel::bounded::<()>(1);
        let mut fired = false;
        rig.hooks.on_dispatch(move || {
            if fired {
                return;
            }
            fired = true;
            let _ = at_gate_tx.send(());
            let _ = go.recv();
        });
        let sweep = rig.req();
        let token = CancelToken::new();
        rig.handle
            .send_auto_select(Activation(1), sweep, token.clone())
            .expect("the sweep registers and enqueues");
        at_gate
            .recv_timeout(Duration::from_secs(10))
            .expect("the actor must reach the dispatch gate");
        let denied = rig
            .handle
            .send_auto_select(Activation(1), rig.ids.allocate(), CancelToken::new())
            .expect_err("one long operation at a time");
        assert_eq!(denied.reason, SendRefusal::LongOperationLive);
        assert!(rig.handle.cancel_long_operation());
        assert!(
            token.cancelled(),
            "the ledger cancels through the request's own token"
        );
        go_tx.send(()).unwrap();
        match rig.recv() {
            BrowseEvent::AutoSelectDone {
                req,
                outcome: AutoSelectOutcome::Refused(AutoSelectRefusal::CancelledBeforeFirstCommit),
                ..
            } => assert_eq!(req, sweep),
            other => panic!("the cancelled sweep settles typed: {other:?}"),
        }
        match rig.handle.settle(sweep) {
            Some(Settled::Long(long)) => assert_eq!(long.req, sweep),
            other => panic!("the long operation settles by its id: {other:?}"),
        }
        let next = rig.ids.allocate();
        rig.handle
            .send_auto_select(Activation(1), next, CancelToken::new())
            .expect("the slot is free after settlement");
        match rig.recv() {
            BrowseEvent::AutoSelectDone { req, .. } => assert_eq!(req, next),
            other => panic!("the second sweep settles: {other:?}"),
        }
        assert!(rig.handle.settle(next).is_some());
        rig.shutdown();
    }

    /// Mandate 7, deterministic half: a request linearized after `begin_close` is rejected to
    /// its caller and never enters the queue — acceptance without ownership is exactly what
    /// the old drain window allowed.
    #[test]
    fn a_send_after_close_is_rejected_locally() {
        let mut rig = Rig::new("post_close_send", BrowseRole::Operator);
        rig.open(1);
        let (at_gate_tx, at_gate) = crossbeam_channel::bounded::<()>(1);
        let (go_tx, go) = crossbeam_channel::bounded::<()>(1);
        let mut fired = false;
        rig.hooks.on_dispatch(move || {
            if fired {
                return;
            }
            fired = true;
            let _ = at_gate_tx.send(());
            let _ = go.recv();
        });
        let parked = rig.req();
        assert!(rig.handle.send_raw(BrowseRequest::MarkedCount {
            act: Activation(1),
            req: parked,
        }));
        at_gate
            .recv_timeout(Duration::from_secs(10))
            .expect("the actor must reach the dispatch gate");
        assert!(rig.handle.begin_close_send());
        assert_eq!(
            rig.handle.send(BrowseRequest::LatestScan {
                act: Activation(0),
                req: rig.ids.allocate(),
            }),
            Err(SendRefusal::Closing),
            "a post-close request is refused to the caller, never accepted"
        );
        go_tx.send(()).unwrap();
        match rig.recv() {
            BrowseEvent::MarkedCount { req, .. } => assert_eq!(req, parked),
            other => panic!("the in-flight request completes: {other:?}"),
        }
        match rig.recv() {
            BrowseEvent::Closed {
                cause: CloseCause::Requested,
                ..
            } => {}
            other => panic!("exactly one Closed follows: {other:?}"),
        }
        assert!(
            rig.events.try_recv().is_err(),
            "the rejected request has no orphan event"
        );
        rig.join.take().unwrap().join().unwrap();
        std::fs::remove_dir_all(&rig.dir).ok();
    }

    /// Mandate 7, concurrent half: two sender clones race one closer through the shared gate.
    /// Under every interleaving, an accepted send receives its declared event before the one
    /// `Closed`, and a rejected send has none — no request is ever accepted and then lost.
    #[test]
    fn no_accepted_send_is_ever_lost_across_close() {
        let mut rig = Rig::new("send_close_race", BrowseRole::Operator);
        rig.open(1);
        const PER_SENDER: u64 = 25;
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut senders = Vec::new();
        for lane in 0..2u64 {
            let handle = rig.handle.clone();
            let barrier = barrier.clone();
            senders.push(std::thread::spawn(move || {
                let mut accepted: Vec<RequestId> = Vec::new();
                barrier.wait();
                for slot in 0..PER_SENDER {
                    let req = RequestId(1_000 + lane * PER_SENDER + slot);
                    if handle
                        .send(BrowseRequest::LatestScan {
                            act: Activation(0),
                            req,
                        })
                        .is_ok()
                    {
                        accepted.push(req);
                    }
                }
                accepted
            }));
        }
        let closer = {
            let handle = rig.handle.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                assert!(handle.begin_close_send());
            })
        };
        let mut accepted: Vec<RequestId> = Vec::new();
        for sender in senders {
            accepted.extend(sender.join().unwrap());
        }
        closer.join().unwrap();
        let mut answered: Vec<RequestId> = Vec::new();
        loop {
            match rig.recv() {
                BrowseEvent::Closed {
                    cause: CloseCause::Requested,
                    ..
                } => break,
                BrowseEvent::LatestScan { req, .. } => answered.push(req),
                other => panic!("only LatestScan replies and one Closed exist: {other:?}"),
            }
        }
        accepted.sort();
        answered.sort();
        assert_eq!(
            accepted, answered,
            "accepted ⇔ answered: nothing lost, nothing invented"
        );
        assert!(rig.events.try_recv().is_err());
        rig.join.take().unwrap().join().unwrap();
        std::fs::remove_dir_all(&rig.dir).ok();
    }

    // ---- R4B-2b2a: one atomic ownership boundary ----------------------------------------------

    /// The Codex interleaving, permanent. The actor is already dead, a typed mark send parks
    /// between registration and the channel send WHILE OWNING THE GATE, and a terminal drain
    /// runs concurrently: it cannot pass the gate during the window, the dead receiver then
    /// rejects the enqueue, the sender receives its COMPLETE ticket — and the drain sees no
    /// copy of it. Red on `e5f3864`: the drain stole the just-registered ticket and the
    /// sender was refused with `before = []` out of the loss-hiding fallback.
    #[test]
    fn a_terminal_cannot_take_a_ticket_between_registration_and_enqueue() {
        let _lock = crate::panics::test_lock();
        let mut rig = Rig::new("boundary_marks", BrowseRole::Operator);
        rig.open(1);
        let [a1, ..] = rig.files.clone();
        // Kill the actor: the receiver is dropped before its Closed is observable.
        rig.hooks.on_dispatch(|| panic!("boom for the boundary"));
        assert!(rig.handle.send_raw(BrowseRequest::LatestScan {
            act: Activation(0),
            req: RequestId(900),
        }));
        match rig.recv() {
            BrowseEvent::Closed {
                cause: CloseCause::Panicked(_),
                ..
            } => {}
            other => panic!("the actor must die first: {other:?}"),
        }
        rig.join.take().unwrap().join().unwrap();
        // Park the typed send at the boundary, gate held.
        let (parked_tx, parked) = crossbeam_channel::bounded::<()>(1);
        let (go_tx, go) = crossbeam_channel::bounded::<()>(1);
        let mut fired = false;
        rig.handle.on_typed_send(move || {
            // One-shot: a later typed send in the same test must not park again.
            if fired {
                return;
            }
            fired = true;
            let _ = parked_tx.send(());
            let _ = go.recv();
        });
        let req = rig.req();
        let sender = {
            let handle = rig.handle.clone();
            let path = a1.clone();
            std::thread::spawn(move || {
                handle.send_set_marks(
                    Activation(1),
                    req,
                    vec![keeper_entry(&path)],
                    vec![(path.clone(), None)],
                )
            })
        };
        parked
            .recv_timeout(Duration::from_secs(10))
            .expect("the sender must park at the boundary");
        // The concurrent terminal drain — serialized strictly after the sender's whole
        // critical section by the gate.
        let drainer = {
            let handle = rig.handle.clone();
            std::thread::spawn(move || handle.drain_tickets())
        };
        go_tx.send(()).unwrap();
        let refused = sender
            .join()
            .unwrap()
            .expect_err("the dead receiver rejects the enqueue");
        match refused {
            RefusedMarkSend::Refused { reason, ticket } => {
                assert_eq!(reason, SendRefusal::Disconnected);
                assert_eq!(ticket.act, Activation(1));
                assert_eq!(ticket.req, req);
                assert_eq!(ticket.paths, vec![a1.clone()]);
                assert_eq!(
                    ticket.before,
                    vec![(a1.clone(), None)],
                    "the rejected sender must receive its complete before-image, \
                     not an empty vector"
                );
            }
            other => panic!("the complete ticket comes back: {other:?}"),
        }
        let drained = drainer.join().unwrap();
        assert!(
            drained.tickets.is_empty() && drained.long_op.is_none(),
            "the retirement must not own a ticket for a request that was never accepted"
        );
        std::fs::remove_dir_all(&rig.dir).ok();
    }

    /// The long-operation twin: terminal drain cannot steal the record between registration
    /// and enqueue; on the dead receiver the sender receives the exact `act`, `req` and the
    /// ORIGINAL token, and no long-op slot leaks.
    #[test]
    fn a_terminal_cannot_take_the_long_operation_between_registration_and_enqueue() {
        let _lock = crate::panics::test_lock();
        let mut rig = Rig::new("boundary_long", BrowseRole::Operator);
        rig.open(1);
        rig.hooks.on_dispatch(|| panic!("boom for the boundary"));
        assert!(rig.handle.send_raw(BrowseRequest::LatestScan {
            act: Activation(0),
            req: RequestId(901),
        }));
        match rig.recv() {
            BrowseEvent::Closed {
                cause: CloseCause::Panicked(_),
                ..
            } => {}
            other => panic!("the actor must die first: {other:?}"),
        }
        rig.join.take().unwrap().join().unwrap();
        let (parked_tx, parked) = crossbeam_channel::bounded::<()>(1);
        let (go_tx, go) = crossbeam_channel::bounded::<()>(1);
        let mut fired = false;
        rig.handle.on_typed_send(move || {
            // One-shot: a later typed send in the same test must not park again.
            if fired {
                return;
            }
            fired = true;
            let _ = parked_tx.send(());
            let _ = go.recv();
        });
        let req = rig.req();
        let token = CancelToken::new();
        let sender = {
            let handle = rig.handle.clone();
            let token = token.clone();
            std::thread::spawn(move || handle.send_auto_select(Activation(1), req, token))
        };
        parked
            .recv_timeout(Duration::from_secs(10))
            .expect("the sender must park at the boundary");
        let drainer = {
            let handle = rig.handle.clone();
            std::thread::spawn(move || handle.drain_tickets())
        };
        go_tx.send(()).unwrap();
        let refused = sender
            .join()
            .unwrap()
            .expect_err("the dead receiver rejects the enqueue");
        assert_eq!(refused.reason, SendRefusal::Disconnected);
        assert_eq!(refused.long_op.act, Activation(1));
        assert_eq!(refused.long_op.req, req);
        refused.long_op.cancel.cancel();
        assert!(
            token.cancelled(),
            "the refusal carries the ORIGINAL request-scoped token, not a substitute"
        );
        let drained = drainer.join().unwrap();
        assert!(
            drained.long_op.is_none() && drained.tickets.is_empty(),
            "the retirement must not own a long operation whose request was never accepted"
        );
        // No slot leaked: the next attempt fails on the dead channel, not on a stuck slot.
        let follow = rig
            .handle
            .send_auto_select(Activation(1), rig.ids.allocate(), CancelToken::new())
            .expect_err("the channel is still dead");
        assert_eq!(follow.reason, SendRefusal::Disconnected);
        std::fs::remove_dir_all(&rig.dir).ok();
    }

    /// Close versus typed sends, two clones, full ownership accounting: every mark attempt
    /// is either rejected with its complete ticket, or accepted — and an accepted one appears
    /// in exactly one reply AND in the retirement exactly once.
    #[test]
    fn every_typed_send_is_owned_exactly_once_across_close() {
        let mut rig = Rig::new("ownership_race", BrowseRole::Operator);
        rig.open(1);
        let files = rig.files.clone();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut lanes = Vec::new();
        for lane in 0..2usize {
            let handle = rig.handle.clone();
            let barrier = barrier.clone();
            let mine: Vec<PathBuf> = vec![files[lane * 2].clone(), files[lane * 2 + 1].clone()];
            lanes.push(std::thread::spawn(move || {
                let mut accepted: Vec<RequestId> = Vec::new();
                barrier.wait();
                for (slot, path) in mine.iter().enumerate() {
                    let req = RequestId(2_000 + (lane as u64) * 10 + slot as u64);
                    match handle.send_set_marks(
                        Activation(1),
                        req,
                        vec![keeper_entry(path)],
                        vec![(path.clone(), None)],
                    ) {
                        Ok(()) => accepted.push(req),
                        Err(RefusedMarkSend::Refused { reason, ticket }) => {
                            assert_eq!(reason, SendRefusal::Closing);
                            assert_eq!(ticket.req, req);
                            assert_eq!(ticket.paths, vec![path.clone()]);
                            assert_eq!(ticket.before, vec![(path.clone(), None)]);
                        }
                        Err(other) => {
                            panic!("only complete Closing refusals exist here: {other:?}")
                        }
                    }
                }
                accepted
            }));
        }
        let closer = {
            let handle = rig.handle.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                assert!(handle.begin_close_send());
            })
        };
        let mut accepted: Vec<RequestId> = Vec::new();
        for lane in lanes {
            accepted.extend(lane.join().unwrap());
        }
        closer.join().unwrap();
        let mut answered: Vec<RequestId> = Vec::new();
        loop {
            match rig.recv() {
                BrowseEvent::Closed {
                    cause: CloseCause::Requested,
                    ..
                } => break,
                BrowseEvent::MarkAck { req, .. } => answered.push(req),
                other => panic!("only MarkAck replies and one Closed exist: {other:?}"),
            }
        }
        accepted.sort();
        answered.sort();
        assert_eq!(
            accepted, answered,
            "every accepted mutation settles exactly once"
        );
        let mut retired: Vec<RequestId> = rig
            .handle
            .drain_tickets()
            .tickets
            .into_iter()
            .map(|ticket| ticket.req)
            .collect();
        retired.sort();
        assert_eq!(
            retired, accepted,
            "the retirement holds exactly the accepted tickets"
        );
        rig.join.take().unwrap().join().unwrap();
        std::fs::remove_dir_all(&rig.dir).ok();
    }

    /// The production API has no ungated registration seam: `register_ticket` exists only
    /// under `cfg(test)`, so runtime evidence can only enter the ledger through the gated
    /// typed sends.
    #[test]
    fn production_has_no_ungated_registration_seam() {
        let source = include_str!("browse.rs");
        let production = source
            .split_once("\n#[cfg(test)]\nmod tests")
            .map(|(production, _)| production)
            .unwrap_or(source);
        let at = production
            .find("fn register_ticket")
            .expect("the seeding seam exists");
        let preceding = &production[at.saturating_sub(400)..at];
        assert!(
            preceding.contains("#[cfg(test)]"),
            "register_ticket must be test-only"
        );
        assert_eq!(
            production.matches("fn register_ticket").count(),
            1,
            "exactly one seeding seam exists"
        );
    }

    // ---- 12. the probe matrix, pinned by counters ---------------------------------------------

    #[test]
    fn the_door_pays_exactly_the_tabled_probes() {
        let (dir, db, scan_id, files) = seeded_db("door_probes");
        let mut door = guarded::BrowsingStore::open(&db, BrowseRole::Operator).unwrap();
        let expect = |door: &guarded::BrowsingStore, before: u64, cost: u64, what: &str| {
            assert_eq!(
                door.identity_probes(),
                before + cost,
                "{what} must cost exactly {cost} probe(s)"
            );
            door.identity_probes()
        };
        let mut at = door.identity_probes();
        door.identity_check().unwrap();
        at = expect(&door, at, 1, "the reuse check");
        // Self-guarded operations: the door adds nothing.
        {
            let snapshot = door.membership_snapshot(scan_id).unwrap();
            at = expect(&door, at, 1, "membership_snapshot");
            // Snapshot readers pay nothing — the snapshot already did.
            let ids: Vec<GroupId> = snapshot
                .summaries()
                .unwrap()
                .groups
                .iter()
                .map(|(id, _)| *id)
                .collect();
            snapshot.group_page(&ids[0], 0, 10).unwrap();
            snapshot.group_member_count(&ids[0]).unwrap();
            snapshot.group_of_path(&files[0]).unwrap();
            let refs: Vec<&Path> = files.iter().map(|p| p.as_path()).collect();
            snapshot.panel_files(&refs).unwrap();
            snapshot.file_info(&files[0]).unwrap();
            snapshot.dir_group_at(&dir).unwrap();
            at = expect(&door, at, 0, "every snapshot reader together");
        }
        door.prepare_legacy_for_viewing(scan_id).unwrap();
        at = expect(&door, at, 1, "prepare_legacy_for_viewing");
        door.save_marks_settled(scan_id, &[keeper_entry(&files[0])])
            .unwrap();
        at = expect(&door, at, 1, "save_marks_settled");
        // Legacy operations: exactly one door probe each.
        door.load_config(scan_id).unwrap();
        at = expect(&door, at, 1, "load_config");
        door.scan_status(scan_id).unwrap();
        at = expect(&door, at, 1, "scan_status");
        door.scan_summary(scan_id).unwrap();
        at = expect(&door, at, 1, "scan_summary");
        door.scan_created_at(scan_id).unwrap();
        at = expect(&door, at, 1, "scan_created_at");
        door.marked_count(scan_id).unwrap();
        at = expect(&door, at, 1, "marked_count");
        door.latest_scan_id().unwrap();
        at = expect(&door, at, 1, "latest_scan_id");
        door.latest_scan_covering(&dir).unwrap();
        at = expect(&door, at, 1, "latest_scan_covering");
        door.attributed_dir_group_summaries(scan_id).unwrap();
        at = expect(&door, at, 1, "attributed_dir_group_summaries");
        door.attributed_dir_group(scan_id, "0000").unwrap();
        at = expect(&door, at, 1, "attributed_dir_group");
        door.dir_sizes_under(scan_id, std::slice::from_ref(&dir))
            .unwrap();
        at = expect(&door, at, 1, "dir_sizes_under");
        door.dir_signatures_under(
            scan_id,
            std::slice::from_ref(&dir),
            crate::model::duplicate::DirSigAlgo::Old,
        )
        .unwrap();
        at = expect(&door, at, 1, "dir_signatures_under");
        door.reconcile_marks_after_batch(scan_id, &[], false)
            .unwrap();
        at = expect(&door, at, 1, "reconcile_marks_after_batch");
        door.upsert_hash(1, 2, 3, 4, &[6u8; 32]).unwrap();
        at = expect(&door, at, 1, "upsert_hash");
        let _ = door.build_action_plan(scan_id, &[]).unwrap();
        let _ = expect(
            &door,
            at,
            1,
            "build_action_plan (the probe, whatever the plan says)",
        );
        drop(door);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The Open candidate sequence spends exactly the tabled count — 8 for an operator, 7 for
    /// an observer (`prepare` is operator-only). The open bracket's own two
    /// `probe_existing_db_file` calls live inside the store and are not `ensure_current_path`
    /// probes, so they are outside this counter by design.
    #[test]
    fn an_open_candidate_spends_the_tabled_probe_count() {
        let (dir, db, scan_id, _files) = seeded_db("open_probes");
        for (role, tabled) in [(BrowseRole::Operator, 8), (BrowseRole::Observer, 7)] {
            let mut door = guarded::BrowsingStore::open(&db, role).unwrap();
            let before = door.identity_probes();
            if role == BrowseRole::Operator {
                door.prepare_legacy_for_viewing(scan_id).unwrap();
            }
            {
                let snapshot = door.membership_snapshot(scan_id).unwrap();
                snapshot.summaries().unwrap();
            }
            door.load_config(scan_id).unwrap();
            door.scan_status(scan_id).unwrap();
            door.scan_summary(scan_id).unwrap();
            door.scan_created_at(scan_id).unwrap();
            door.marked_count(scan_id).unwrap();
            door.attributed_dir_group_summaries(scan_id).unwrap();
            assert_eq!(
                door.identity_probes() - before,
                tabled,
                "the {role:?} candidate sequence"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// One browsing interaction, one store, one validation: twenty legacy reads after the
    /// snapshot re-validate nothing, and the actor never opens a second connection — the
    /// door is the only way in, and it is built once per actor life.
    #[test]
    fn one_browsing_interaction_validates_once() {
        let (dir, db, scan_id, _files) = seeded_db("one_validation");
        let door = guarded::BrowsingStore::open(&db, BrowseRole::Observer).unwrap();
        {
            let snapshot = door.membership_snapshot(scan_id).unwrap();
            snapshot.summaries().unwrap();
        }
        assert_eq!(door.full_validation_count(), 1);
        for _ in 0..20 {
            door.scan_created_at(scan_id).unwrap();
            door.marked_count(scan_id).unwrap();
        }
        assert_eq!(
            door.full_validation_count(),
            1,
            "header-class reads must not re-validate the authority"
        );
        drop(door);
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- 13. structural dormancy ---------------------------------------------------------------

    /// Production spawns no actor and routes nothing through it; the carrier exists beside a
    /// still-live `ResultsLoaded`; the actor itself never consults the process-global role
    /// opener. Textual, deliberately: the module privacy is compiler-enforced, and this pins
    /// the half the compiler cannot see.
    #[test]
    fn production_spawns_no_actor_and_the_carrier_stays_dormant() {
        let app = include_str!("../app.rs");
        assert!(
            app.contains("browse: crate::state::browse::BrowseFleet"),
            "the dormant fleet field exists"
        );
        assert!(
            !app.contains("BrowseActor::spawn") && !app.contains(".browse.spawn"),
            "nothing in the App spawns an actor yet"
        );
        assert!(
            app.contains("AppEvent::Browse(_) => {}"),
            "the carrier arm is a no-op until R4B-2c"
        );
        let events = include_str!("../tui/event.rs");
        assert!(
            events.contains("ResultsLoaded(i64, Vec<GroupSummary>, ScanSummary, bool)"),
            "ResultsLoaded stays live beside the carrier"
        );
        assert!(events.contains("Browse(Box<crate::state::browse::BrowseEvent>)"));
        let browse = include_str!("browse.rs");
        let production = browse
            .split_once("\n#[cfg(test)]\nmod tests")
            .map(|(production, _)| production)
            .unwrap_or(browse);
        assert!(
            !production.contains("ScanStore::open("),
            "the actor opens by its own role, never by the mutable global"
        );
        assert_eq!(
            production.matches("inner: ScanStore").count(),
            1,
            "exactly one raw-store field exists, inside the guarded door"
        );
    }
}
