//! Four commands and one event, over the `DevTools` protocol.
//!
//! CDP is JSON over a WebSocket: a request carries an `id` and comes back with
//! that `id`, and everything else the browser says is an event. That is the
//! whole protocol as far as this service is concerned, which is why there is no
//! automation framework here. A CDP crate brings a process supervisor, a DOM
//! API, a screenshot pipeline and an input synthesiser to carry
//! `Page.navigate`, and each of those is dependency surface on a component
//! whose entire job is to be handed hostile input.
//!
//! One connection per browser, multiplexed: every render attaches its own
//! session to its own target, and `sessionId` is what keeps two concurrent
//! renders apart on the one socket.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

/// How many events are held for a receiver that is not reading fast enough.
///
/// A render subscribes before it navigates and then waits for one event among
/// the hundreds a page emits, so the buffer has to cover a page's worth of
/// chatter. Lagging is not fatal: the waiter falls back to its timeout, which
/// is the same outcome as a page that never finished loading.
const EVENT_BUFFER: usize = 512;

/// Something the browser said that nobody asked for.
#[derive(Debug, Clone)]
pub struct Event {
    /// The CDP method, `Page.loadEventFired` and the like.
    pub method: String,
    /// Which attached session it belongs to, when it belongs to one.
    pub session: Option<String>,
    /// The event body.
    pub params: Value,
}

/// Why a command did not produce an answer.
#[derive(Debug, Clone)]
pub enum CdpError {
    /// The socket would not open, or closed under a call in flight.
    Closed,
    /// The browser answered with an error object.
    Protocol(String),
    /// The browser did not answer in time.
    TimedOut,
    /// The answer was not shaped the way the command's caller needs.
    Unexpected(&'static str),
}

impl std::fmt::Display for CdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "the browser closed the connection"),
            Self::Protocol(message) => write!(f, "the browser refused: {message}"),
            Self::TimedOut => write!(f, "the browser did not answer in time"),
            Self::Unexpected(what) => write!(f, "the browser's answer had no {what}"),
        }
    }
}

/// The commands sent and not yet answered, by their id.
type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, CdpError>>>>>;

/// One connection to a running browser.
#[derive(Debug)]
pub struct Cdp {
    outgoing: mpsc::UnboundedSender<Message>,
    pending: Pending,
    events: broadcast::Sender<Event>,
    next_id: AtomicU64,
}

impl Cdp {
    /// Open the socket and start pumping it.
    ///
    /// # Errors
    ///
    /// [`CdpError::Closed`] when the endpoint will not accept a WebSocket,
    /// which in practice means the browser died between printing its address
    /// and this connecting.
    pub async fn connect(endpoint: &str) -> Result<Self, CdpError> {
        let (socket, _) = tokio_tungstenite::connect_async(endpoint)
            .await
            .map_err(|_| CdpError::Closed)?;
        let (mut sink, mut stream) = socket.split();
        let (outgoing, mut to_send) = mpsc::unbounded_channel::<Message>();
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let (events, _) = broadcast::channel(EVENT_BUFFER);

        drop(tokio::spawn(async move {
            while let Some(message) = to_send.recv().await {
                if sink.send(message).await.is_err() {
                    break;
                }
            }
        }));

        let reading = Arc::clone(&pending);
        let announce = events.clone();
        drop(tokio::spawn(async move {
            while let Some(Ok(message)) = stream.next().await {
                let Message::Text(text) = message else {
                    continue;
                };
                let Ok(value) = serde_json::from_str::<Value>(text.as_str()) else {
                    continue;
                };
                dispatch(&value, &reading, &announce);
            }
            // The browser is gone. Every call still waiting has to be told, or
            // it waits for its whole timeout for an answer that cannot come.
            //
            // Collected before it is drained, so this is a walk over a list in
            // a stated order rather than over whatever order the map happens to
            // hold: which command is told first does not matter here, and code
            // that reads as though it might is worth not writing.
            let abandoned: Vec<_> = lock(&reading).drain().map(|(_, waiting)| waiting).collect();
            for waiting in abandoned {
                let _ = waiting.send(Err(CdpError::Closed));
            }
        }));

        Ok(Self {
            outgoing,
            pending,
            events,
            next_id: AtomicU64::new(1),
        })
    }

    /// Everything the browser says from now on.
    #[must_use]
    pub fn events(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    /// Whether the socket is still up.
    ///
    /// What tells the service to relaunch: a browser that crashed on a page is
    /// a browser the next render must not be sent to.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        !self.outgoing.is_closed()
    }

    /// Send one command and do not wait for it.
    ///
    /// For a caller that cannot await: `Browser::drop` asks the browser to
    /// close, and on the platforms where the launcher exits and leaves the
    /// browser behind, that request is the *only* way it is ever asked. The
    /// writer task owns the socket and outlives this handle, so a command
    /// queued here goes out even as the caller is being dropped.
    pub fn notify(&self, method: &str, params: &Value) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = json!({ "id": id, "method": method, "params": params });
        let _ = self
            .outgoing
            .send(Message::Text(request.to_string().into()));
    }

    /// Send one command and wait for its answer.
    ///
    /// # Errors
    ///
    /// [`CdpError`]: the socket closing, the browser refusing the command, or
    /// no answer inside `timeout`.
    pub async fn call(
        &self,
        method: &str,
        params: Value,
        session: Option<&str>,
        timeout: Duration,
    ) -> Result<Value, CdpError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut request = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session {
            let _ = request
                .as_object_mut()
                .map(|object| object.insert("sessionId".to_owned(), json!(session)));
        }
        let (tell, told) = oneshot::channel();
        let _ = lock(&self.pending).insert(id, tell);
        if self
            .outgoing
            .send(Message::Text(request.to_string().into()))
            .is_err()
        {
            let _ = lock(&self.pending).remove(&id);
            return Err(CdpError::Closed);
        }
        match tokio::time::timeout(timeout, told).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => Err(CdpError::Closed),
            Err(_) => {
                // Dropped from the table on the way out: a command that timed
                // out must not leave a sender behind for the life of the
                // connection.
                let _ = lock(&self.pending).remove(&id);
                Err(CdpError::TimedOut)
            }
        }
    }
}

/// One message from the browser: the answer to a command, or an event.
///
/// Its own function rather than the body of the read loop, because those are
/// two different jobs: the loop owns the socket and the lifetime of the
/// connection, and this owns what one message means.
fn dispatch(value: &Value, pending: &Pending, events: &broadcast::Sender<Event>) {
    // An `id` means it is the answer to something this end sent. Everything
    // else the browser says is an event.
    if let Some(id) = value.get("id").and_then(Value::as_u64) {
        // The entry is taken out under the lock and answered outside it: a
        // `oneshot::send` runs the receiver's waker, and doing that while
        // holding the table would let a waking task contend for it.
        let waiting = lock(pending).remove(&id);
        if let Some(waiting) = waiting {
            let _ = waiting.send(answer(value));
        }
        return;
    }
    let Some(method) = value.get("method").and_then(Value::as_str) else {
        return;
    };
    // No receivers is the ordinary state between renders, and not a reason to
    // stop reading the socket.
    let _ = events.send(Event {
        method: method.to_owned(),
        session: value
            .get("sessionId")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        params: value.get("params").cloned().unwrap_or(Value::Null),
    });
}

/// The result half of a reply, or the error the browser put there instead.
fn answer(value: &Value) -> Result<Value, CdpError> {
    if let Some(error) = value.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("no message");
        return Err(CdpError::Protocol(message.to_owned()));
    }
    Ok(value.get("result").cloned().unwrap_or(Value::Null))
}

/// The table, never poisoned into a panic.
///
/// A poisoned lock here would end every later render for the life of the
/// process, and the state it protects is a map of pending replies: the worst a
/// recovered guard can cost is one command's answer.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_carrying_an_error_is_an_error_and_not_an_empty_result() {
        // The failure this prevents: `Target.createTarget` refused for want of
        // a browser context comes back as a well-formed reply with an `error`
        // object, and reading `result` from it yields `null`, which would have
        // been rendered as a page with no content rather than reported.
        let refused = json!({
            "id": 3,
            "error": { "code": -32000, "message": "Cannot create target" }
        });
        match answer(&refused) {
            Err(CdpError::Protocol(message)) => assert!(message.contains("Cannot create target")),
            other => panic!("an error reply must not read as a result: {other:?}"),
        }
    }

    #[test]
    fn a_reply_with_no_result_is_still_a_success() {
        // `Page.enable` answers with an empty object, and a command that
        // succeeded must not be reported as one that failed.
        assert!(answer(&json!({ "id": 1, "result": {} })).is_ok());
        assert!(answer(&json!({ "id": 1 })).is_ok());
    }
}
