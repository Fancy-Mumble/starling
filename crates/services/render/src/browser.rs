//! Starting a browser, keeping it, and getting one page out of it.
//!
//! The browser is **persistent**: launching Chrome costs a few hundred
//! milliseconds and a process tree, and a service that did that per link would
//! spend more time starting browsers than rendering. One browser, a fresh
//! target per render, and the target is closed whatever happens to it - a tab
//! that outlives its render is a page that goes on running script on a server.
//!
//! It is also **replaceable**: a renderer given hostile input crashes, and the
//! honest reading of a dead socket is "the browser is gone", not "renders are
//! over". The service relaunches on the next request.
//!
//! Every flag here is either a guard, a way to stop the browser talking to
//! anything but the proxy, or a way to stop it writing to the disk it shares
//! with the server.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Semaphore;

use crate::cdp::{Cdp, CdpError, Event};

/// How long to wait for the browser to say where its debugger is.
///
/// It prints the line as soon as it is up. A browser that has not printed it in
/// this long is one that failed to start - a missing shared library, a profile
/// directory it cannot write - and the stderr collected alongside says which.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);

/// How long any one `DevTools` command may take.
///
/// Not the render budget, which is the caller's: this is the ceiling on a
/// single command, so a browser that has stopped answering is noticed rather
/// than waited on for the whole render.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// How much of the browser's own account of its failure to keep.
///
/// Chrome says what went wrong in a line or two and then repeats itself; this
/// is enough to carry the reason into the error an operator reads, and little
/// enough that a browser logging steadily cannot grow it.
const KEPT_STDERR_LINES: usize = 12;

/// What the operator settled about the browser.
#[derive(Debug, Clone)]
pub struct Options {
    /// The binary to run. Empty means "find one", which is what a container
    /// with exactly one browser in it wants.
    pub binary: String,
    /// Extra flags, for the deployment that needs one nobody anticipated.
    pub extra_args: Vec<String>,
    /// Whether to hand the renderer `--no-sandbox`.
    ///
    /// Off by default, and worth understanding before turning on. Chrome's own
    /// sandbox needs one thing this deployment may not be able to give it: the
    /// ability to create a user namespace. A pod running the Kubernetes
    /// `restricted` profile cannot, and **not because of the capability drop
    /// itself**: the container runtime's default seccomp profile permits
    /// `clone` with namespace flags only when `CAP_SYS_ADMIN` is in the
    /// bounding set (containerd's `seccomp_default.go`), so `drop: [ALL]`
    /// removes the permission along with the capability. `no_new_privs`, which
    /// `allowPrivilegeEscalation: false` sets, separately rules out the setuid
    /// helper Chrome would otherwise fall back to.
    ///
    /// So on such a pod there are three honest ways forward, in order of
    /// preference, and `deploy/render-k8s.yaml` spells all three out:
    ///
    /// 1. a sandboxing *runtime* - gVisor or Kata - where the container itself
    ///    is the boundary and Chrome's own sandbox is not the thing standing
    ///    between a page and anything;
    /// 2. a `Localhost` seccomp profile that re-permits the namespace `clone`,
    ///    which needs **no capability and no privilege escalation** and gives
    ///    Chrome its real sandbox back;
    /// 3. this - with [`Options::jitless`], which is why that exists.
    pub no_sandbox: bool,
    /// Whether to run V8 with no just-in-time compiler.
    ///
    /// Defaults to *on when the sandbox is off*, because the two decisions are
    /// the same decision. The overwhelming majority of remote-code-execution
    /// bugs in a browser are in the JIT compilers: they turn a stranger's
    /// script into native code, and a bug there is native code the page chose.
    /// `--jitless` removes that machinery, and with it `WebAssembly`, which
    /// V8 will not expose without a JIT.
    ///
    /// It is affordable *here* specifically. This browser exists to read a
    /// page's head, not to run an application: interpreted script is slower at
    /// something the deadline already bounds, and the pages it costs the most
    /// are the ones a preview learns least from.
    pub jitless: bool,
    /// How long after the load event to let a page settle before the DOM is
    /// read. Metadata written by script is written in that window.
    pub settle: Duration,
    /// The viewport, which some sites serve different markup for.
    pub window: (u32, u32),
    /// What `Accept-Language` the browser asks with.
    pub language: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            binary: String::new(),
            extra_args: Vec::new(),
            no_sandbox: false,
            jitless: false,
            settle: Duration::from_millis(300),
            window: (1280, 900),
            language: "en-US,en".to_owned(),
        }
    }
}

/// Why there is no page.
#[derive(Debug, Clone)]
pub enum RenderError {
    /// No browser binary was found or configured. The service runs without
    /// one; it just cannot render, and says so rather than pretending.
    NoBrowser,
    /// The browser would not start, with whatever it said on the way down.
    Launch(String),
    /// The browser is running and did not do what was asked.
    Cdp(CdpError),
    /// The navigation itself failed - the guard refused the address, the name
    /// does not resolve, the far end hung up.
    Navigation(String),
    /// The render did not finish inside the budget.
    TimedOut,
    /// Too many renders are already running.
    Busy,
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoBrowser => write!(f, "this server has no browser to render with"),
            Self::Launch(detail) => write!(f, "the browser would not start: {detail}"),
            Self::Cdp(error) => write!(f, "{error}"),
            Self::Navigation(detail) => write!(f, "that link would not load: {detail}"),
            Self::TimedOut => write!(f, "that link took too long to render"),
            Self::Busy => write!(f, "too many renders at once; try again"),
        }
    }
}

/// A page, as the browser had it when the render finished.
#[derive(Debug, Clone)]
pub struct Rendered {
    /// Where the browser ended up.
    pub url: String,
    /// The DOM, serialised after script ran.
    pub html: String,
    /// The main document's status, or 0 if the browser never said.
    pub status: u32,
}

/// A running browser.
#[derive(Debug)]
pub struct Browser {
    child: Child,
    cdp: Cdp,
    profile: PathBuf,
    tabs: Arc<Semaphore>,
    settle: Duration,
    /// What every target announces itself as: the browser's own user-agent
    /// with the word that gives it away taken out. See [`presentable`].
    agent: String,
    /// The language every target asks in, alongside the agent, so the two
    /// cannot disagree.
    language: String,
}

impl Browser {
    /// Start one, pointed at `proxy` and nowhere else.
    ///
    /// # Errors
    ///
    /// [`RenderError::NoBrowser`] when there is no binary to run, and
    /// [`RenderError::Launch`] when there is one and it did not come up.
    pub async fn launch(
        proxy: SocketAddr,
        options: &Options,
        tabs: usize,
    ) -> Result<Self, RenderError> {
        let binary = resolve_binary(&options.binary).ok_or(RenderError::NoBrowser)?;
        let profile = profile_dir();
        std::fs::create_dir_all(&profile)
            .map_err(|error| RenderError::Launch(format!("no profile directory: {error}")))?;

        let mut command = Command::new(&binary);
        let _ = command
            .args(browser_args(proxy, &profile, options))
            .args(&options.extra_args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|error| RenderError::Launch(format!("{}: {error}", binary.display())))?;

        // Drained for the life of the browser, and started before anything
        // waits on it. A pipe nobody reads fills, and a browser whose stderr is
        // full stops - which would look exactly like a browser that hangs on
        // the tenth page.
        //
        // The last few lines are kept, because they are the difference between
        // "the browser would not start" and an operator knowing why. Chrome
        // says exactly what is wrong on the way down - a namespace it could not
        // create, a library that is missing, a profile directory it cannot
        // write - and that sentence used to go to a trace log nobody had on.
        let said: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
        if let Some(stderr) = child.stderr.take() {
            let keeping = Arc::clone(&said);
            drop(tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::trace!(line, "browser");
                    keep(&keeping, line);
                }
            }));
        }

        // The file rather than the "DevTools listening on ..." line, because
        // the line is not reliably printed: Edge writes the port to
        // `DevToolsActivePort` in the profile and says nothing at all on
        // stderr, and a launcher that waits for the line waits out its whole
        // timeout against a browser that is up and answering.
        let endpoint =
            match tokio::time::timeout(STARTUP_TIMEOUT, devtools_endpoint(&profile, &mut child))
                .await
            {
                Ok(Ok(endpoint)) => endpoint,
                Ok(Err(gone)) => return Err(RenderError::Launch(explain(&gone, &said))),
                Err(_) => {
                    return Err(RenderError::Launch(explain(
                        "it never opened a debugger",
                        &said,
                    )));
                }
            };

        let cdp = Cdp::connect(&endpoint).await.map_err(RenderError::Cdp)?;
        // Asked rather than assumed. The user-agent has to match the handshake
        // that carries it - a request claiming Chrome 140 from a Chrome 152
        // TLS stack is a mismatch a bot-management service reads as easily as
        // the word "Headless" - so this takes the browser's own string and
        // edits out only the part that is not true of what it renders.
        let announced = cdp
            .call("Browser.getVersion", json!({}), None, COMMAND_TIMEOUT)
            .await
            .ok()
            .and_then(|version| {
                version
                    .get("userAgent")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_default();
        Ok(Self {
            child,
            cdp,
            profile,
            tabs: Arc::new(Semaphore::new(tabs.max(1))),
            settle: options.settle,
            agent: presentable(&announced),
            language: options.language.clone(),
        })
    }

    /// Whether this browser is still worth sending a page to.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.cdp.is_alive()
    }

    /// Render one page.
    ///
    /// # Errors
    ///
    /// [`RenderError`]: no capacity, a browser that stopped answering, a
    /// navigation the guard or the network refused, or a page that did not
    /// finish inside `budget`.
    pub async fn render(&self, url: &str, budget: Duration) -> Result<Rendered, RenderError> {
        let Ok(_tab) = Arc::clone(&self.tabs).try_acquire_owned() else {
            return Err(RenderError::Busy);
        };
        // Two bounds, and they do different jobs. The inner one is a deadline
        // the wait *returns* at, with whatever the page has become by then; the
        // outer one is the backstop for a browser that has stopped answering
        // at all. A render that only had the outer bound would throw away a
        // perfectly good DOM for want of the last few hundred milliseconds.
        let settling = std::time::Instant::now() + budget.mul_f32(0.7);
        tokio::time::timeout(budget, self.one_page(url, settling))
            .await
            .unwrap_or(Err(RenderError::TimedOut))
    }

    /// The render itself, with the target closed whatever it does.
    async fn one_page(
        &self,
        url: &str,
        settling: std::time::Instant,
    ) -> Result<Rendered, RenderError> {
        let created = self
            .command("Target.createTarget", json!({ "url": "about:blank" }), None)
            .await?;
        let target = created
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or(RenderError::Cdp(CdpError::Unexpected("targetId")))?
            .to_owned();

        let outcome = self.in_target(&target, url, settling).await;

        // Closed on the way out, on every path. A target that survives its
        // render is a page still running script, still holding sockets, in a
        // browser that will be asked to render the next link.
        let _ = self
            .command("Target.closeTarget", json!({ "targetId": target }), None)
            .await;
        outcome
    }

    /// Attach, navigate, wait, read.
    async fn in_target(
        &self,
        target: &str,
        url: &str,
        settling: std::time::Instant,
    ) -> Result<Rendered, RenderError> {
        let attached = self
            .command(
                "Target.attachToTarget",
                json!({ "targetId": target, "flatten": true }),
                None,
            )
            .await?;
        let session = attached
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or(RenderError::Cdp(CdpError::Unexpected("sessionId")))?
            .to_owned();

        let _ = self
            .command("Page.enable", json!({}), Some(&session))
            .await?;
        // For the status of the main document. A page that renders a block page
        // is still blocked, and a caller that cannot see the 403 would learn
        // the wrong lesson about which method works for that host.
        let _ = self
            .command("Network.enable", json!({}), Some(&session))
            .await?;
        // Measured, 2026-09-08: headless Edge announces
        // `... HeadlessChrome/152.0.0.0 ... Edg/152.0.0.0`, and idealo answers
        // that with the same 403 it gives an HTTP client - a whole browser
        // spent to be refused by a substring. With the word removed, the same
        // render returns the page.
        if !self.agent.is_empty() {
            let _ = self
                .command(
                    "Network.setUserAgentOverride",
                    json!({ "userAgent": self.agent, "acceptLanguage": self.language }),
                    Some(&session),
                )
                .await?;
        }

        // Lifecycle events, for `networkAlmostIdle`: the signal that a page has
        // stopped fetching things, as distinct from having fired its load
        // event. On an ad-heavy page the two are seconds apart, and without
        // this every such render waits out its whole deadline.
        let _ = self
            .command(
                "Page.setLifecycleEventsEnabled",
                json!({ "enabled": true }),
                Some(&session),
            )
            .await?;

        // Subscribed *before* the navigation: a page served from a warm
        // connection can finish loading before a subscription taken afterwards
        // exists, and then the wait below is a wait for an event that already
        // happened.
        let events = self.cdp.events();

        let navigated = self
            .command("Page.navigate", json!({ "url": url }), Some(&session))
            .await?;
        if let Some(failure) = navigated.get("errorText").and_then(Value::as_str) {
            return Err(RenderError::Navigation(failure.to_owned()));
        }
        let frame = navigated
            .get("frameId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();

        let status = wait_until_quiet(events, &session, &frame, self.settle, settling).await;

        let html = self
            .evaluate(&session, "document.documentElement.outerHTML")
            .await?;
        let final_url = self.evaluate(&session, "location.href").await?;
        Ok(Rendered {
            url: if final_url.is_empty() {
                url.to_owned()
            } else {
                final_url
            },
            html,
            status,
        })
    }

    /// One expression, evaluated for a string.
    async fn evaluate(&self, session: &str, expression: &str) -> Result<String, RenderError> {
        let evaluated = self
            .command(
                "Runtime.evaluate",
                json!({ "expression": expression, "returnByValue": true }),
                Some(session),
            )
            .await?;
        Ok(evaluated
            .get("result")
            .and_then(|result| result.get("value"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned())
    }

    /// One command, with this file's ceiling on how long it may take.
    async fn command(
        &self,
        method: &str,
        params: Value,
        session: Option<&str>,
    ) -> Result<Value, RenderError> {
        self.cdp
            .call(method, params, session, COMMAND_TIMEOUT)
            .await
            .map_err(RenderError::Cdp)
    }

    /// Stop the browser and take its profile directory with it.
    pub async fn shutdown(mut self) {
        self.cdp.notify("Browser.close", &json!({}));
        let _ = self.child.kill().await;
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        // Asked to close over CDP *and* killed as a child, because which of the
        // two works depends on the platform: Windows Edge re-execs, so the
        // process this code holds is a launcher that has already exited and
        // killing it stops nothing. The DevTools request reaches the browser
        // that is actually running.
        self.cdp.notify("Browser.close", &json!({}));
        // And the directory it leaves behind: a profile per launch, and a
        // service that relaunches on every crash would otherwise fill the temp
        // directory with them. Best effort - the browser may still be exiting,
        // and a profile that outlives one drop is swept by the next launch's
        // own cleanup rather than worth blocking a drop over.
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

/// Wait for the page to stop doing things, and take the main document's status
/// on the way.
///
/// The load event is **not** the end of a render, and the sites this service
/// exists for are exactly the ones where it is not. idealo's first answer is a
/// 2.6 KB script that runs, decides, and navigates the frame to the real page:
/// a render that read the DOM at `load` plus a fixed pause captured the
/// interstitial, which has no title and no metadata at all. So this waits for a
/// *quiet* page - loaded, and then `settle` with nothing of its own happening -
/// and a navigation puts it back to waiting.
///
/// Bounded by `deadline` rather than by patience: a page with a heartbeat never
/// goes quiet, and the answer for one of those is the DOM as it stands.
///
/// The status is the **last** main-document response, not the first. A
/// challenge that 403s and then serves the page on the second request would
/// otherwise be reported as a 403 with the real page's DOM attached, and the
/// caller would learn the wrong thing about that host.
async fn wait_until_quiet(
    mut events: tokio::sync::broadcast::Receiver<Event>,
    session: &str,
    frame: &str,
    settle: Duration,
    deadline: std::time::Instant,
) -> u32 {
    let mut status = 0;
    let mut loaded = false;
    let mut last = std::time::Instant::now();
    loop {
        let now = std::time::Instant::now();
        let Some(left) = deadline.checked_duration_since(now) else {
            return status;
        };
        // Before the load event, the only bound is the deadline. After it, the
        // page has `settle` to do something else before this calls it done.
        let wait = if loaded {
            match settle.checked_sub(now.saturating_duration_since(last)) {
                Some(remaining) => remaining.min(left),
                None => return status,
            }
        } else {
            left
        };
        let Ok(received) = tokio::time::timeout(wait, events.recv()).await else {
            // Quiet for long enough, or out of time. Either way this is as
            // finished as the page is going to get.
            return status;
        };
        let Ok(event) = received else {
            // Lagged past the buffer, or the browser is gone. The DOM read that
            // follows is still worth attempting.
            return status;
        };
        if event.session.as_deref() != Some(session) {
            // Another render's traffic. It must not reset this one's quiet
            // window, which is the whole reason the timer is kept by hand
            // rather than taken from the timeout.
            continue;
        }
        last = std::time::Instant::now();
        // Whether this event is about the page or about something inside it.
        // An ad-heavy page runs a dozen iframes, each firing the same lifecycle
        // events as the document, and taking those at face value meant `loaded`
        // was reset by an advert every few hundred milliseconds - so the wait
        // never ended early and every such render cost its whole deadline.
        let main_frame = event
            .params
            .get("frameId")
            .and_then(Value::as_str)
            .is_none_or(|id| id == frame);
        match event.method.as_str() {
            "Network.responseReceived" => {
                let is_document = event
                    .params
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind == "Document");
                let is_main = event
                    .params
                    .get("frameId")
                    .and_then(Value::as_str)
                    .is_none_or(|id| id == frame);
                if is_document && is_main {
                    status = event
                        .params
                        .get("response")
                        .and_then(|response| response.get("status"))
                        .and_then(Value::as_u64)
                        .and_then(|code| u32::try_from(code).ok())
                        .unwrap_or(status);
                }
            }
            "Page.loadEventFired" => loaded = true,
            // The page has stopped fetching things. Chrome's own definition -
            // no more than two connections in flight for half a second - and a
            // far better end than a fixed pause: it is what ends the render on
            // a page with a heartbeat, which never goes quiet at all.
            "Page.lifecycleEvent"
                if loaded
                    && main_frame
                    && event
                        .params
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| name == "networkAlmostIdle") =>
            {
                return status;
            }
            // The interstitial moving on. Back to waiting for a load event,
            // because what is in the DOM now is the page being left.
            "Page.frameStartedLoading" | "Page.frameRequestedNavigation" if main_frame => {
                loaded = false;
            }
            _ => {}
        }
    }
}

/// Wait for the browser to write where its debugger is.
///
/// Both browsers drop `DevToolsActivePort` into the profile as soon as the
/// debugger is up: the port on the first line and the browser's own WebSocket
/// path on the second. Polled rather than watched, because a filesystem watcher
/// is a dependency and a platform question for a file that appears within a
/// second of a process this code just started.
///
/// The child is checked on every turn, so a browser that dies on startup - a
/// missing shared library, a sandbox the container will not grant - is reported
/// then rather than after the whole timeout.
async fn devtools_endpoint(profile: &Path, child: &mut Child) -> Result<String, String> {
    let marker = profile.join("DevToolsActivePort");
    // How long a browser whose launcher has exited is still given to write the
    // file. Windows Edge re-execs and the process this code started returns 0
    // immediately, with the real browser coming up behind it - so an exited
    // child is not proof of a failed launch, and treating it as one refused
    // every render on that platform. The grace is what keeps a *genuine*
    // failure fast: a browser that cannot start writes no file and is reported
    // in a moment rather than at the end of the timeout.
    const AFTER_EXIT: Duration = Duration::from_secs(3);
    let mut exited_at: Option<std::time::Instant> = None;
    loop {
        if let Ok(text) = tokio::fs::read_to_string(&marker).await
            && let Some(endpoint) = endpoint_from(&text)
        {
            return Ok(endpoint);
        }
        match (child.try_wait(), exited_at) {
            (Ok(Some(status)), None) => {
                tracing::debug!(%status, "the browser launcher exited; waiting for the browser");
                exited_at = Some(std::time::Instant::now());
            }
            (_, Some(since)) if since.elapsed() > AFTER_EXIT => {
                return Err("it exited while starting".to_owned());
            }
            _ => {}
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The WebSocket address in a `DevToolsActivePort` file, if it is complete.
///
/// `None` for a half-written one: the browser writes the two lines separately
/// and this is read on a 50 ms poll, so reading it mid-write is ordinary rather
/// than exceptional, and the answer is to look again.
fn endpoint_from(text: &str) -> Option<String> {
    let mut lines = text.lines();
    let port: u16 = lines.next()?.trim().parse().ok()?;
    let path = lines.next()?.trim();
    if !path.starts_with('/') {
        return None;
    }
    Some(format!("ws://127.0.0.1:{port}{path}"))
}

/// Remember one line the browser said, dropping the oldest when full.
///
/// Its own function so the reading loop stays a reading loop: what to keep is a
/// decision about a bounded buffer, and it is the same decision every time.
fn keep(said: &Arc<Mutex<VecDeque<String>>>, line: String) {
    let mut kept = said
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if kept.len() == KEPT_STDERR_LINES {
        let _ = kept.pop_front();
    }
    kept.push_back(line);
}

/// A launch failure, with what the browser said and - where the answer is
/// known - what to do about it.
///
/// The sandbox case earns its own sentence because it is the one an operator
/// cannot guess from the message. Chrome reports a namespace it could not
/// create; the cause is a container runtime whose default seccomp profile
/// permits the namespace `clone` only for a container holding `CAP_SYS_ADMIN`,
/// so a pod that drops every capability has dropped this too. Nothing about
/// that is visible in "Failed to move to new namespace".
fn explain(what: &str, said: &Arc<Mutex<VecDeque<String>>>) -> String {
    let kept: Vec<String> = said
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .cloned()
        .collect();
    let tail = kept.join(" | ");
    if is_sandbox_failure(&tail) {
        return format!(
            "{what}: the browser could not create its sandbox. This is what a container that \
             drops CAP_SYS_ADMIN looks like: the runtime's default seccomp profile only \
             permits the namespace clone for a container that holds it. Either give the pod a \
             seccomp profile that allows it (see deploy/render-k8s.yaml, no capability and no \
             privilege escalation required), or set browser_no_sandbox = \"true\" and read \
             what that means. The browser said: {tail}"
        );
    }
    if tail.is_empty() {
        return what.to_owned();
    }
    format!("{what}. The browser said: {tail}")
}

/// Whether what the browser said is the sandbox refusing to start.
fn is_sandbox_failure(said: &str) -> bool {
    let said = said.to_ascii_lowercase();
    [
        "failed to move to new namespace",
        "no usable sandbox",
        "sandbox helper",
        "clone_newuser",
        "operation not permitted",
    ]
    .iter()
    .any(|marker| said.contains(marker))
}

/// The flags every launch carries.
fn browser_args(proxy: SocketAddr, profile: &Path, options: &Options) -> Vec<String> {
    let (width, height) = options.window;
    let mut args = vec![
        "--headless=new".to_owned(),
        // Port 0: the browser picks, prints it, and two of these can run on one
        // host without an operator allocating ports for a socket that never
        // leaves loopback.
        "--remote-debugging-port=0".to_owned(),
        format!("--user-data-dir={}", profile.display()),
        // Everything the browser does goes through the guard.
        format!("--proxy-server=http://{proxy}"),
        // ...including the addresses Chrome would otherwise reach directly.
        // Without this, `localhost` and the deployment's own private addresses
        // bypass the proxy, which is exactly the traffic that must not.
        "--proxy-bypass-list=<-loopback>".to_owned(),
        format!("--window-size={width},{height}"),
        format!("--lang={}", options.language),
        // A browser that phones home is a browser making requests nobody asked
        // for, on a server that exists to make one request per link.
        "--no-first-run".to_owned(),
        "--no-default-browser-check".to_owned(),
        "--disable-background-networking".to_owned(),
        "--disable-component-update".to_owned(),
        "--disable-client-side-phishing-detection".to_owned(),
        "--disable-sync".to_owned(),
        "--disable-default-apps".to_owned(),
        "--disable-extensions".to_owned(),
        "--no-service-autorun".to_owned(),
        "--password-store=basic".to_owned(),
        "--use-mock-keychain".to_owned(),
        // `navigator.webdriver`, which is a one-line check any page can do and
        // several defended ones do. Nothing here drives the page - there is no
        // automation to hide, only a renderer being used as one - so the flag
        // says nothing true about this render.
        "--disable-blink-features=AutomationControlled".to_owned(),
        // Nothing here draws, and a GPU process in a container is a crash
        // looking for a reason.
        "--disable-gpu".to_owned(),
        "--hide-scrollbars".to_owned(),
        "--mute-audio".to_owned(),
        // The default /dev/shm in a container is 64 MiB, and a renderer that
        // runs out of it dies mid-page.
        "--disable-dev-shm-usage".to_owned(),
    ];
    if options.no_sandbox {
        args.push("--no-sandbox".to_owned());
        // What is left when the sandbox is gone. Each of these removes a class
        // of attack surface that a preview has no use for, and they are the
        // reason an unsandboxed render is not simply "a browser with the door
        // open": the door is off, so the rooms behind it are emptied.
        args.extend([
            // WebGL and the GPU command buffers behind it: a large native
            // surface reachable from script, on a service that draws nothing.
            "--disable-3d-apis".to_owned(),
            // Nothing here plays media, and the codecs are C++ parsers fed by
            // whatever the page links.
            "--autoplay-policy=user-gesture-required".to_owned(),
        ]);
    }
    if options.jitless {
        // `--jitless` is V8's own switch for "interpret, never compile". It
        // also takes `WebAssembly` with it, which V8 will not expose without a
        // JIT - and which is a second compiler taking bytes from the page.
        args.push("--js-flags=--jitless".to_owned());
    }
    args
}

/// The browser's user-agent, without the word that is only true of how it was
/// started.
///
/// `HeadlessChrome/152.0.0.0` becomes `Chrome/152.0.0.0`: the version, the
/// platform and the engine are all still the truth about what rendered the
/// page, and the token that is removed describes whether a window was drawn -
/// which is not something the far end has any business serving different
/// markup for.
fn presentable(announced: &str) -> String {
    announced
        .replace("HeadlessChrome", "Chrome")
        .replace("HeadlessEdg", "Edg")
}

/// Where this launch keeps its profile.
///
/// Its own directory per launch, under the system temp: a profile shared
/// between two browsers is a browser that refuses to start, and a profile
/// shared between two *renders* is a page leaving cookies for the next one.
fn profile_dir() -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    std::env::temp_dir().join(format!("starling-render-{}-{unique}", std::process::id()))
}

/// The binary to run: what the operator named, or the first one on this host.
fn resolve_binary(configured: &str) -> Option<PathBuf> {
    let configured = configured.trim();
    if !configured.is_empty() {
        // Taken at their word, including a bare name to be found on PATH: an
        // operator who names a binary gets that binary or a clear failure, not
        // a silent fallback to a different browser.
        //
        // A separator means they wrote a path, and a path that is not there is
        // a misconfiguration to report rather than a reason to go looking for
        // some other browser. `is_absolute` is not the test: on Windows
        // "/opt/chrome" is a relative path, and a configured binary that
        // silently became whatever else was installed is the failure this
        // whole branch exists to prevent.
        let path = PathBuf::from(configured);
        if configured.contains(['/', '\\']) {
            return path.exists().then_some(path);
        }
        return on_path(configured).or(Some(path));
    }
    candidates().into_iter().find(|path| path.exists())
}

/// The usual places, in the order a deployment is likely to have them.
///
/// Every platform's, on every platform: a path that does not exist costs a
/// `stat`, and a list that is conditional on `cfg!(target_os)` is a list where
/// the arm nobody builds is the arm nobody notices is wrong.
fn candidates() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    // A container image for this service installs one of these, and the bare
    // name is what the package manager put on PATH.
    for name in [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "chrome",
        "msedge",
    ] {
        if let Some(path) = on_path(name) {
            found.push(path);
        }
    }
    for fixed in [
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
        "/snap/bin/chromium",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "C:/Program Files/Google/Chrome/Application/chrome.exe",
        "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
        "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
        "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
    ] {
        found.push(PathBuf::from(fixed));
    }
    found
}

/// `name` as found on PATH, executable suffixes included.
fn on_path(name: &str) -> Option<PathBuf> {
    let suffixes: &[&str] = if cfg!(windows) { &["", ".exe"] } else { &[""] };
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|directory| {
        suffixes.iter().find_map(|suffix| {
            let candidate = directory.join(format!("{name}{suffix}"));
            candidate.is_file().then_some(candidate)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Vec<String> {
        browser_args(
            "127.0.0.1:41337".parse().expect("a loopback address"),
            Path::new("/tmp/profile"),
            &Options::default(),
        )
    }

    #[test]
    fn every_launch_goes_through_the_proxy_including_loopback() {
        // The pair that makes the guard total. `--proxy-server` alone leaves
        // localhost and the deployment's own addresses reachable directly,
        // which is the traffic the guard exists for.
        let args = args();
        assert!(
            args.iter()
                .any(|arg| arg == "--proxy-server=http://127.0.0.1:41337")
        );
        assert!(
            args.iter()
                .any(|arg| arg == "--proxy-bypass-list=<-loopback>")
        );
    }

    #[test]
    fn the_sandbox_is_on_unless_an_operator_turns_it_off() {
        assert!(!args().iter().any(|arg| arg == "--no-sandbox"));
        let options = Options {
            no_sandbox: true,
            ..Options::default()
        };
        let args = browser_args(
            "127.0.0.1:1".parse().expect("a loopback address"),
            Path::new("/tmp/profile"),
            &options,
        );
        assert!(args.iter().any(|arg| arg == "--no-sandbox"));
    }

    #[test]
    fn the_announced_agent_keeps_everything_true_and_drops_what_is_not() {
        // Short strings on purpose: the point is which token changes, and a
        // wrapped user-agent literal makes a whitespace difference look like a
        // failure of the thing under test.
        assert_eq!(
            presentable("AppleWebKit/537.36 HeadlessChrome/152.0.0.0 Edg/152.0.0.0"),
            "AppleWebKit/537.36 Chrome/152.0.0.0 Edg/152.0.0.0",
            "the version must survive: a UA that disagrees with the handshake is its own tell"
        );
        assert_eq!(
            presentable("HeadlessEdg/152.0.0.0"),
            "Edg/152.0.0.0",
            "the other spelling of the same giveaway"
        );
        // A browser that never said it was headless is left alone.
        let ordinary = "Mozilla/5.0 (X11; Linux x86_64) Chrome/152.0.0.0 Safari/537.36";
        assert_eq!(presentable(ordinary), ordinary);
    }

    #[test]
    fn each_launch_gets_its_own_profile() {
        // Two browsers on one profile is a browser that will not start, and
        // two renders on one profile is a page reading the last one's cookies.
        assert_ne!(profile_dir(), profile_dir());
    }

    #[test]
    fn a_configured_path_that_does_not_exist_is_not_silently_replaced() {
        // An operator who names a browser and gets a different one has a
        // deployment whose behaviour does not match its configuration.
        assert_eq!(resolve_binary("/nonexistent/chrome"), None);
        assert_eq!(resolve_binary("C:/nonexistent/chrome.exe"), None);
        assert_eq!(resolve_binary(r"C:\nonexistent\chrome.exe"), None);
        assert_eq!(
            resolve_binary(
                r"C:
onexistent\chrome.exe"
            ),
            None
        );
    }

    #[test]
    fn the_endpoint_comes_from_the_file_the_browser_writes() {
        // Measured on Edge 2026-09-08: two lines, the port and the path, and
        // *nothing at all* on stderr. A launcher that waited for the
        // "DevTools listening on" line waited out its whole timeout against a
        // browser that was up.
        assert_eq!(
            endpoint_from("52287\n/devtools/browser/ae098245-3404-405d\n"),
            Some("ws://127.0.0.1:52287/devtools/browser/ae098245-3404-405d".to_owned())
        );
    }

    #[test]
    fn a_half_written_file_is_read_again_rather_than_used() {
        // The two lines are written separately and this is polled, so catching
        // it mid-write is ordinary. Reading a port with no path would dial the
        // wrong URL and fail as if the browser were broken.
        assert_eq!(endpoint_from("52287\n"), None);
        assert_eq!(endpoint_from(""), None);
        assert_eq!(endpoint_from("not-a-port\n/devtools/browser/x\n"), None);
    }
}
