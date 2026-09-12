//! `render`: the last rung of the preview ladder, in its own process.
//!
//! `link-preview` reads the web with an HTTP client, which is right for the web
//! as it is published and wrong for the part of it that is defended. A
//! bot-management service scores the TLS handshake and the header set, not the
//! user-agent: idealo answers `Discordbot`, `Googlebot`, `TelegramBot` and a
//! full Chrome header set with the same 403, and a real browser with the page.
//! Some sites also assemble their metadata in script, which no fetch of the
//! HTML can run. Both are the same request from here: render it in a browser.
//!
//! # Why a service of its own
//!
//! **It carries a browser.** A process tree, a profile directory and a few
//! hundred megabytes of resident memory, which a server that previews nothing
//! should not be paying for, and which does not belong in the address space of
//! the process holding the channel tree.
//!
//! **It runs a renderer over bytes a stranger chose.** That is the single most
//! attackable thing this deployment does, and it is now the one thing that can
//! be given its own container, its own seccomp profile and its own memory
//! limit without taking the server with it when it dies.
//!
//! Split it out and `link-preview` dials it over gRPC; leave it in
//! `--all-in-one` and the call never leaves the process. Neither side knows
//! which, which is the point of the resolver.
//!
//! # The guard
//!
//! A browser resolves its own names and opens its own sockets, so the SSRF
//! guard cannot be a check on the URL here. It is a proxy: the browser is
//! started with `--proxy-server` pointing at a loopback listener this service
//! owns and `--proxy-bypass-list=<-loopback>` so nothing escapes it, and every
//! request the render makes - document, redirect, script, tracker - is vetted,
//! resolved and connected by address there. See `proxy.rs`.

pub mod browser;
pub mod cdp;
pub mod proxy;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use starling_outbound::vet;
use starling_proto_fancy::render::render_server::{Render, RenderServer};
use starling_proto_fancy::render::{FetchReply, FetchRequest};
use starling_runtime::health::Readiness;
use starling_runtime::log::{Category, LogEvent, Logger};
use starling_runtime::metrics::Counter;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use crate::browser::{Browser, Options, RenderError, Rendered};

/// The service.
#[derive(Debug)]
pub struct RenderService {
    /// The browser, launched on the first render and relaunched when it dies.
    ///
    /// Lazy rather than started at boot: a server whose ladder never reaches
    /// this rung should not be running a browser, and a service that launched
    /// one at start-up would make "configured" and "in use" the same thing.
    browser: Mutex<Option<Arc<Browser>>>,
    options: Options,
    /// Where the browser is allowed to talk to. Bound in `build`, served in
    /// `run`: the address has to exist before a launch, and a browser may be
    /// launched by the first request either of them wins.
    proxy: Mutex<Option<proxy::Guarded>>,
    proxy_address: SocketAddr,
    /// What a render costs at most, and the ceiling on what a caller may ask
    /// for. A caller naming a longer budget gets this one.
    budget: Duration,
    /// The most DOM that travels back.
    ///
    /// A rendered page is larger than a fetched one - it is the document *plus*
    /// everything script built - and it crosses a gRPC hop in a split
    /// deployment, where the default decode limit is 4 MiB and a page past it
    /// fails as "the render service refused" rather than as "that page is
    /// enormous". The caller reads the head, so the cap costs a preview
    /// nothing.
    max_html: usize,
    tabs: usize,
    health: starling_runtime::health::Health,
    logger: Logger,
    rendered: Counter,
    refused: Counter,
}

impl RenderService {
    /// Render one page, or say why not.
    async fn fetch(&self, url: &str, budget: Duration) -> Result<Rendered, RenderError> {
        // Vetted here as well as by the caller. This service is dialable in a
        // split deployment, so a guard that only ran in `link-preview` would
        // hold exactly as long as nothing else ever dialled this.
        if let Err(refusal) = vet(url) {
            return Err(RenderError::Navigation(refusal.reason().to_owned()));
        }
        let browser = self.browser().await?;
        browser.render(url, budget).await
    }

    /// The running browser, started or restarted as needed.
    async fn browser(&self) -> Result<Arc<Browser>, RenderError> {
        let mut held = self.browser.lock().await;
        if let Some(browser) = held.as_ref() {
            if browser.is_alive() {
                return Ok(Arc::clone(browser));
            }
            // A renderer given hostile input crashes, and this is what that
            // looks like from here: a socket that closed. The dead one is
            // dropped, which kills the process tree and takes its profile
            // directory with it.
            tracing::warn!("the browser died; starting another");
            self.logger.log(LogEvent::warning(
                Category::Server,
                "render: the browser died and was restarted",
            ));
            let _ = held.take();
        }
        let started = Browser::launch(self.proxy_address, &self.options, self.tabs).await;
        match started {
            Ok(browser) => {
                self.health.set("browser", Readiness::Ready);
                let browser = Arc::new(browser);
                *held = Some(Arc::clone(&browser));
                Ok(browser)
            }
            Err(error) => {
                // A server with no browser is a poorer server, not a broken
                // one: the ladder below this rung still works, and every
                // preview that does not need a browser still happens. So this
                // is a warning gate rather than an unready one.
                self.health.set("browser", Readiness::Warning);
                Err(error)
            }
        }
    }
}

/// The gRPC surface, as a type this crate owns.
#[derive(Debug, Clone)]
pub struct RenderRpc(Arc<RenderService>);

#[tonic::async_trait]
impl Render for RenderRpc {
    async fn fetch(&self, request: Request<FetchRequest>) -> Result<Response<FetchReply>, Status> {
        let asked = request.into_inner();
        // The operator's ceiling wins over the caller's ask. A budget is a
        // bound on this server's work, and a caller that could raise it could
        // hold a browser tab for as long as it liked.
        let budget = match asked.timeout_ms {
            0 => self.0.budget,
            asked => Duration::from_millis(u64::from(asked)).min(self.0.budget),
        };
        match self.0.fetch(&asked.url, budget).await {
            Ok(page) => {
                self.0.rendered.inc();
                Ok(Response::new(FetchReply {
                    final_url: page.url,
                    html: capped(page.html, self.0.max_html),
                    status: page.status,
                    error: String::new(),
                }))
            }
            // A failure is a *reply*, not a `Status`. The caller's question is
            // "can this link be previewed with a browser", and "no" is an
            // answer to it: a transport error would be indistinguishable from
            // the render service being down, which is a different fact and
            // leads to a different decision about the host.
            Err(error) => {
                self.0.refused.inc();
                tracing::debug!(url = %asked.url, %error, "render refused");
                Ok(Response::new(FetchReply {
                    final_url: String::new(),
                    html: String::new(),
                    status: 0,
                    error: error.to_string(),
                }))
            }
        }
    }
}

/// `html`, cut to at most `cap` bytes on a character boundary.
///
/// A cut in the middle of a multi-byte character would panic on a slice and
/// produce mojibake if it did not, on input a stranger chose. What is dropped
/// is the tail of a body nothing was going to read: the metadata a caller wants
/// is in the head, at the front.
fn capped(html: String, cap: usize) -> String {
    if html.len() <= cap {
        return html;
    }
    let mut end = cap;
    while end > 0 && !html.is_char_boundary(end) {
        end -= 1;
    }
    tracing::debug!(bytes = html.len(), cap, "rendered page truncated");
    let mut html = html;
    html.truncate(end);
    html
}

impl Serve for RenderService {
    const NAME: &'static str = "render";

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let service = ctx.service();
        let default = Options::default();
        let no_sandbox = service
            .option::<bool>("browser_no_sandbox")
            .unwrap_or(false);
        let options = Options {
            binary: service
                .option::<String>("browser_binary")
                .unwrap_or_default(),
            extra_args: service
                .option::<String>("browser_args")
                .map(|args| {
                    args.split_whitespace()
                        .map(ToOwned::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            no_sandbox,
            // The two are one decision: a renderer with no sandbox around it
            // should not also be compiling a stranger's script to native code.
            // An operator can still separate them - a sandboxed browser that
            // wants no JIT either, or an unsandboxed one that needs a page only
            // the JIT is fast enough for - but the default follows the sandbox.
            jitless: service
                .option::<bool>("browser_jitless")
                .unwrap_or(no_sandbox),
            settle: service
                .option::<u64>("browser_settle_ms")
                .map_or(default.settle, Duration::from_millis),
            window: (
                service.option::<u32>("browser_width").unwrap_or(1280),
                service.option::<u32>("browser_height").unwrap_or(900),
            ),
            language: service
                .option::<String>("browser_language")
                .unwrap_or(default.language),
        };
        // Tabs, not processes: one browser serves them all, and each render
        // gets its own target. Two is the default because a render is seconds
        // of a whole browser engine, and a server that will run eight at once
        // has promised a stranger eight renderers' worth of memory.
        let tabs = service.option::<usize>("render_concurrency").unwrap_or(2);
        let guarded = proxy::Guarded::bind(tabs.max(1) * 32)
            .await
            .map_err(|error| {
                ServiceError::Service(format!("render: no loopback port for the guard: {error}"))
            })?;
        let proxy_address = guarded.address();

        if no_sandbox {
            // Loud, once, at startup rather than only in a config file: this is
            // the setting whose consequences an operator most needs to have
            // been told about, and a log is where somebody inheriting the
            // deployment will find it.
            tracing::warn!(
                "render: the browser runs without its own sandbox; the container is the boundary"
            );
            ctx.logger.log(LogEvent::warning(
                Category::Server,
                "render: the browser runs without Chrome's sandbox (browser_no_sandbox)",
            ));
        }

        // Declared warming rather than ready: nothing has started a browser
        // yet, and a service reporting ready before it knows whether it has one
        // is a service that answers the operator's question wrongly.
        ctx.health.gate("browser");

        Ok(Arc::new(Self {
            browser: Mutex::new(None),
            options,
            proxy: Mutex::new(Some(guarded)),
            proxy_address,
            budget: service
                .option::<u64>("render_timeout_ms")
                .map_or(Duration::from_secs(20), Duration::from_millis),
            max_html: service
                .option::<usize>("render_max_html_bytes")
                .unwrap_or(2 * 1024 * 1024),
            tabs,
            health: ctx.health.clone(),
            logger: ctx.logger.clone(),
            rendered: ctx.metrics.counter("render.pages"),
            refused: ctx.metrics.counter("render.refused"),
        }))
    }

    fn routes(self: Arc<Self>) -> tonic::service::Routes {
        tonic::service::Routes::default().add_service(RenderServer::new(RenderRpc(self)))
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let guarded = self.proxy.lock().await.take();
        if let Some(guarded) = guarded {
            tracing::debug!(address = %self.proxy_address, "the render guard is listening");
            // The guard serves until it is dropped, so the drain has to be
            // what drops it: left to run, this task was cut off at the end of
            // its grace on every stop, and a deployment under test stops once
            // per test.
            tokio::select! {
                () = ctx.shutdown.wait() => {}
                () = guarded.serve() => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_is_cut_on_a_character_boundary() {
        // The input is a page a stranger chose, so a cut mid-character is a
        // panic reachable from a pasted link. The euro sign is three bytes at
        // offsets 2..5, so a cap of 3 or 4 lands inside it.
        let page = "aa\u{20ac}bb".to_owned();
        assert_eq!(capped(page.clone(), 1024), page, "under the cap, untouched");
        assert_eq!(capped(page.clone(), 4), "aa");
        assert_eq!(capped(page.clone(), 3), "aa");
        assert_eq!(capped(page, 5), "aa\u{20ac}");
    }

    #[test]
    fn a_caller_cannot_ask_for_a_longer_budget_than_the_operator_allows() {
        // The rule the RPC applies, on its own: a budget is a bound on this
        // server's work, and "the caller asked nicely" is not a reason to hold
        // a browser tab for a minute.
        let operator = Duration::from_secs(20);
        let asked = |ms: u32| match ms {
            0 => operator,
            ms => Duration::from_millis(u64::from(ms)).min(operator),
        };
        assert_eq!(asked(0), operator, "zero means the operator's number");
        assert_eq!(asked(5_000), Duration::from_secs(5), "a smaller ask stands");
        assert_eq!(asked(600_000), operator, "a larger one does not");
    }
}
