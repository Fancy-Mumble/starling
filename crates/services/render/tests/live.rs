//! What the browser does against the real web.
//!
//! Every test here is `#[ignore]`d: they need a browser installed and they
//! reach hosts nobody in this deployment controls, so they are not CI's to run
//! and not a gate on a merge. They are the record of *why* this service is
//! shaped the way it is, and the way to check it after touching the browser
//! flags, the waiter or the proxy:
//!
//! ```text
//! cargo test -p starling-render -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! `--test-threads=1` matters: each of these starts a browser of its own, and
//! three browsers rendering the same defended site at once is a different
//! experiment from the one being run - the bot-walled page has been seen to
//! fail that way and pass on its own.
//!
//! `STARLING_TEST_BROWSER` names a browser on a machine that has none
//! installed, and `STARLING_TEST_NO_SANDBOX` is for a host whose kernel will
//! not give Chrome its sandbox; see [`options`].
//!
//! A failure here is a finding about the web, not necessarily a bug: idealo can
//! change what it serves, and the first thing to check is whether the page
//! still behaves as the comments say it did.

// An integration test is its own crate, so it is neither `#[cfg(test)]` to
// clippy nor a user of everything the library it exercises depends on.
#![expect(
    clippy::expect_used,
    reason = "AUDIT: a test, and a browser that will not start is a failure to               report rather than one to paper over"
)]

// Linked because this is a test *of* the library, used because none of them is
// what these tests are made of.
use futures_util as _;
use serde_json as _;
use starling_outbound as _;
use starling_proto_fancy as _;
use starling_runtime as _;
use tokio_tungstenite as _;
use tonic as _;
use tracing as _;

use std::time::Duration;

use starling_render::browser::{Browser, Options};
use starling_render::proxy::Guarded;

/// How to start a browser on the machine running these.
///
/// Two environment variables rather than the service's own options, because
/// these tests do not read a configuration file:
///
/// * `STARLING_TEST_BROWSER` - a browser to use instead of whichever one is
///   found. A machine with no packaged browser can point this at an unpacked
///   Chrome for Testing build.
/// * `STARLING_TEST_NO_SANDBOX` - set it where the kernel will not give Chrome
///   its sandbox. A distribution that restricts unprivileged user namespaces
///   is the usual reason, and it is a property of the host rather than of this
///   code, so a test that cannot run without it should say so out loud rather
///   than quietly turn the sandbox off for everybody.
fn options() -> Options {
    let no_sandbox = std::env::var("STARLING_TEST_NO_SANDBOX").is_ok();
    Options {
        binary: std::env::var("STARLING_TEST_BROWSER").unwrap_or_default(),
        no_sandbox,
        // Mirrors what the service does with these two options, so that running
        // these tests unsandboxed exercises the configuration a locked-down pod
        // actually runs rather than a halfway one that exists nowhere.
        jitless: no_sandbox,
        ..Options::default()
    }
}

/// A browser behind the guard, or the reason there is not one.
async fn browser() -> Browser {
    launched(options()).await
}

/// The same, with the options a particular test needs.
async fn launched(options: Options) -> Browser {
    let guarded = Guarded::bind(64).await.expect("a loopback port");
    let address = guarded.address();
    drop(tokio::spawn(guarded.serve()));
    Browser::launch(address, &options, 2)
        .await
        .expect("a browser: install chromium, or set STARLING_TEST_BROWSER")
}

/// What one line of script saw, rendered into the document's title.
///
/// A `data:` URL, so this asks the browser about itself without involving a
/// host or the network: the question is what the *renderer* was given, and a
/// page fetched to ask it would only add a way for the answer to be wrong.
async fn asked_of_the_page(browser: &Browser, expression: &str) -> String {
    let url = format!(
        "data:text/html,<html><head><script>document.title=String({expression})</script></head><body></body></html>"
    );
    let page = browser
        .render(&url, Duration::from_secs(20))
        .await
        .expect("a render");
    let html = page.html;
    let start = html.find("<title>").map(|at| at + "<title>".len());
    let end = html.find("</title>");
    match (start, end) {
        (Some(start), Some(end)) if end >= start => {
            html.get(start..end).unwrap_or_default().trim().to_owned()
        }
        _ => String::new(),
    }
}

#[tokio::test]
#[ignore = "needs a browser"]
async fn the_hardening_flags_reach_the_renderer() {
    // A flag Chrome does not recognise is *ignored*, silently, which is the
    // failure mode this test exists for: a deployment that dropped the sandbox
    // in exchange for `--jitless` should not discover years later that the
    // exchange never happened. So this asks the renderer what it actually has.
    //
    // `WebAssembly` is the observable: V8 will not expose it without a JIT, so
    // its absence is the JIT's absence, and it is one property rather than an
    // inference from timing.
    let hardened = launched(Options {
        no_sandbox: true,
        jitless: true,
        ..options()
    })
    .await;
    assert_eq!(
        asked_of_the_page(&hardened, "typeof WebAssembly").await,
        "undefined",
        "the JIT is still there: --js-flags=--jitless did not reach V8"
    );
    assert_eq!(
        asked_of_the_page(
            &hardened,
            "!!document.createElement('canvas').getContext('webgl')"
        )
        .await,
        "false",
        "WebGL is still there: --disable-3d-apis did not reach the renderer"
    );

    // ...and that the same browser without the hardening does have them, so a
    // passing test above cannot be a browser that never had either.
    let ordinary = launched(Options {
        no_sandbox: true,
        jitless: false,
        ..options()
    })
    .await;
    assert_eq!(
        asked_of_the_page(&ordinary, "typeof WebAssembly").await,
        "object",
        "a browser with its JIT should expose WebAssembly; if this fails the          observable has changed and the assertion above proves nothing"
    );
}

#[tokio::test]
#[ignore = "needs a browser and the internet"]
async fn a_page_behind_a_bot_wall_renders() {
    // The case the whole service exists for. Measured 2026-09-08: idealo
    // answers *every* HTTP client with 403 - Discordbot, Googlebot,
    // TelegramBot, a full Chrome header set over HTTP/2, all of them - and
    // answers a browser with the page. Telegram gets a card because Akamai
    // verifies its crawler by IP, which a self-hosted server can never be.
    let browser = browser().await;
    let page = browser
        .render(
            "https://www.idealo.de/preisvergleich/OffersOfProduct/5972779_-860-evo-1tb-2-5-samsung.html",
            Duration::from_secs(25),
        )
        .await
        .expect("a render");

    assert_eq!(page.status, 200, "the browser was refused as a bot");
    let head = page.html.to_lowercase();
    let head = head.split("</head").next().unwrap_or_default();
    // idealo publishes no `og:title`: the card is built from the title tag, the
    // meta description and `og:image`, which is exactly what Telegram draws.
    assert!(head.contains("<title"), "no title in the rendered head");
    assert!(head.contains("og:image"), "no picture in the rendered head");
    assert!(
        head.contains("name=\"description\""),
        "no description in the rendered head"
    );
}

#[tokio::test]
#[ignore = "needs a browser and the internet"]
async fn an_ordinary_page_renders_quickly() {
    // The other half: the browser must not be slow on a page that is not
    // defended, or the ladder's last rung would be unusable even where it
    // works. Half a second here against ~2.5s for the bot-walled page.
    let browser = browser().await;
    let started = std::time::Instant::now();
    let page = browser
        .render("https://example.org/", Duration::from_secs(25))
        .await
        .expect("a render");

    assert_eq!(page.status, 200);
    assert!(page.html.to_lowercase().contains("<title"));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "an undefended page took {:?}, which means the waiter is not ending early",
        started.elapsed()
    );
}

#[tokio::test]
#[ignore = "needs a browser"]
async fn the_guard_is_the_only_way_out_of_the_browser() {
    // Not a page-content test: this asserts that a render of an address inside
    // the deployment fails at the proxy. The browser is pointed at the guard
    // with `--proxy-bypass-list=<-loopback>`, so even localhost goes through
    // it, and the guard refuses every private range.
    //
    // The service refuses this URL before it ever reaches a browser too; this
    // is the layer *below* that, which is the one that has to hold when the
    // page itself asks for the address.
    let browser = browser().await;
    let rendered = browser
        .render("http://127.0.0.1:1/", Duration::from_secs(10))
        .await;

    match rendered {
        // What the browser reports for a proxy that refused the tunnel.
        Err(error) => {
            let said = error.to_string();
            assert!(
                said.contains("would not load") || said.contains("took too long"),
                "the guard must refuse it: {said}"
            );
        }
        Ok(page) => assert_ne!(
            page.status, 200,
            "an address inside the deployment answered a render"
        ),
    }
}
