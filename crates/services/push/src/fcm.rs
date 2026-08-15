//! Delivery through Firebase Cloud Messaging, HTTP v1.
//!
//! murmur has this as a shared library it `dlopen`s at start-up, behind a C ABI
//! (`mumble_push_api.h`), because a server that must build without a push
//! provider cannot link one in. Starling has no such constraint: a service is
//! already an optional unit an operator can switch off, and one that is
//! configured with no credentials sends nothing. So the module boundary is gone
//! and the provider is a [`Sender`] -- which keeps the seam that mattered, since
//! the fan-out decisions are then testable without anybody's network.
//!
//! What is ported unchanged is the part that is Google's and not ours: the
//! service-account assertion (in [`crate::oauth`]), the hour-long access token
//! cached with a margin, the clock-skew probe, and the shape of the `messages:send`
//! body.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::oauth::{
    ASSERTION_LIFETIME, CredentialError, ServiceAccount, TOKEN_HOST, TOKEN_PATH, exchange_body,
};

/// Where notifications are posted.
const FCM_HOST: &str = "fcm.googleapis.com";

/// How long before expiry a token is replaced.
///
/// A token that expires between the check and the send is a notification lost
/// for no reason; five minutes is murmur's margin and is generous.
const REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);

/// What a token is assumed to be worth when the answer does not say.
///
/// Google's tokens last an hour and the answer does say, so this is the
/// fallback for an answer that has changed shape, held short of the assertion's
/// own hour on purpose.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(55 * 60);

/// How long one exchange or one send may take.
///
/// Push is optional and fire-and-forget; a request to Google that hangs must
/// not hold a task forever.
const TIMEOUT: Duration = Duration::from_secs(15);

/// What a notification is about.
///
/// murmur's `MumblePushCategory`, kept whole: it travels to the device in the
/// data payload, where a client decides how to present it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Category {
    /// Somebody said something in a channel.
    #[default]
    TextMessage,
    /// Somebody said something *to you*.
    Mention,
    /// Somebody reacted to a message.
    Reaction,
    /// Somebody joined or left.
    Channel,
}

impl Category {
    /// The category a `Notification`'s `data["category"]` names, if it names one.
    ///
    /// Unknown names read as a text message rather than as nothing: the caller
    /// asked for a notification, and dropping it over a spelling would be a
    /// silence nobody can debug.
    #[must_use]
    pub fn parse(name: &str) -> Self {
        match name {
            "mention" => Self::Mention,
            "reaction" => Self::Reaction,
            "channel" => Self::Channel,
            _ => Self::TextMessage,
        }
    }

    /// The number murmur's clients already read out of the data payload.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::TextMessage => 0,
            Self::Mention => 1,
            Self::Reaction => 2,
            Self::Channel => 3,
        }
    }

    /// Whether this one wakes a sleeping device.
    ///
    /// Only a mention does. High priority is a budget Google enforces per app,
    /// so spending it on every channel message is how an app stops being
    /// allowed to wake anything.
    #[must_use]
    pub const fn high_priority(self) -> bool {
        matches!(self, Self::Mention)
    }
}

/// Who a notification is for.
///
/// murmur encodes both in one string, `"/topics/<name>"` against a bare token,
/// because the C ABI has one field for it. Nothing here has to: a topic and a
/// device token are different keys in the request body, and this is the type
/// that says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// One device, by its registration token.
    Token(String),
    /// Everybody subscribed to a topic, by its bare name.
    Topic(String),
}

/// One notification, as far as this crate is concerned.
#[derive(Debug, Clone)]
pub struct Message {
    /// Who it is for.
    pub target: Target,
    /// The line a device shows in bold. Usually who is speaking.
    pub title: String,
    /// The line under it. Usually what they said, already truncated.
    pub body: String,
    /// What it is about.
    pub category: Category,
    /// Which virtual server, so a client on several can tell them apart.
    pub server: u32,
    /// Which channel, for the same reason and for the tap-through.
    pub channel: u32,
    /// Anything else the caller wants the device to have.
    pub data: std::collections::BTreeMap<String, String>,
}

impl Message {
    /// The `messages:send` request body.
    ///
    /// Data values are strings because FCM's are: the field is
    /// `map<string, string>` on the wire, whatever the caller was thinking of.
    #[must_use]
    pub fn payload(&self) -> serde_json::Value {
        let mut data = serde_json::Map::new();
        // The caller's entries go in first, so the three below cannot be
        // overwritten by a `data` map that happens to use the same keys.
        for (key, value) in &self.data {
            let _ = data.insert(key.clone(), serde_json::Value::String(value.clone()));
        }
        let _ = data.insert("server_id".to_owned(), self.server.to_string().into());
        let _ = data.insert("channel_id".to_owned(), self.channel.to_string().into());
        let _ = data.insert(
            "category".to_owned(),
            self.category.code().to_string().into(),
        );

        let mut message = serde_json::Map::new();
        let _ = match &self.target {
            Target::Token(token) => message.insert("token".to_owned(), token.clone().into()),
            Target::Topic(topic) => message.insert("topic".to_owned(), topic.clone().into()),
        };
        let _ = message.insert(
            "notification".to_owned(),
            serde_json::json!({ "title": self.title, "body": self.body }),
        );
        let _ = message.insert("data".to_owned(), data.into());
        if self.category.high_priority() {
            let _ = message.insert(
                "android".to_owned(),
                serde_json::json!({ "priority": "high" }),
            );
        }
        serde_json::json!({ "message": message })
    }
}

/// Why a notification did not get to the provider.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// The credentials cannot produce an assertion.
    #[error(transparent)]
    Credentials(#[from] CredentialError),
    /// The network, or TLS, or the shape of a URL.
    #[error("reaching {host}: {reason}")]
    Unreachable {
        /// Which host would not talk to us.
        host: &'static str,
        /// What went wrong.
        reason: String,
    },
    /// It took longer than [`TIMEOUT`].
    #[error("{host} did not answer within {}s", TIMEOUT.as_secs())]
    TimedOut {
        /// Which host went quiet.
        host: &'static str,
    },
    /// Google answered, and said no.
    ///
    /// The body is kept because it is the only explanation there is; an
    /// `UNREGISTERED` for a stale token and a refused key are the same status
    /// otherwise.
    #[error("{host} refused the request: {status} {body}")]
    Refused {
        /// Which host refused.
        host: &'static str,
        /// The status it answered with.
        status: StatusCode,
        /// What it said, truncated to something a log line can hold.
        body: String,
    },
}

/// Somewhere a notification can be delivered.
///
/// A trait for the reason [`crate::PushService`]'s fan-out is worth testing and
/// Google's availability is not: the tests deliver into a recorder.
#[async_trait::async_trait]
pub trait Sender: std::fmt::Debug + Send + Sync + 'static {
    /// Deliver one notification.
    ///
    /// # Errors
    ///
    /// [`SendError`] when it did not reach the provider, or was refused.
    async fn send(&self, message: Message) -> Result<(), SendError>;
}

/// The cached authentication, and the clock correction it needs.
#[derive(Debug, Default)]
struct Auth {
    /// The bearer token, while it is worth using.
    token: Option<CachedToken>,
    /// Seconds to add to the local clock to get Google's, once probed.
    ///
    /// `None` until the first exchange. See [`Fcm::clock_offset`] for why a
    /// server's own clock is not trusted to sign a time-limited assertion.
    offset: Option<i64>,
}

/// A bearer token and when it stops being one.
#[derive(Debug, Clone)]
struct CachedToken {
    /// The token itself.
    value: String,
    /// When it expires, on the local monotonic clock.
    expires: Instant,
}

/// Firebase Cloud Messaging.
#[derive(Debug)]
pub struct Fcm {
    /// The Firebase project notifications are sent under.
    project: String,
    /// The key that buys tokens.
    account: ServiceAccount,
    /// Roots for the two Google hosts. Mozilla's bundle, so this behaves the
    /// same in a container, in CI and on a laptop.
    tls: Arc<ClientConfig>,
    /// One lock over the token and the clock offset, which also makes a
    /// refresh single-flight: a burst of notifications after an idle hour
    /// exchanges one assertion, not one per message.
    auth: tokio::sync::Mutex<Auth>,
}

impl Fcm {
    /// A sender for `project`, authenticating as `account`.
    #[must_use]
    pub fn new(project: String, account: ServiceAccount) -> Self {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        // The provider is named rather than taken from the process default:
        // `ClientConfig::builder()` panics when none is installed, and whether
        // one is depends on which other component started first.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_or_else(
                |_| unreachable!("ring supports the default protocol versions"),
                |builder| builder.with_root_certificates(roots).with_no_client_auth(),
            );
        Self {
            project,
            account,
            tls: Arc::new(tls),
            auth: tokio::sync::Mutex::new(Auth::default()),
        }
    }

    /// A usable bearer token, refreshing when the cached one is nearly out.
    async fn access_token(&self) -> Result<String, SendError> {
        let mut auth = self.auth.lock().await;
        if let Some(token) = auth
            .token
            .as_ref()
            .filter(|token| Instant::now() + REFRESH_MARGIN < token.expires)
        {
            return Ok(token.value.clone());
        }

        // Probed once, on the first exchange, and kept: an assertion is signed
        // over an `iat`/`exp` window, so a server whose clock is a few minutes
        // off has every assertion rejected as expired or not-yet-valid, with an
        // error message about the assertion rather than about the clock. This
        // is murmur's probe, for murmur's reason.
        if auth.offset.is_none() {
            auth.offset = Some(self.clock_offset().await);
        }
        let offset = auth.offset.unwrap_or(0);
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
        .unwrap_or(i64::MAX);
        let issued_at = u64::try_from(now.saturating_add(offset)).unwrap_or_default();

        let assertion = self.account.assertion(issued_at)?;
        let answer = self
            .post(
                TOKEN_HOST,
                TOKEN_PATH,
                "application/x-www-form-urlencoded",
                None,
                exchange_body(&assertion),
            )
            .await?;
        if !answer.status.is_success() {
            return Err(SendError::Refused {
                host: TOKEN_HOST,
                status: answer.status,
                body: answer.body,
            });
        }

        let document: serde_json::Value = serde_json::from_str(&answer.body).unwrap_or_default();
        let value = document
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| SendError::Refused {
                host: TOKEN_HOST,
                status: answer.status,
                body: "no access_token in the answer".to_owned(),
            })?
            .to_owned();
        // `expires_in` when it is there, rather than murmur's fixed 55 minutes:
        // the answer is authoritative about its own token, and a hard-coded
        // lifetime is a guess that silently starts being wrong.
        let lifetime = document
            .get("expires_in")
            .and_then(serde_json::Value::as_u64)
            .map_or(DEFAULT_LIFETIME, Duration::from_secs)
            .min(ASSERTION_LIFETIME);
        auth.token = Some(CachedToken {
            value: value.clone(),
            expires: Instant::now() + lifetime,
        });
        tracing::debug!(
            lifetime_s = lifetime.as_secs(),
            "obtained an FCM access token"
        );
        Ok(value)
    }

    /// Seconds to add to the local clock to match Google's.
    ///
    /// An empty POST to the token endpoint, which is refused, and whose refusal
    /// carries a `Date` header. Zero when it cannot be worked out, which is the
    /// same behaviour as never having probed.
    async fn clock_offset(&self) -> i64 {
        let answer = self
            .post(
                TOKEN_HOST,
                TOKEN_PATH,
                "application/x-www-form-urlencoded",
                None,
                String::new(),
            )
            .await;
        let Ok(remote) = answer.as_ref().map(|answer| answer.date) else {
            tracing::debug!("could not probe Google's clock; assuming the local one is right");
            return 0;
        };
        let Some(remote) = remote.and_then(|date| date.duration_since(UNIX_EPOCH).ok()) else {
            return 0;
        };
        let local = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let offset = i64::try_from(remote.as_secs()).unwrap_or(0)
            - i64::try_from(local.as_secs()).unwrap_or(0);
        if offset.abs() > 5 {
            // Worth an operator's attention: everything else on this host that
            // signs or verifies a timestamp is off by the same amount, and push
            // is merely the thing that noticed.
            tracing::warn!(
                offset_s = offset,
                "this host's clock disagrees with Google's; signing against theirs"
            );
        }
        offset
    }

    /// One HTTPS POST, with the response read whole.
    async fn post(
        &self,
        host: &'static str,
        path: &str,
        content_type: &str,
        bearer: Option<&str>,
        body: String,
    ) -> Result<Answer, SendError> {
        let exchange = async {
            let name = ServerName::try_from(host).map_err(|error| SendError::Unreachable {
                host,
                reason: error.to_string(),
            })?;
            let stream =
                TcpStream::connect((host, 443))
                    .await
                    .map_err(|error| SendError::Unreachable {
                        host,
                        reason: error.to_string(),
                    })?;
            let tls = TlsConnector::from(Arc::clone(&self.tls))
                .connect(name, stream)
                .await
                .map_err(|error| SendError::Unreachable {
                    host,
                    reason: error.to_string(),
                })?;

            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .map_err(|error| SendError::Unreachable {
                    host,
                    reason: error.to_string(),
                })?;
            // The connection has to be driven for the request to make progress,
            // and it ends on its own when the response is done.
            drop(tokio::spawn(async move {
                if let Err(error) = connection.await {
                    tracing::debug!(%error, host, "the connection closed");
                }
            }));

            let mut request = Request::builder()
                .method("POST")
                .uri(path)
                .header("host", host)
                .header("content-type", content_type)
                .header(
                    "user-agent",
                    concat!("Starling/", env!("CARGO_PKG_VERSION")),
                );
            if let Some(bearer) = bearer {
                request = request.header("authorization", format!("Bearer {bearer}"));
            }
            let request = request
                .body(Full::new(Bytes::from(body)))
                .map_err(|error| SendError::Unreachable {
                    host,
                    reason: error.to_string(),
                })?;

            let response =
                sender
                    .send_request(request)
                    .await
                    .map_err(|error| SendError::Unreachable {
                        host,
                        reason: error.to_string(),
                    })?;
            let status = response.status();
            let date = response
                .headers()
                .get("date")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| httpdate::parse_http_date(value).ok());
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(|error| SendError::Unreachable {
                    host,
                    reason: error.to_string(),
                })?
                .to_bytes();
            // Truncated here rather than at every log site: these bodies end up
            // in error messages, and Google's error documents are long.
            let mut body = String::from_utf8_lossy(&body).trim().to_owned();
            body.truncate(500);
            Ok(Answer { status, date, body })
        };

        tokio::time::timeout(TIMEOUT, exchange)
            .await
            .unwrap_or(Err(SendError::TimedOut { host }))
    }
}

/// What a POST came back with.
#[derive(Debug)]
struct Answer {
    /// The status line.
    status: StatusCode,
    /// The `Date` header, which is the clock this is checked against.
    date: Option<SystemTime>,
    /// The body, truncated.
    body: String,
}

#[async_trait::async_trait]
impl Sender for Fcm {
    async fn send(&self, message: Message) -> Result<(), SendError> {
        let token = self.access_token().await?;
        let answer = self
            .post(
                FCM_HOST,
                &format!("/v1/projects/{}/messages:send", self.project),
                "application/json",
                Some(&token),
                message.payload().to_string(),
            )
            .await?;
        if !answer.status.is_success() {
            return Err(SendError::Refused {
                host: FCM_HOST,
                status: answer.status,
                body: answer.body,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(target: Target) -> Message {
        Message {
            target,
            title: "alice".to_owned(),
            body: "are you there?".to_owned(),
            category: Category::TextMessage,
            server: 1,
            channel: 7,
            data: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn a_device_and_a_topic_are_different_keys_and_not_a_prefixed_string() {
        // murmur passes `"/topics/<name>"` in the field a token goes in and the
        // module splits it apart again; the whole round trip exists because a C
        // struct had one pointer for both.
        let device = message(Target::Token("device-token".to_owned())).payload();
        assert_eq!(device["message"]["token"], "device-token");
        assert!(device["message"].get("topic").is_none());

        let topic = message(Target::Topic("mumble_server1_channel7".to_owned())).payload();
        assert_eq!(topic["message"]["topic"], "mumble_server1_channel7");
        assert!(topic["message"].get("token").is_none());
    }

    #[test]
    fn the_data_payload_carries_where_it_came_from_as_strings() {
        let payload = message(Target::Token("t".to_owned())).payload();
        let data = &payload["message"]["data"];
        // Strings, because FCM's data map is `map<string, string>` and a number
        // here is a request Google rejects whole.
        assert_eq!(data["server_id"], "1");
        assert_eq!(data["channel_id"], "7");
        assert_eq!(data["category"], "0");
        assert_eq!(payload["message"]["notification"]["title"], "alice");
        assert_eq!(payload["message"]["notification"]["body"], "are you there?");
    }

    #[test]
    fn a_caller_cannot_overwrite_the_routing_keys_with_its_own_data() {
        // Otherwise a caller passing `channel_id` in `data` would send a device
        // to the wrong room on tap, and nothing would say so.
        let mut message = message(Target::Token("t".to_owned()));
        let _ = message
            .data
            .insert("channel_id".to_owned(), "999".to_owned());
        let _ = message.data.insert("thread".to_owned(), "42".to_owned());
        let data = &message.payload()["message"]["data"];
        assert_eq!(data["channel_id"], "7");
        assert_eq!(data["thread"], "42", "and the rest is passed through");
    }

    #[test]
    fn only_a_mention_asks_to_wake_the_device() {
        // High priority is a per-app budget Google enforces. Spending it on
        // every channel message is how an app loses the ability to wake
        // anything, mentions included.
        let mut message = message(Target::Token("t".to_owned()));
        assert!(message.payload()["message"].get("android").is_none());

        message.category = Category::Mention;
        assert_eq!(message.payload()["message"]["android"]["priority"], "high");
        assert_eq!(message.payload()["message"]["data"]["category"], "1");
    }

    #[test]
    fn an_unknown_category_reads_as_a_message_rather_than_as_nothing() {
        assert_eq!(Category::parse("mention"), Category::Mention);
        assert_eq!(Category::parse("reaction"), Category::Reaction);
        assert_eq!(Category::parse("channel"), Category::Channel);
        assert_eq!(
            Category::parse("whatever-a-newer-caller-sends"),
            Category::TextMessage
        );
    }
}
