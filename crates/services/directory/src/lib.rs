//! `directory`: what this server tells the outside world about itself.
//!
//! The replacement for murmur's `Register.cpp`: an hourly announcement to the
//! public Mumble server list, so a server that wants to be found can be.
//!
//! **It has no client-facing message type and no gRPC surface.** Nothing calls
//! it; it calls out. That makes it internal by construction rather than by
//! convention, the same property `session-view` has for the opposite reason.
//!
//! # Why this is its own service and not part of `server-config`
//!
//! `server-config` is **essential**, a cold start with it down rejects logins.
//! This is a scheduled outbound HTTPS client with a TLS trust store and an XML
//! payload, and none of that belongs in the process the handshake cannot proceed
//! without. Being listed publicly is the definition of **optional**: nobody
//! notices for an hour, which is the interval anyway.
//!
//! # What it needs, and where each piece comes from
//!
//! | Fact | Source | Why not somewhere else |
//! |---|---|---|
//! | name, secret, url, location | `server-config` | murmur lets an operator change them live |
//! | user count | `session-view` | with two gateways, one gateway's view is a fraction |
//! | channel count | `metadata` | the sole writer of channel state |
//! | certificate digest | the gateway's own cert file | it must be the fingerprint clients pin |
//! | port | the deployment TOML | it needs a restart anyway |

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use starling_proto_fancy::common::Scope;
use starling_proto_fancy::metadata::TreeRequest;
use starling_proto_fancy::metadata::metadata_client::MetadataClient;
use starling_proto_fancy::serverconfig::GetRequest;
use starling_proto_fancy::serverconfig::server_config_client::ServerConfigClient;
use starling_proto_fancy::sessionview::SubscribeRequest;
use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;
use starling_runtime::serve::{Serve, ServiceContext, ServiceError};
use tonic::service::Routes;

pub mod listing;
pub mod registrar;

pub use listing::{Listing, PUBLIC_LIST, Unlisted, digest, eligible};
pub use registrar::{DEFAULT_TRUST_STORE, PublicList, RegisterError, Registrar};

/// The earliest a first announcement is sent, after start-up.
///
/// murmur waits 60-180 seconds. The delay is not politeness: a server that
/// announces the instant it boots announces a user count of zero and a channel
/// tree that has not loaded, and the jitter stops a thousand servers restarting
/// after a package upgrade from arriving at the list together.
const FIRST_DELAY: Duration = Duration::from_mins(1);
/// How much random delay is added to the first announcement.
const FIRST_JITTER: u64 = 120;
/// The interval between announcements once the first has gone out.
const INTERVAL: Duration = Duration::from_hours(1);
/// How much random delay is added to each subsequent announcement.
const INTERVAL_JITTER: u64 = 300;

/// The service.
#[derive(Debug)]
pub struct DirectoryService {
    /// Where the certificate whose fingerprint is announced lives.
    cert: PathBuf,
    /// The private key that authenticates the announcement.
    key: PathBuf,
    /// The PEM bundle the public list's own certificate is verified against.
    trust_store: PathBuf,
    /// The control port clients are told to connect to.
    port: u16,
    /// Which server instance this announces.
    scope: u32,
}

impl DirectoryService {
    /// The delay before the first announcement.
    fn first_delay() -> Duration {
        FIRST_DELAY + jitter(FIRST_JITTER)
    }

    /// The delay between announcements.
    fn interval() -> Duration {
        INTERVAL + jitter(INTERVAL_JITTER)
    }

    /// Gather everything and submit one announcement.
    ///
    /// Never returns an error: being unlisted for an hour is not a reason to
    /// stop the service, and the next tick is a fresh attempt. Everything that
    /// prevented it is logged, because "why is my server not on the list" is a
    /// question with a dozen answers and no other way to tell them apart.
    async fn announce(&self, ctx: &ServiceContext) {
        let Some(config) = self.settings(ctx).await else {
            tracing::debug!("server-config is unreachable; not announcing this round");
            return;
        };

        if let Err(reason) = eligible(&config) {
            // Info, not warn: an operator who never asked to be listed is not
            // looking at a problem. It is said once per interval rather than
            // never, because the alternative is silence about a thing that was
            // configured and did not happen.
            tracing::info!(%reason, "not announcing to the public server list");
            return;
        }

        let Some(identity) = self.identity() else {
            tracing::info!(
                cert = %self.cert.display(),
                reason = %Unlisted::NoCertificate,
                "not announcing to the public server list"
            );
            return;
        };
        // Before the identity is consumed by the client that authenticates with
        // it: this is the fingerprint clients pin, and the list keys the entry
        // by it.
        let digest = identity
            .certs
            .first()
            .map(|leaf| digest(leaf.as_ref()))
            .unwrap_or_default();

        let listing = listing::compose(
            &config,
            self.port,
            digest,
            self.users(ctx).await,
            self.channels(ctx).await,
        );

        // Rebuilt per announcement rather than held: it reads the certificate
        // and the trust store, so a rotated certificate is picked up without a
        // restart. Once an hour, this costs nothing.
        let registrar = match PublicList::new(PUBLIC_LIST, identity, &self.trust_store) {
            Ok(registrar) => registrar,
            Err(error) => {
                tracing::warn!(%error, "cannot build the public-list client");
                return;
            }
        };

        Self::submit(&registrar, &listing).await;
    }

    /// Submit one composed document and report what happened.
    ///
    /// Takes the registrar rather than building one so the document that goes
    /// out can be asserted on without a network.
    async fn submit(registrar: &impl Registrar, listing: &Listing) {
        // `to_xml`, not `to_xml_redacted`: the real secret is what authenticates
        // the update. Sending the redacted form would produce a listing that
        // silently stops being updatable.
        if let Err(error) = registrar.submit(listing.to_xml()).await {
            // The document is logged because it is the only way to see what the
            // list objected to, and redacted because it carries that secret.
            tracing::warn!(
                %error,
                document = %listing.to_xml_redacted(),
                "the public-list announcement failed"
            );
        }
    }

    /// The operational settings, or nothing if they cannot be read.
    ///
    /// Deliberately not defaulted: defaults would make an unconfigured server
    /// *eligible* only by accident, and the one thing worse than failing to
    /// announce is announcing something nobody chose.
    async fn settings(
        &self,
        ctx: &ServiceContext,
    ) -> Option<starling_proto_fancy::serverconfig::Snapshot> {
        let channel = ctx.resolver.channel("server-config").ok()?;
        ServerConfigClient::new(channel)
            .get(GetRequest {
                scope: Some(self.scope()),
            })
            .await
            .ok()
            .map(tonic::Response::into_inner)
    }

    /// How many users are connected, server-wide.
    async fn users(&self, ctx: &ServiceContext) -> u32 {
        let Ok(channel) = ctx.resolver.channel("session-view") else {
            return 0;
        };
        let sessions = SessionViewClient::new(channel)
            .list(SubscribeRequest {
                scope: Some(self.scope()),
                subscriber: Self::NAME.to_owned(),
            })
            .await;
        sessions.map_or(0, |sessions| {
            u32::try_from(sessions.into_inner().sessions.len()).unwrap_or(u32::MAX)
        })
    }

    /// How many channels exist.
    async fn channels(&self, ctx: &ServiceContext) -> u32 {
        let Ok(channel) = ctx.resolver.channel("metadata") else {
            return 0;
        };
        let tree = MetadataClient::new(channel)
            .max_decoding_message_size(ctx.resolver.max_tree_message())
            .get_tree(TreeRequest {
                scope: Some(self.scope()),
            })
            .await;
        tree.map_or(0, |tree| {
            u32::try_from(tree.into_inner().channels.len()).unwrap_or(u32::MAX)
        })
    }

    /// The certificate and key this server is identified by, if they exist yet.
    ///
    /// Loaded, never generated. On a first boot the gateway writes the pair, and
    /// generating a second one here would either race it or announce a
    /// fingerprint no client will ever be shown.
    fn identity(&self) -> Option<starling_crypto::identity::TlsIdentity> {
        let files = starling_crypto::identity::PemFiles::new(&self.cert, &self.key);
        if !starling_crypto::identity::CertificateSource::available(&files) {
            return None;
        }
        match starling_crypto::identity::CertificateSource::load(&files) {
            Ok(identity) => Some(identity),
            Err(error) => {
                tracing::warn!(%error, cert = %self.cert.display(), "cannot read the server certificate");
                None
            }
        }
    }

    /// This service's server instance, as a request scope.
    const fn scope(&self) -> Scope {
        Scope {
            instance: self.scope,
        }
    }
}

/// A random extra delay of up to `seconds`.
fn jitter(seconds: u64) -> Duration {
    use rand::RngExt as _;
    Duration::from_secs(rand::rng().random_range(0..=seconds))
}

impl Serve for DirectoryService {
    const NAME: &'static str = "directory";

    /// Nothing calls this service; it calls out. An endpoint nobody dials would
    /// be one more thing to misconfigure, which is the gateway's reasoning for
    /// the same choice.
    const SERVES_GRPC: bool = false;

    async fn build(ctx: ServiceContext) -> Result<Arc<Self>, ServiceError> {
        let service = ctx.service();
        let data_dir = &ctx.config.runtime.data_dir;
        // The gateway's certificate, by exactly the same rule the gateway uses
        // to find it, the announced fingerprint has to be the one clients are
        // shown, so a second convention here would be a second answer.
        let cert = ctx
            .config
            .gateway
            .tls
            .cert
            .clone()
            .unwrap_or_else(|| data_dir.join("cert.pem"));
        let key = ctx
            .config
            .gateway
            .tls
            .key
            .clone()
            .unwrap_or_else(|| data_dir.join("key.pem"));

        Ok(Arc::new(Self {
            cert,
            key,
            trust_store: service
                .options
                .get("trust_store")
                .map_or_else(|| PathBuf::from(DEFAULT_TRUST_STORE), PathBuf::from),
            port: ctx
                .config
                .instances
                .first()
                .map_or(64738, |server| server.port),
            scope: ctx.instances().first().copied().unwrap_or(1),
        }))
    }

    fn routes(self: Arc<Self>) -> Routes {
        Routes::default()
    }

    async fn run(self: Arc<Self>, ctx: ServiceContext) -> Result<(), ServiceError> {
        let mut delay = Self::first_delay();
        tracing::info!(
            first_announcement_in_s = delay.as_secs(),
            "the public-list announcer is running"
        );
        loop {
            tokio::select! {
                _ = ctx.shutdown.wait() => break,
                () = tokio::time::sleep(delay) => {
                    self.announce(&ctx).await;
                    delay = Self::interval();
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registrar::tests::Recording;

    #[tokio::test]
    async fn the_document_that_goes_out_carries_the_real_secret() {
        // The bug worth a test: `to_xml_redacted` exists for logging, and using
        // it by mistake here produces a registration the list accepts once and
        // can never authenticate an update against again. Nothing on this side
        // would show it, the POST succeeds.
        let listing = Listing {
            name: "Starling".to_owned(),
            password: "shared-secret".to_owned(),
            port: 64738,
            url: "https://example.org".to_owned(),
            ..Listing::default()
        };
        let registrar = Recording::default();

        DirectoryService::submit(&registrar, &listing).await;

        let documents = registrar.documents();
        assert_eq!(documents.len(), 1);
        let document = documents.first().expect("one document");
        assert!(
            document.contains("<password>shared-secret</password>"),
            "the announcement must carry the real registry password"
        );
        assert!(!document.contains("[redacted]"));
    }

    #[test]
    fn the_first_announcement_waits_between_one_and_three_minutes() {
        // A server that announces the instant it boots reports zero users and an
        // empty channel tree, which is what the list then shows for an hour.
        for _ in 0..200 {
            let delay = DirectoryService::first_delay();
            assert!(delay >= Duration::from_secs(60), "{delay:?} is too soon");
            assert!(delay <= Duration::from_secs(180), "{delay:?} is too late");
        }
    }

    #[test]
    fn the_interval_is_hourly_and_never_exactly_hourly() {
        // Jitter is the point: without it every server that restarted together
        // stays synchronised and hits the list in the same second every hour.
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            let delay = DirectoryService::interval();
            assert!(delay >= Duration::from_secs(3_600));
            assert!(delay <= Duration::from_secs(3_900));
            let _ = seen.insert(delay.as_secs());
        }
        assert!(seen.len() > 1, "the interval is not jittered at all");
    }
}
