//! Who may be told about a channel at all.
//!
//! A notification carries a channel's name and a line of what was said in it,
//! to a person who is not connected and therefore not standing anywhere. The
//! fork gates that on its own permission bit, `SubscribePush`, computed per
//! channel while the device registers (`Server::computeAllowedPushChannels`).
//! Without the gate, registering a device would be a way to read the parts of
//! a server you cannot see.
//!
//! Ported with the check moved from registration time to notification time.
//! The fork stores the allowed set on the registration and refreshes it while
//! the user is connected, so an ACL changed while they are away is an ACL that
//! does not apply to them; asking once per notification is always current, and
//! asks about one channel rather than all of them.
//!
//! # Why this is a trait
//!
//! The same reason [`crate::fcm::Sender`] is: it is the seam between "who
//! should be notified", which is worth testing, and a running `permissions`
//! service, which is not something a unit test should need.

use starling_proto_fancy::common::Scope;
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::permissions::permissions_client::PermissionsClient;
use starling_proto_fancy::permissions::{CheckRequest, Subject};
use starling_runtime::channel::Resolver;
use starling_runtime::permit::Permit;

/// Whether somebody may be told what happens in a channel.
///
/// Two questions, because push answers for two kinds of recipient: a person who
/// is *away*, identified by the account their device is registered under, and a
/// session that is *here*, asking for live delivery. Both ask for the same
/// permission bit; only the identity differs, and with it which check is safe.
#[async_trait::async_trait]
pub trait Audience: std::fmt::Debug + Send + Sync + 'static {
    /// Whether `account` may be notified about `channel`.
    ///
    /// Implementations must **deny** on any failure. A push service that
    /// notifies everybody whenever `permissions` is down would make taking a
    /// service down a way to read a private channel.
    async fn may_receive(&self, scope: u32, account: u64, channel: u32) -> bool;

    /// Whether the client on `session` may be sent `channel`'s messages live.
    ///
    /// Denies on any failure, for the same reason.
    async fn session_may_receive(&self, scope: u32, session: u32, channel: u32) -> bool;
}

/// The real answer: ask `permissions`.
#[derive(Debug, Clone)]
pub struct Permitted {
    /// How `permissions` is reached for the account check, which this file
    /// makes itself.
    resolver: Resolver,
    /// The session check, which the runtime already owns and fails closed.
    permit: Permit,
}

impl Permitted {
    /// A check that asks through `resolver`.
    #[must_use]
    pub fn new(resolver: Resolver) -> Self {
        Self {
            permit: Permit::new(resolver.clone()),
            resolver,
        }
    }
}

#[async_trait::async_trait]
impl Audience for Permitted {
    async fn may_receive(&self, scope: u32, account: u64, channel: u32) -> bool {
        let Ok(transport) = self.resolver.channel("permissions") else {
            tracing::warn!(
                account,
                channel,
                "permissions is unreachable; not notifying"
            );
            return false;
        };
        // `Check` and not `CheckSession`, which is the one place in the server
        // that legitimately needs it: the subject is a person with no session,
        // and resolving one would find nothing. What makes it safe here is that
        // the identity is not a caller's claim -- it comes from this service's
        // own registration table, filed under the account `session-view` named
        // when the device registered.
        let answer = PermissionsClient::new(transport)
            .check(CheckRequest {
                scope: Some(Scope { instance: scope }),
                subject: Some(Subject {
                    // Nobody: they are not connected. Deliberately not the
                    // channel being asked about, which would make every `@in`
                    // grant true for a person who is not there.
                    session: 0,
                    channel: 0,
                    account,
                    // The whole reason there is an account to check at all: an
                    // unregistered guest has no durable identity and never
                    // reaches this.
                    registered: true,
                    name: String::new(),
                    // A token is something a client presents on a live
                    // connection, and a certificate belongs to one. Neither
                    // survives the disconnect, so neither can open a door here.
                    tokens: Vec::new(),
                    cert_hash: Vec::new(),
                    strong_cert: false,
                }),
                channel,
                permission: Perm::SUBSCRIBE_PUSH.bits(),
            })
            .await;

        match answer {
            Ok(decision) => decision.into_inner().allowed,
            Err(status) => {
                // Said out loud: a check that is failing closed looks exactly
                // like a user who was never granted the permission, and the
                // difference is the operator's to see.
                tracing::warn!(account, channel, %status, "the push permission check failed; not notifying");
                false
            }
        }
    }

    async fn session_may_receive(&self, scope: u32, session: u32, channel: u32) -> bool {
        // `CheckSession` through the runtime's own guard: the subject here is
        // connected, so the identity is `session-view`'s to resolve and never
        // this service's to state. The account path above exists only because
        // an absent person has no session to resolve.
        self.permit
            .allows_session(scope, session, channel, Perm::SUBSCRIBE_PUSH.bits())
            .await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// An audience that answers from a set instead of from a service.
    #[derive(Debug, Default)]
    pub(crate) struct Allowed {
        /// The `(account, channel)` pairs that are permitted.
        pairs: BTreeSet<(u64, u32)>,
        /// The `(session, channel)` pairs that are permitted live delivery.
        sessions: BTreeSet<(u32, u32)>,
        /// Whether everything else is permitted too.
        everyone: bool,
    }

    impl Allowed {
        /// Everybody, everywhere: the check is not what this test is about.
        pub(crate) const fn everyone() -> Self {
            Self {
                pairs: BTreeSet::new(),
                sessions: BTreeSet::new(),
                everyone: true,
            }
        }

        /// Only these `(account, channel)` pairs.
        pub(crate) fn only(pairs: impl IntoIterator<Item = (u64, u32)>) -> Self {
            Self {
                pairs: pairs.into_iter().collect(),
                sessions: BTreeSet::new(),
                everyone: false,
            }
        }

        /// Only these `(session, channel)` pairs, for live delivery.
        pub(crate) fn sessions(pairs: impl IntoIterator<Item = (u32, u32)>) -> Self {
            Self {
                pairs: BTreeSet::new(),
                sessions: pairs.into_iter().collect(),
                everyone: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl Audience for Allowed {
        async fn may_receive(&self, _scope: u32, account: u64, channel: u32) -> bool {
            self.everyone || self.pairs.contains(&(account, channel))
        }

        async fn session_may_receive(&self, _scope: u32, session: u32, channel: u32) -> bool {
            self.everyone || self.sessions.contains(&(session, channel))
        }
    }

    #[tokio::test]
    async fn an_unreachable_permissions_service_notifies_nobody() {
        // The property the type exists for: taking `permissions` down must not
        // turn a private channel into one everybody's phone reads out. The
        // default configuration points at a socket nothing is serving.
        let config = starling_runtime::config::Config::with_defaults(std::path::Path::new(
            "/run/starling-push-test",
        ));
        let resolver = Resolver::new(
            std::sync::Arc::new(config),
            starling_runtime::inproc::Broker::new(),
        );
        let permitted = Permitted::new(resolver);
        assert!(!permitted.may_receive(1, 5, 7).await);
        // And the same for the session that is here: the two identities take
        // different paths through `permissions` and must fail the same way.
        assert!(!permitted.session_may_receive(1, 9, 7).await);
    }
}
