//! Asking `session-view` about a session this roster has not heard of yet.
//!
//! A roster follows the view by subscription, so it learns of an arrival a
//! moment after the view does, and the arriving client may already be talking:
//! it is told it has joined (`ServerSync`) without waiting for every service's
//! roster to catch up. A decision made from the roster in that moment ("a
//! scheduled message needs a certificate", "only the author may edit") was made
//! about nobody, and refused a client that had what it asked for. So before
//! deciding by a session it does not know, a service asks the authority.

use starling_proto_fancy::common::Scope;
use starling_proto_fancy::sessionview::GetRequest;
use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;

use crate::channel::Resolver;
use crate::roster::{NOBODY, Roster};

impl Roster {
    /// Ask through `resolver` from now on, for a roster that is not following
    /// the view itself (a test's), or before it has started to.
    pub fn ask_through(&self, resolver: Resolver) {
        let _ = self.authority.set(resolver);
    }

    /// Make sure this roster knows `session`, asking `session-view` if it
    /// does not; what the view says is folded in as its own event would be.
    ///
    /// Nothing is asked for a session already known, so the ordinary case
    /// costs a map lookup. A session the view does not know either is left
    /// unknown: it has gone, or never was. A roster with nowhere to ask (one
    /// not following the view) answers from what it has, as before.
    pub async fn catch_up(&self, scope: u32, session: u32) {
        if session == NOBODY || self.channel_of(session).is_some() {
            return;
        }
        let Some(resolver) = self.authority.get() else {
            return;
        };
        let Ok(transport) = resolver.channel("session-view") else {
            return;
        };
        let Ok(found) = SessionViewClient::new(transport)
            .get(GetRequest {
                scope: Some(Scope { instance: scope }),
                session,
            })
            .await
        else {
            return;
        };
        tracing::debug!(session, "the roster had not caught up; asked session-view");
        self.upsert(&found.into_inner());
    }
}
