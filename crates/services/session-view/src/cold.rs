//! Cold queries: routed to the owning authority, never answered from here.
//!
//! The cost is one extra hop for the cold cases, an ACL question about a
//! channel the user is not in, or a lookup of an offline account. Neither is on
//! a hot path: whisper setup is not per-packet and moderation is not per-frame
//! (`docs/ARCHITECTURE.md` §4).
//!
//! What this module deliberately does *not* have is a cache. Caching the
//! `(user, channel)` cross product is exactly the line between a subscription
//! hub and a second ACL engine.

use starling_proto_fancy::permissions::permissions_client::PermissionsClient;
use starling_proto_fancy::permissions::{CheckRequest, Subject};
use starling_proto_fancy::sessionview::{Account, ColdAnswer, ColdQuery, cold_answer, cold_query};
use starling_proto_fancy::userdata::user_data_client::UserDataClient;
use starling_proto_fancy::userdata::{LookupRequest, lookup_request};
use starling_runtime::channel::Resolver;
use tonic::Status;

/// Forwards a cold query to whichever service owns the answer.
#[derive(Debug, Clone)]
pub struct ColdRouter {
    resolver: Option<Resolver>,
}

impl ColdRouter {
    /// A router over `resolver`.
    #[must_use]
    pub fn new(resolver: Resolver) -> Self {
        Self {
            resolver: Some(resolver),
        }
    }

    /// A router with nowhere to forward to, for tests.
    #[must_use]
    pub fn disconnected() -> Self {
        Self { resolver: None }
    }

    /// Forward one query, on behalf of `asker`.
    ///
    /// `asker` is the identified subject the query is about, which only the
    /// caller can supply, this router holds no view of its own. Passing `None`
    /// evaluates the query as an anonymous guest, which is the safe direction but
    /// denies a registered user permissions they hold.
    ///
    /// # Errors
    ///
    /// [`Status::unavailable`] when the owning service cannot be reached. A
    /// refusal is safe here and an invented answer is not: a fabricated grant
    /// is a security bug, and a fabricated denial is a bug report.
    pub async fn forward(
        &self,
        query: ColdQuery,
        asker: Option<Subject>,
    ) -> Result<ColdAnswer, Status> {
        // The shape is checked before reachability: an empty query is invalid
        // whether or not the authority happens to be up, and reporting it as
        // "unavailable" would send the caller to look at the wrong thing.
        if query.query.is_none() {
            return Err(Status::invalid_argument("an empty cold query"));
        }
        let Some(resolver) = &self.resolver else {
            return Err(Status::unavailable("no authority is reachable"));
        };
        let scope = query.scope;
        match query.query {
            Some(cold_query::Query::Acl(acl)) => {
                let channel = resolver
                    .channel("permissions")
                    .map_err(|error| Status::unavailable(error.to_string()))?;
                // The identity comes from the caller, which is this service: it
                // is the read model that knows who a session is, and permissions
                // cannot look it up itself without reversing the cold-query edge.
                //
                // A subject sent without one is evaluated as an anonymous guest,
                // which for the SuperUser means being denied by the very ACL
                // table the bypass exists to survive.
                let subject = asker.unwrap_or(Subject {
                    session: acl.session,
                    registered: false,
                    ..Subject::default()
                });
                let decision = PermissionsClient::new(channel)
                    .check(CheckRequest {
                        scope,
                        subject: Some(subject),
                        channel: acl.channel,
                        permission: acl.permission,
                    })
                    .await?
                    .into_inner();
                Ok(ColdAnswer {
                    answer: Some(cold_answer::Answer::Decision(decision)),
                })
            }
            Some(cold_query::Query::Account(account)) => {
                let channel = resolver
                    .channel("userdata")
                    .map_err(|error| Status::unavailable(error.to_string()))?;
                let by = match account.by {
                    Some(starling_proto_fancy::sessionview::account_query::By::Id(id)) => {
                        Some(lookup_request::By::Id(id))
                    }
                    Some(starling_proto_fancy::sessionview::account_query::By::Name(name)) => {
                        Some(lookup_request::By::Name(name))
                    }
                    None => None,
                };
                let found = UserDataClient::new(channel)
                    .lookup(LookupRequest { scope, by })
                    .await;
                let answer = match found {
                    Ok(account) => {
                        let account = account.into_inner();
                        Account {
                            id: account.id,
                            name: account.name,
                            found: true,
                        }
                    }
                    // Not found is an answer, not a failure: an operator asking
                    // about an account that does not exist wants "no", not a
                    // stack trace.
                    Err(status) if status.code() == tonic::Code::NotFound => Account {
                        found: false,
                        ..Account::default()
                    },
                    Err(status) => return Err(status),
                };
                Ok(ColdAnswer {
                    answer: Some(cold_answer::Answer::Account(answer)),
                })
            }
            None => Err(Status::invalid_argument("an empty cold query")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_unreachable_authority_refuses_rather_than_inventing_an_answer() {
        // A fabricated grant is a security bug. Refusing is the only safe
        // failure for a permission question.
        let err = ColdRouter::disconnected()
            .forward(
                ColdQuery {
                    scope: None,
                    query: Some(cold_query::Query::Acl(
                        starling_proto_fancy::sessionview::AclQuery {
                            session: 1,
                            channel: 0,
                            permission: 1,
                        },
                    )),
                },
                None,
            )
            .await
            .expect_err("no authority");
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }

    #[tokio::test]
    async fn an_empty_query_is_rejected_rather_than_guessed() {
        let err = ColdRouter::disconnected()
            .forward(
                ColdQuery {
                    scope: None,
                    query: None,
                },
                None,
            )
            .await
            .expect_err("empty query");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
