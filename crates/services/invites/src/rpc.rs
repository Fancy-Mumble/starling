//! The mesh surface: the handshake redeems, operator-api manages.
//!
//! Neither caller has a client session, which is why these are RPCs rather
//! than envelope arms: the handshake asks before a session exists, and an
//! operator never has one.

use std::sync::Arc;

use starling_proto_fancy::invites::invites_server::{Invites, InvitesServer};
use starling_proto_fancy::invites::{
    CreateRequest, ListReply, ListRequest, Record, RedeemReply, RedeemRequest, RevokeReply,
    RevokeRequest,
};
use starling_runtime::ids::now_ms;
use starling_runtime::trail::{self, Record as TrailRecord};
use tonic::{Request, Response, Status};

use crate::store::{self, Redeemed, Row};
use crate::{
    InvitesService, Policy, describe, lifetime_ms, mint_code, plausible, redeemer_key, use_limit,
};

/// The generated server, wrapping the service.
pub(crate) fn server(service: Arc<InvitesService>) -> InvitesServer<InvitesRpc> {
    InvitesServer::new(InvitesRpc(service))
}

/// tonic's generated trait is foreign and `Arc` is foreign, so the service
/// cannot implement it through an `Arc` directly; the same one-field wrapper
/// `server-config` uses.
#[derive(Debug, Clone)]
pub struct InvitesRpc(Arc<InvitesService>);

fn scope_of(scope: Option<starling_proto_fancy::common::Scope>) -> u32 {
    scope.map_or(1, |scope| scope.instance)
}

fn unavailable(error: &starling_runtime::storage::StoreError) -> Status {
    tracing::warn!(%error, "invites storage failed");
    Status::unavailable("invites storage failed")
}

impl Row {
    fn to_record(&self) -> Record {
        Record {
            code: self.code.clone(),
            channel: self.channel,
            created_ms: self.created_ms,
            expires_ms: self.expires_ms,
            max_uses: self.max_uses,
            uses: self.uses,
            creator: self.creator.clone(),
            creator_account: self.creator_account,
        }
    }
}

#[tonic::async_trait]
impl Invites for InvitesRpc {
    async fn redeem(
        &self,
        request: Request<RedeemRequest>,
    ) -> Result<Response<RedeemReply>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let refused = |reason: &str| {
            Ok(Response::new(RedeemReply {
                admitted: false,
                channel: 0,
                reason: reason.to_owned(),
            }))
        };
        if !plausible(&req.code) {
            return refused("not an invite code");
        }
        // Asked of this service's own view as well as the handshake's: the
        // switch has to hold even for a caller that forgot to look.
        if Policy::of(&self.0.settings.get(scope)) == Policy::Off {
            return refused("invites are switched off");
        }
        let who = redeemer_key(&req.cert_hash, &req.name);
        match store::redeem(&self.0.store, scope, &req.code, &who, now_ms())
            .await
            .map_err(|error| unavailable(&error))?
        {
            Redeemed::Admitted { channel } => Ok(Response::new(RedeemReply {
                admitted: true,
                channel,
                reason: String::new(),
            })),
            Redeemed::Refused(reason) => refused(reason),
        }
    }

    async fn list(&self, request: Request<ListRequest>) -> Result<Response<ListReply>, Status> {
        let scope = scope_of(request.into_inner().scope);
        let rows = store::live(&self.0.store, scope, None, now_ms())
            .await
            .map_err(|error| unavailable(&error))?;
        Ok(Response::new(ListReply {
            invites: rows.iter().map(Row::to_record).collect(),
        }))
    }

    async fn create(&self, request: Request<CreateRequest>) -> Result<Response<Record>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let config = self.0.settings.get(scope);
        if Policy::of(&config) == Policy::Off {
            // An operator may mint one whoever the setting names, but not one
            // that could never admit anybody: that is a link that fails
            // silently in somebody else's hands.
            return Err(Status::failed_precondition(
                "invites are switched off on this server",
            ));
        }
        let now = now_ms();
        let lifetime = lifetime_ms(req.max_age_s, config.invite_max_hours);
        let creator = if req.creator.trim().is_empty() {
            "operator".to_owned()
        } else {
            req.creator.trim().to_owned()
        };
        let row = Row {
            code: mint_code(),
            channel: req.channel,
            created_ms: now,
            expires_ms: if lifetime == 0 { 0 } else { now + lifetime },
            max_uses: use_limit(req.max_uses, config.invite_max_uses),
            uses: 0,
            creator: creator.clone(),
            creator_key: "operator".to_owned(),
            creator_account: None,
        };
        store::insert(&self.0.store, scope, &row)
            .await
            .map_err(|error| unavailable(&error))?;
        self.0.trail.record(
            scope,
            TrailRecord::new(trail::category::INVITE, "invite created")
                .target_channel(row.channel)
                .detail(format!(
                    "by {creator} through the operator API: {}",
                    describe(&row)
                )),
        );
        Ok(Response::new(row.to_record()))
    }

    async fn revoke(
        &self,
        request: Request<RevokeRequest>,
    ) -> Result<Response<RevokeReply>, Status> {
        let req = request.into_inner();
        let scope = scope_of(req.scope);
        let found = store::remove(&self.0.store, scope, &req.code, None)
            .await
            .map_err(|error| unavailable(&error))?;
        if found {
            self.0.trail.record(
                scope,
                TrailRecord::new(trail::category::INVITE, "invite revoked")
                    .detail("through the operator API"),
            );
        }
        Ok(Response::new(RevokeReply { found }))
    }
}
