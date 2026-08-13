//! The REST surface.
//!
//! Every handler does the same three things in the same order: identify the
//! caller, check the scope the operation needs, and record the action before
//! answering. The order matters, a record written after the answer is a record
//! that can be missing for an action that happened.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use starling_proto_fancy::common::{Actor, Operator, Scope, actor};
use starling_proto_fancy::moderation::moderation_client::ModerationClient;
use starling_proto_fancy::serverconfig::server_config_client::ServerConfigClient;
use starling_proto_fancy::userdata::user_data_client::UserDataClient;
use starling_proto_fancy::userdata::{
    Account, ListRequest, LookupRequest, RegisterRequest, UpdateRequest, lookup_request,
};

use crate::OperatorApi;
use crate::audit::AuditRecord;
use crate::auth::Refusal;

/// The router, with the API mounted at the root.
pub fn router(api: Arc<OperatorApi>) -> Router {
    Router::new()
        .route("/openapi.json", get(openapi))
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/v1/accounts", get(list_accounts).post(create_account))
        // Setting the SuperUser password is `PUT /v1/accounts/0`: the
        // administrator is an account, so it takes the account route.
        .route(
            "/v1/accounts/{id}",
            put(update_account).delete(delete_account),
        )
        // Avatar and comment are content-addressed blobs behind an account
        // and not fields on it, so they are their own resources, and they
        // are bytes, which do not belong in a JSON field.
        .route(
            "/v1/accounts/{id}/texture",
            get(get_texture).put(set_texture).delete(clear_texture),
        )
        .route(
            "/v1/accounts/{id}/comment",
            get(get_comment).put(set_comment),
        )
        // `Ban`, `Unban` and `Kick` have existed in `moderation.proto` since the
        // service did, and nothing outside the service ever called them: an
        // operator could *list* bans and not make one, so the admin plane could
        // watch a user misbehave and do nothing about them.
        .route("/v1/bans", get(list_bans).post(create_ban))
        .route("/v1/bans/{id}", delete(remove_ban))
        .route("/v1/config", get(get_config).post(set_config))
        // How the server is, collected by the `health` service. The route a
        // dashboard polls; `/healthz` above stays a bare liveness probe.
        .route("/v1/health", get(get_health))
        // The read side a channel viewer needs. Ice served this on the C++
        // server (`getChannels`, `getUsers`) and Starling has no Ice at all
        // (`docs/GAP-ANALYSIS.md` S6), so without these a viewer has no way to
        // see the server, the whole surface it was built on is gone.
        .route("/v1/channels", get(list_channels).post(create_channel))
        .route(
            "/v1/channels/{id}",
            put(update_channel).delete(delete_channel),
        )
        // The write half of `docs/GAP-ANALYSIS.md` G1: `SetAcl` exists over
        // gRPC and had no operator surface, so an ACL could be read from here
        // and changed only from a client that cannot write one either.
        .route("/v1/channels/{id}/acl", get(get_acl).put(set_acl))
        .route(
            "/v1/channels/{id}/groups/{group}/members",
            post(add_temporary_group).delete(remove_temporary_group),
        )
        // The server addressing a connected user, which is the one thing an
        // external system cannot do by holding a client connection of its own.
        .route("/v1/messages", post(send_message))
        .route("/v1/sessions", get(list_sessions))
        // Moderating a *connected* user. `PATCH` because these are a partial
        // update to a live session and every field is optional, omitted means
        // "leave it alone", which a `PUT` could not express without the caller
        // having to restate the user's whole state and race whoever else is
        // changing it.
        .route("/v1/sessions/{session}", patch(set_session_state))
        .route("/v1/sessions/{session}/kick", post(kick_session))
        // murmur's `hasPermission` and `effectivePermissions` in one route: the
        // first is the second plus a mask test, and serving them separately
        // would be two ways to ask one question that could disagree.
        .route(
            "/v1/sessions/{session}/permissions",
            get(session_permissions),
        )
        // murmur's `getLog`/`getLogLen`. The audit service has answered
        // `Query` all along; nothing exposed it.
        .route("/v1/log", get(get_log))
        // What changed, as it changes: one stream a consumer follows instead
        // of polling every route above. Bidirectional, because registering a
        // context-menu entry has to end when the connection servicing it does.
        .route("/v1/events", get(crate::live::websocket))
        .route("/v1/whoami", post(whoami))
        .with_state(api)
}

/// The `OpenAPI` description, so an admin client is trivial in any language.
async fn openapi() -> impl IntoResponse {
    (
        [("content-type", "application/json")],
        crate::openapi::description(),
    )
}

/// `Channel.flags` bits, from `metadata`'s `tree_actor.rs`.
///
/// Written out, not imported: `operator-api` depending on a service's
/// crate is the coupling the gRPC boundary exists to prevent, and these two
/// bits are part of the published shape of `Tree`, not an implementation
/// detail. The proto documents the layout at `Channel.flags`.
const CHANNEL_HIDDEN: u32 = 1;
const CHANNEL_TEMPORARY: u32 = 2;
/// Out of the tree: parentless, and not the root. Surfaced because `parent` is
/// null for both, so a caller building a tree from this JSON has no other way
/// to tell a meeting room from the server's own root channel.
const CHANNEL_DETACHED: u32 = 4;

/// What a refusal looks like on the wire.
#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
}

fn refuse(status: StatusCode, message: &str) -> (StatusCode, Json<ApiError>) {
    (
        status,
        Json(ApiError {
            error: message.to_owned(),
        }),
    )
}

/// Identify, authorise and record, in that order.
fn admit(
    api: &OperatorApi,
    headers: &HeaderMap,
    scope: &str,
    action: &str,
) -> Result<String, (StatusCode, Json<ApiError>)> {
    let header = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    let identity = api.identify(header).map_err(|refusal| {
        let status = match refusal {
            Refusal::Missing | Refusal::Malformed => StatusCode::UNAUTHORIZED,
            Refusal::Rejected | Refusal::Unscoped => StatusCode::FORBIDDEN,
        };
        refuse(status, &refusal.to_string())
    })?;

    if !identity.allows(scope) {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            &format!("this identity does not hold {scope}"),
        ));
    }

    // Recorded before the action is performed, and a failure to record refuses
    // the request outright.
    let record = AuditRecord {
        subject: identity.subject.clone(),
        action: action.to_owned(),
        outcome: "accepted".to_owned(),
    };
    if let Err(error) = api.record(&record) {
        return Err(refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("the action was not recorded and so did not happen: {error}"),
        ));
    }
    Ok(identity.subject)
}

/// `admit`, for a handler that cannot answer with this module's JSON body.
///
/// The WebSocket upgrade returns a `Response` and not a `Json<ApiError>`,
/// and authorisation still has to happen before the upgrade, a socket that
/// opens and immediately closes is, to most clients, indistinguishable from a
/// network fault.
///
/// # Errors
///
/// The same statuses `admit` produces, with the reason as plain text.
pub fn admit_live(
    api: &OperatorApi,
    headers: &HeaderMap,
    action: &str,
) -> Result<String, (StatusCode, String)> {
    admit(api, headers, "session-view:read", action)
        .map_err(|(status, body)| (status, body.0.error))
}

/// A channel to one service, or a 502 saying which one could not be reached.
fn dial(
    api: &OperatorApi,
    service: &str,
) -> Result<tonic::transport::Channel, (StatusCode, Json<ApiError>)> {
    api.resolver().channel(service).map_err(|error| {
        refuse(
            StatusCode::BAD_GATEWAY,
            &format!("{service} is unreachable: {error}"),
        )
    })
}

/// The identity a service should attribute this change to.
///
/// Carried on every write, not for authorisation, the services trust this
/// plane, but so a change has a name against it in the service's own log. An
/// operator action that appears in the audit file and nowhere else is only half
/// recorded.
fn operator_actor(subject: String, scope: &str) -> Option<Actor> {
    Some(Actor {
        who: Some(actor::Who::Operator(Operator {
            subject,
            scopes: vec![scope.to_owned()],
        })),
    })
}

/// The server instance every route addresses.
///
/// One constant, not a parameter on each handler: multi-tenancy is a
/// deployment shape Starling supports but this API has never exposed, and a
/// half-threaded `scope` would read as though it did.
fn scope() -> Option<Scope> {
    Some(Scope { instance: 1 })
}

/// One account, as JSON.
#[derive(Debug, Serialize, Deserialize)]
struct AccountJson {
    id: u64,
    name: String,
    email: String,
    /// SHA-1 of the user's certificate as lowercase hex, empty when none is
    /// registered.
    ///
    /// Hex, not base64, because that is the form murmur prints it in,
    /// the form a Mumble client shows in its certificate dialog, and therefore
    /// the form an operator has in hand when comparing the two.
    cert_hash: String,
}

impl From<Account> for AccountJson {
    fn from(account: Account) -> Self {
        Self {
            id: account.id,
            name: account.name,
            email: account.email,
            cert_hash: hex(&account.cert_hash),
        }
    }
}

/// Bytes to lowercase hex.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        // Writing to a String cannot fail, and the alternative is threading a
        // Result out of a formatting helper that has nothing to report.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Lowercase or uppercase hex to bytes.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// What creating an account takes.
#[derive(Debug, Deserialize)]
struct NewAccount {
    name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
}

/// A change to one account. Absent fields are left alone.
///
/// `Option` per field, not `String`: "not mentioned" and "set to empty"
/// are different requests, and collapsing them would make omitting a name a
/// silent way to erase it.
#[derive(Debug, Deserialize)]
struct AccountUpdate {
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    /// SHA-1 of the certificate to accept for this account, as hex.
    ///
    /// Registering it ahead of time is how a user is issued a certificate to
    /// import rather than having to first connect with one; empty clears it.
    #[serde(default)]
    cert_hash: Option<String>,
    /// Which server instance the account belongs to. Defaults to the first.
    #[serde(default)]
    instance: Option<u32>,
}

impl AccountUpdate {
    /// The field names userdata should write, in the order they were declared.
    fn fields(&self) -> Vec<String> {
        let mut fields = Vec::new();
        if self.password.is_some() {
            fields.push("password".to_owned());
        }
        if self.name.is_some() {
            fields.push("name".to_owned());
        }
        if self.email.is_some() {
            fields.push("email".to_owned());
        }
        if self.cert_hash.is_some() {
            fields.push("cert_hash".to_owned());
        }
        fields
    }
}

/// How a caller narrows the account list.
///
/// `name` is an exact match and `prefix` is a scan. They are separate because
/// they are different questions with different answers: resolving a known
/// username to an id must not depend on no other account sharing its opening
/// characters, which is what filtering a prefix client-side would make it do.
#[derive(Debug, Default, Deserialize)]
struct AccountQuery {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    prefix: Option<String>,
}

async fn list_accounts(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Query(query): Query<AccountQuery>,
) -> Result<Json<Vec<AccountJson>>, (StatusCode, Json<ApiError>)> {
    let _ = admit(&api, &headers, "userdata:read", "GET /v1/accounts")?;
    let channel = dial(&api, "userdata")?;
    let mut userdata = UserDataClient::new(channel);

    // An exact name is a lookup, not a filtered list. A miss is an empty array
    // rather than a 404: this is a collection, and "no account is called that"
    // is an answer about its contents, not a missing resource.
    if let Some(name) = query.name {
        return Ok(Json(
            userdata
                .lookup(LookupRequest {
                    scope: scope(),
                    by: Some(lookup_request::By::Name(name)),
                })
                .await
                .map_or_else(
                    |_| Vec::new(),
                    |account| vec![AccountJson::from(account.into_inner())],
                ),
        ));
    }

    let page = userdata
        .list(ListRequest {
            scope: scope(),
            name_prefix: query.prefix.unwrap_or_default(),
            limit: 200,
            after_id: 0,
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, &status.to_string()))?;

    Ok(Json(
        page.into_inner()
            .accounts
            .into_iter()
            .map(AccountJson::from)
            .collect(),
    ))
}

async fn create_account(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Json(new): Json<NewAccount>,
) -> Result<Json<AccountJson>, (StatusCode, Json<ApiError>)> {
    let _ = admit(&api, &headers, "userdata:write", "POST /v1/accounts")?;
    let channel = api
        .resolver()
        .channel("userdata")
        .map_err(|error| refuse(StatusCode::BAD_GATEWAY, &error.to_string()))?;

    let account = UserDataClient::new(channel)
        .register(RegisterRequest {
            scope: Some(Scope { instance: 1 }),
            actor: None,
            account: Some(Account {
                name: new.name,
                email: new.email,
                ..Account::default()
            }),
            password: new.password,
        })
        .await
        // A name already taken is a 409; a userdata that cannot be reached is
        // not. Reporting both as CONFLICT tells an operator to pick another
        // name when the real answer is that the service is down, and the
        // message it comes with ("dns error") does not read as either.
        .map_err(|status| match status.code() {
            tonic::Code::AlreadyExists | tonic::Code::InvalidArgument => {
                refuse(StatusCode::CONFLICT, status.message())
            }
            tonic::Code::PermissionDenied => refuse(StatusCode::FORBIDDEN, status.message()),
            _ => refuse(StatusCode::BAD_GATEWAY, &status.to_string()),
        })?;

    Ok(Json(AccountJson::from(account.into_inner())))
}

/// Change named fields of one account.
///
/// Only the fields present in the body are written, which is what makes this a
/// general edit, not a whole-object replace: two operators changing
/// different settings must not silently overwrite each other, and userdata
/// enforces that with an explicit field list, not by diffing.
///
/// **This is also how the SuperUser password is set**, the administrator is
/// simply account `0`:
///
/// ```text
/// PUT /v1/accounts/0  {"password":"..."}
/// ```
///
/// There is deliberately no separate superuser route. One would be this endpoint
/// with a hard-coded id, and it would drift: a change to how a password is
/// written here would have to be remembered there.
///
/// The account has to exist. For the administrator it always does, userdata
/// creates it on first boot, but a userdata database restored from before that
/// has no way back in over HTTP, which is what `starling
/// set-superuser-password` is for.
async fn update_account(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    Json(change): Json<AccountUpdate>,
) -> Result<Json<AccountJson>, (StatusCode, Json<ApiError>)> {
    let subject = admit(
        &api,
        &headers,
        "userdata:write",
        &format!("PUT /v1/accounts/{id}"),
    )?;

    // Absent means "leave it alone"; present-but-empty is a request to store an
    // empty password, which would leave a login that any password opens. The two
    // are different, so they are distinguished and not both defaulted.
    if change.password.as_deref().is_some_and(str::is_empty) {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "a password cannot be set to the empty string",
        ));
    }
    let fields = change.fields();
    if fields.is_empty() {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "no fields to change; send at least one of password, name, email, cert_hash",
        ));
    }

    // Decoded before anything is written, so a malformed hash is a 400 naming
    // the field rather than a certificate silently registered as empty, which
    // would read as "this account accepts no certificate" and lock the user out.
    let cert_hash = match change.cert_hash.as_deref() {
        None | Some("") => Vec::new(),
        Some(text) => unhex(text).ok_or_else(|| {
            refuse(
                StatusCode::BAD_REQUEST,
                "cert_hash must be an even number of hex digits",
            )
        })?,
    };

    let scope = Some(Scope {
        instance: change.instance.unwrap_or(1),
    });
    let channel = api
        .resolver()
        .channel("userdata")
        .map_err(|error| refuse(StatusCode::BAD_GATEWAY, &error.to_string()))?;
    let mut userdata = UserDataClient::new(channel);

    // Asked about before it is changed, so a missing id is a 404 and not the
    // 403 a refused change is. userdata reports both as `permission_denied`, and
    // an operator cannot act on "denied" when the truth is "no such account".
    let _ = userdata
        .lookup(LookupRequest {
            scope,
            by: Some(lookup_request::By::Id(id)),
        })
        .await
        .map_err(|_| refuse(StatusCode::NOT_FOUND, "no such account"))?;

    let updated = userdata
        .update(UpdateRequest {
            scope,
            // The operator identity is load-bearing: without it userdata demands
            // the *current* password before changing a sensitive field, which is
            // exactly what an operator resetting a lost credential does not have.
            actor: Some(Actor {
                who: Some(actor::Who::Operator(Operator {
                    subject,
                    scopes: vec!["userdata:write".to_owned()],
                })),
            }),
            id,
            fields,
            values: Some(Account {
                name: change.name.unwrap_or_default(),
                email: change.email.unwrap_or_default(),
                cert_hash,
                ..Account::default()
            }),
            password: change.password.unwrap_or_default(),
            current_password: String::new(),
        })
        .await
        .map_err(|status| refuse(StatusCode::FORBIDDEN, status.message()))?;

    Ok(Json(AccountJson::from(updated.into_inner())))
}

async fn delete_account(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(id): Path<u64>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let _ = admit(
        &api,
        &headers,
        "userdata:write",
        &format!("DELETE /v1/accounts/{id}"),
    )?;
    let channel = api
        .resolver()
        .channel("userdata")
        .map_err(|error| refuse(StatusCode::BAD_GATEWAY, &error.to_string()))?;

    let _ = UserDataClient::new(channel)
        .delete(starling_proto_fancy::userdata::DeleteRequest {
            scope: Some(Scope { instance: 1 }),
            actor: None,
            id,
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, &status.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Which content-addressed field of an account a request is about.
///
/// The two blobs behave identically, `userdata` stores bytes and the account
/// holds the hash, so they share every step but the field name.
#[derive(Clone, Copy)]
enum Blob {
    Texture,
    Comment,
}

impl Blob {
    /// The `Account` field holding this blob's hash.
    const fn field(self) -> &'static str {
        match self {
            Self::Texture => "texture_hash",
            Self::Comment => "comment_hash",
        }
    }
}

/// The hash an account currently holds for one blob, or `None` when unset.
///
/// A missing account and an account with no avatar are different answers, so
/// this distinguishes them instead of collapsing both to "nothing there".
async fn blob_hash(
    api: &OperatorApi,
    id: u64,
    which: Blob,
) -> Result<Option<Vec<u8>>, (StatusCode, Json<ApiError>)> {
    let account = UserDataClient::new(dial(api, "userdata")?)
        .lookup(LookupRequest {
            scope: scope(),
            by: Some(lookup_request::By::Id(id)),
        })
        .await
        .map_err(|_| refuse(StatusCode::NOT_FOUND, "no such account"))?
        .into_inner();

    let hash = match which {
        Blob::Texture => account.texture_hash,
        Blob::Comment => account.comment_hash,
    };
    Ok(if hash.is_empty() { None } else { Some(hash) })
}

/// Fetch the bytes behind a hash.
async fn read_blob(
    api: &OperatorApi,
    hash: Vec<u8>,
) -> Result<Vec<u8>, (StatusCode, Json<ApiError>)> {
    Ok(UserDataClient::new(dial(api, "userdata")?)
        .get_blob(starling_proto_fancy::userdata::BlobRequest {
            scope: scope(),
            hash,
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner()
        .bytes)
}

/// Store bytes and point an account's field at them.
///
/// Two steps in this order on purpose: the blob exists before anything refers
/// to it, so a failure between them leaves an unreferenced blob rather than an
/// account pointing at bytes that were never written.
async fn write_blob(
    api: &OperatorApi,
    subject: String,
    id: u64,
    which: Blob,
    bytes: Vec<u8>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let mut userdata = UserDataClient::new(dial(api, "userdata")?);

    // Empty clears the field: there is no blob to write, and the account is
    // pointed at nothing.
    let hash = if bytes.is_empty() {
        Vec::new()
    } else {
        userdata
            .put_blob(starling_proto_fancy::userdata::Blob {
                scope: scope(),
                // `userdata` hashes the content itself; whatever is sent here
                // is ignored, so sending a guess would only invite trusting it.
                hash: Vec::new(),
                bytes,
            })
            .await
            .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
            .into_inner()
            .hash
    };

    let mut values = Account::default();
    match which {
        Blob::Texture => values.texture_hash = hash,
        Blob::Comment => values.comment_hash = hash,
    }

    let _ = userdata
        .update(UpdateRequest {
            scope: scope(),
            actor: operator_actor(subject, "userdata:write"),
            id,
            fields: vec![which.field().to_owned()],
            values: Some(values),
            password: String::new(),
            current_password: String::new(),
        })
        .await
        .map_err(|status| refuse(StatusCode::FORBIDDEN, status.message()))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn get_texture(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(id): Path<u64>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let _ = admit(
        &api,
        &headers,
        "userdata:read",
        &format!("GET /v1/accounts/{id}/texture"),
    )?;
    let Some(hash) = blob_hash(&api, id, Blob::Texture).await? else {
        return Err(refuse(StatusCode::NOT_FOUND, "this account has no texture"));
    };
    let bytes = read_blob(&api, hash).await?;
    // Not `image/png`: the bytes are whatever was uploaded, and murmur's legacy
    // texture format is zlib-compressed BGRA rather than an image at all.
    Ok(([("content-type", "application/octet-stream")], bytes))
}

async fn set_texture(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    body: axum::body::Bytes,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let subject = admit(
        &api,
        &headers,
        "userdata:write",
        &format!("PUT /v1/accounts/{id}/texture"),
    )?;
    write_blob(&api, subject, id, Blob::Texture, body.to_vec()).await
}

async fn clear_texture(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(id): Path<u64>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let subject = admit(
        &api,
        &headers,
        "userdata:write",
        &format!("DELETE /v1/accounts/{id}/texture"),
    )?;
    write_blob(&api, subject, id, Blob::Texture, Vec::new()).await
}

async fn get_comment(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(id): Path<u64>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let _ = admit(
        &api,
        &headers,
        "userdata:read",
        &format!("GET /v1/accounts/{id}/comment"),
    )?;
    // An absent comment is an empty one. Unlike a texture there is nothing a
    // caller could do differently on 404, and every caller would have to write
    // the same branch to turn it back into "".
    let text = match blob_hash(&api, id, Blob::Comment).await? {
        Some(hash) => String::from_utf8(read_blob(&api, hash).await?).unwrap_or_default(),
        None => String::new(),
    };
    Ok(([("content-type", "text/plain; charset=utf-8")], text))
}

async fn set_comment(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    body: String,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let subject = admit(
        &api,
        &headers,
        "userdata:write",
        &format!("PUT /v1/accounts/{id}/comment"),
    )?;
    write_blob(&api, subject, id, Blob::Comment, body.into_bytes()).await
}

/// A ban to place, as JSON.
///
/// Everything except the reason is optional because murmur's ban table matches
/// on any of three things (address, certificate hash, or name) and a ban that
/// named all three would only catch somebody presenting all three.
#[derive(Debug, Deserialize)]
struct NewBan {
    /// Dotted-quad or IPv6 literal. Stored as the bytes murmur stores.
    #[serde(default)]
    address: Option<String>,
    /// How much of `address` to match. Defaults to the whole of it.
    #[serde(default)]
    prefix_len: Option<u32>,
    #[serde(default)]
    name: String,
    /// Hex-encoded certificate digest.
    #[serde(default)]
    cert_hash: String,
    #[serde(default)]
    reason: String,
    /// Seconds. Absent or 0 is permanent, as it is in murmur's `BanTable`.
    #[serde(default)]
    duration_s: u32,
    /// A connected session to drop as part of the ban.
    #[serde(default)]
    session: u32,
}

impl NewBan {
    /// The wire form, or why it could not be built.
    ///
    /// A ban matching nothing is refused, never stored: it would sit in the
    /// list looking like protection and catch nobody.
    fn resolve(self) -> Result<(starling_proto_fancy::moderation::Ban, u32), String> {
        let address = match self.address.as_deref().filter(|a| !a.is_empty()) {
            None => Vec::new(),
            Some(text) => match text.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(v4)) => v4.octets().to_vec(),
                Ok(std::net::IpAddr::V6(v6)) => v6.octets().to_vec(),
                Err(_) => return Err(format!("{text:?} is not an IP address")),
            },
        };
        let cert_hash = if self.cert_hash.is_empty() {
            Vec::new()
        } else {
            decode_hex(&self.cert_hash).ok_or("cert_hash must be hex")?
        };
        if address.is_empty() && cert_hash.is_empty() && self.name.is_empty() {
            return Err(
                "a ban needs an address, a cert_hash or a name; one matching nothing catches nobody"
                    .to_owned(),
            );
        }
        let prefix_len = self
            .prefix_len
            .unwrap_or_else(|| u32::try_from(address.len() * 8).unwrap_or(0));
        Ok((
            starling_proto_fancy::moderation::Ban {
                id: 0,
                address,
                prefix_len,
                name: self.name,
                cert_hash,
                reason: self.reason,
                start_ms: 0,
                duration_s: self.duration_s,
            },
            self.session,
        ))
    }
}

/// Hex to bytes, rejecting anything that is not an even run of hex digits.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

async fn create_ban(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Json(ban): Json<NewBan>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::moderation::BanRequest;

    let subject = admit(&api, &headers, "moderation:write", "POST /v1/bans")?;
    let (ban, session) = ban
        .resolve()
        .map_err(|why| refuse(StatusCode::BAD_REQUEST, &why))?;
    let channel = dial(&api, "moderation")?;

    let result = ModerationClient::new(channel)
        .ban(BanRequest {
            scope: scope(),
            actor: operator_actor(subject, "moderation:write"),
            ban: Some(ban),
            session,
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner();

    if !result.applied {
        return Err(refuse(StatusCode::CONFLICT, &result.refused));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_ban(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(id): Path<u64>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::moderation::UnbanRequest;

    let subject = admit(
        &api,
        &headers,
        "moderation:write",
        &format!("DELETE /v1/bans/{id}"),
    )?;
    let channel = dial(&api, "moderation")?;

    let result = ModerationClient::new(channel)
        .unban(UnbanRequest {
            scope: scope(),
            actor: operator_actor(subject, "moderation:write"),
            id,
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner();

    if !result.applied {
        // A ban that is not there is the state the caller asked for, but saying
        // so is what tells an operator their id was wrong.
        return Err(refuse(StatusCode::NOT_FOUND, &result.refused));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Why somebody is being removed. Optional: murmur allows a bare kick.
#[derive(Debug, Default, Deserialize)]
struct KickReason {
    #[serde(default)]
    reason: String,
}

async fn kick_session(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(session): Path<u32>,
    body: Option<Json<KickReason>>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::moderation::KickRequest;

    let subject = admit(
        &api,
        &headers,
        "moderation:write",
        &format!("POST /v1/sessions/{session}/kick"),
    )?;
    let channel = dial(&api, "moderation")?;

    let result = ModerationClient::new(channel)
        .kick(KickRequest {
            scope: scope(),
            actor: operator_actor(subject, "moderation:write"),
            session,
            reason: body.map(|Json(body)| body.reason).unwrap_or_default(),
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner();

    if !result.applied {
        return Err(refuse(StatusCode::NOT_FOUND, &result.refused));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// A partial change to a live session. Absent means "leave it alone".
#[derive(Debug, Deserialize)]
struct SessionPatch {
    #[serde(default)]
    channel: Option<u32>,
    #[serde(default)]
    mute: Option<bool>,
    #[serde(default)]
    deaf: Option<bool>,
    #[serde(default)]
    suppress: Option<bool>,
    #[serde(default)]
    priority_speaker: Option<bool>,
}

/// murmur's `setState`: move, mute, deafen or suppress a connected user.
///
/// The gap an operator meets first, an admin plane that can watch somebody
/// misbehave and do nothing about them. Everything else here reads the server
/// or changes what is stored; this is the only route that reaches a live
/// connection.
async fn set_session_state(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(session): Path<u32>,
    Json(patch): Json<SessionPatch>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::sessioncontrol::SetStateRequest;
    use starling_proto_fancy::sessioncontrol::session_control_client::SessionControlClient;

    let subject = admit(
        &api,
        &headers,
        "session:write",
        &format!("PATCH /v1/sessions/{session}"),
    )?;
    let channel = dial(&api, "session-lifecycle")?;

    let result = SessionControlClient::new(channel)
        .set_state(SetStateRequest {
            scope: scope(),
            actor: operator_actor(subject, "session:write"),
            session,
            channel: patch.channel,
            mute: patch.mute,
            deaf: patch.deaf,
            suppress: patch.suppress,
            priority_speaker: patch.priority_speaker,
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner();

    if !result.applied {
        // `NOT_FOUND` when the session is gone, `CONFLICT` when it is there and
        // the change was refused, the caller's recourse differs: one is retry
        // with a different session, the other is fix the ACL.
        let status = if result.refused.starts_with("no session") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::CONFLICT
        };
        return Err(refuse(status, &result.refused));
    }
    // The *applied* state, which is not always what was asked: deafening also
    // mutes.
    Ok(Json(serde_json::json!({
        "session": session,
        "channel": result.channel,
        "mute": result.mute,
        "deaf": result.deaf,
        "suppress": result.suppress,
        "priority_speaker": result.priority_speaker,
    })))
}

/// Which channel to evaluate in, and optionally which permission to test.
#[derive(Debug, Deserialize)]
struct PermissionQuery {
    #[serde(default)]
    channel: u32,
    /// A single `ChanACL::Perm` bit. Present turns this into `hasPermission`.
    #[serde(default)]
    permission: Option<u32>,
}

/// One live session as `session-view` holds it.
///
/// Resolved there and nowhere else: it is the authority on who a session is, and
/// an admin plane that let a caller assert an identity would be a way to ask
/// "what could this other user do" and get an answer shaped by the lie.
async fn live_session(
    api: &OperatorApi,
    session: u32,
) -> Result<starling_proto_fancy::sessionview::Session, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::sessionview::SubscribeRequest;
    use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;

    let channel = api
        .resolver()
        .channel("session-view")
        .map_err(|error| refuse(StatusCode::BAD_GATEWAY, &error.to_string()))?;
    let sessions = SessionViewClient::new(channel)
        .list(SubscribeRequest {
            scope: Some(Scope { instance: 1 }),
            subscriber: "operator-api".to_owned(),
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner();

    sessions
        .sessions
        .into_iter()
        .find(|held| held.session == session)
        .ok_or_else(|| {
            refuse(
                StatusCode::NOT_FOUND,
                &format!("no session {session} is connected"),
            )
        })
}

/// murmur's `effectivePermissions`, and `hasPermission` when `permission` is
/// given.
async fn session_permissions(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(session): Path<u32>,
    Query(query): Query<PermissionQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::permissions::permissions_client::PermissionsClient;
    use starling_proto_fancy::permissions::{EffectiveRequest, Subject};

    let _ = admit(
        &api,
        &headers,
        "permissions:read",
        &format!("GET /v1/sessions/{session}/permissions"),
    )?;
    let held = live_session(&api, session).await?;
    let channel = dial(&api, "permissions")?;

    let granted = PermissionsClient::new(channel)
        .effective(EffectiveRequest {
            scope: scope(),
            subject: Some(Subject {
                session,
                account: held.account,
                name: held.name,
                registered: held.registered,
                ..Subject::default()
            }),
            channel: query.channel,
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner();

    let mut answer = serde_json::json!({
        "session": session,
        "channel": query.channel,
        "granted": granted.granted,
        "groups": granted.groups,
    });
    if let Some(permission) = query.permission {
        // The mask test done here, not by a second RPC: one evaluation,
        // so the boolean cannot disagree with the bitset beside it.
        let allowed = permission != 0 && granted.granted & permission == permission;
        answer["permission"] = serde_json::json!(permission);
        answer["allowed"] = serde_json::json!(allowed);
    }
    Ok(Json(answer))
}

/// The window, and how much of it to return.
#[derive(Debug, Deserialize)]
struct LogQuery {
    #[serde(default)]
    since_ms: u64,
    #[serde(default)]
    until_ms: u64,
    #[serde(default)]
    category: String,
    #[serde(default)]
    account: u64,
    #[serde(default)]
    limit: u32,
}

/// murmur's `getLog`, over the audit service's own store.
///
/// `getLogLen` has no counterpart on purpose: it exists upstream so a client can
/// page by offset, and paging by offset over an append-only log re-reads rows
/// that shifted underneath it. `before` is a cursor, so a caller pages by
/// passing back the id of the oldest entry it has.
async fn get_log(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Query(query): Query<LogQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::audit::QueryRequest;
    use starling_proto_fancy::audit::audit_client::AuditClient;

    let subject = admit(&api, &headers, "audit:read", "GET /v1/log")?;
    let channel = dial(&api, "audit")?;

    let page = AuditClient::new(channel)
        .query(QueryRequest {
            scope: scope(),
            actor: operator_actor(subject, "audit:read"),
            since_ms: query.since_ms,
            until_ms: query.until_ms,
            category: query.category,
            target_account: query.account,
            limit: query.limit,
            before: Vec::new(),
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner();

    let entries: Vec<serde_json::Value> = page
        .entries
        .into_iter()
        .map(|entry| {
            serde_json::json!({
                "id": hex(&entry.id),
                "at_ms": entry.at_ms,
                "category": entry.category,
                "action": entry.action,
                "actor_name": entry.actor_name,
            })
        })
        .collect();
    Ok(Json(serde_json::Value::Array(entries)))
}

async fn list_bans(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let _ = admit(&api, &headers, "moderation:read", "GET /v1/bans")?;
    let channel = api
        .resolver()
        .channel("moderation")
        .map_err(|error| refuse(StatusCode::BAD_GATEWAY, &error.to_string()))?;

    let bans = ModerationClient::new(channel)
        .list_bans(Scope { instance: 1 })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, &status.to_string()))?;

    let entries: Vec<serde_json::Value> = bans
        .into_inner()
        .bans
        .into_iter()
        .map(|ban| {
            serde_json::json!({
                "id": ban.id,
                "name": ban.name,
                "reason": ban.reason,
                "start_ms": ban.start_ms,
                "duration_s": ban.duration_s,
            })
        })
        .collect();
    Ok(Json(serde_json::Value::Array(entries)))
}

/// The whole server's readiness, as the health collector last saw it.
///
/// The route a dashboard polls. It is deliberately a *read of a snapshot*
/// rather than a sweep: the collector polls every service once every few
/// seconds for everybody, so ten people watching cost the same as one, and the
/// answer carries `observed_at_ms` so a stale picture is visibly stale rather
/// than quietly presented as current.
///
/// Unreadable without a credential like every other route here. Readiness
/// names internal services and the caches they are waiting on, which is a map
/// of the deployment and not something to serve anonymously.
async fn get_health(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::health::health_overview_client::HealthOverviewClient;
    use starling_proto_fancy::health::{OverviewRequest, State as HealthState};

    let _ = admit(&api, &headers, "server-config:read", "GET /v1/health")?;
    let channel = api
        .resolver()
        .channel("health")
        .map_err(|error| refuse(StatusCode::BAD_GATEWAY, &error.to_string()))?;

    let overview = HealthOverviewClient::new(channel)
        .get(OverviewRequest {
            scope: Some(Scope { instance: 1 }),
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, &status.to_string()))?
        .into_inner();

    /// The wire enum as the name a dashboard renders, not its number.
    fn state_name(state: i32) -> &'static str {
        match HealthState::try_from(state) {
            Ok(HealthState::Ready) => "ready",
            Ok(HealthState::Warming) => "warming",
            Ok(HealthState::Warning) => "warning",
            Ok(HealthState::Unreachable) => "unreachable",
            _ => "unknown",
        }
    }

    // The recent past in the same round trip. A dashboard needs both, the
    // detail of now and the shape of the last hour, and two polls would
    // double the traffic to show one page.
    //
    // Best effort: a collector that can answer `Get` and not `History` is odd
    // but not a reason to fail the whole page, and an empty series renders as
    // "no history yet" rather than as an error.
    let history = HealthOverviewClient::new(
        api.resolver()
            .channel("health")
            .map_err(|error| refuse(StatusCode::BAD_GATEWAY, &error.to_string()))?,
    )
    .history(OverviewRequest {
        scope: Some(Scope { instance: 1 }),
    })
    .await
    .map(tonic::Response::into_inner)
    .unwrap_or_default();

    Ok(Json(serde_json::json!({
        "state": state_name(overview.state),
        "observed_at_ms": overview.observed_at_ms,
        "interval_ms": history.interval_ms,
        "history": history
            .samples
            .iter()
            .map(|sample| serde_json::json!({
                "observed_at_ms": sample.observed_at_ms,
                "state": state_name(sample.state),
                "ready": sample.ready,
                "warming": sample.warming,
                "warning": sample.warning,
                "unreachable": sample.unreachable,
                // Microseconds. A dashboard divides for display; the API does
                // not, because rounding at the source destroys the difference
                // between "fast" and "not measured", every in-process check
                // truncated to 0ms before this.
                "worst_latency_us": sample.worst_latency_us,
                "slowest": sample.slowest,
                "busiest_percent": sample.busiest_percent,
                "busiest": sample.busiest,
                "rejected": sample.rejected,
            }))
            .collect::<Vec<_>>(),
        "disabled": overview.disabled,
        "services": overview
            .services
            .iter()
            .map(|service| serde_json::json!({
                "service": service.service,
                "state": state_name(service.state),
                "latency_us": service.latency_us,
                "error": service.error,
                "gates": service
                    .gates
                    .iter()
                    .map(|gate| serde_json::json!({
                        "name": gate.name,
                        "state": state_name(gate.state),
                    }))
                    .collect::<Vec<_>>(),
                // What this service has queued. `capacity: 0` means nothing
                // declares a limit, and a viewer must then show `used`/`peak`
                // as counts, without inventing a percentage.
                "load": service
                    .load
                    .iter()
                    .map(|load| serde_json::json!({
                        "name": load.name,
                        "used": load.used,
                        "peak": load.peak,
                        "capacity": load.capacity,
                        "rejected": load.rejected,
                    }))
                    .collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
    })))
}

async fn get_config(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let _ = admit(&api, &headers, "server-config:read", "GET /v1/config")?;
    let channel = api
        .resolver()
        .channel("server-config")
        .map_err(|error| refuse(StatusCode::BAD_GATEWAY, &error.to_string()))?;

    let snapshot = ServerConfigClient::new(channel)
        .get(starling_proto_fancy::serverconfig::GetRequest {
            scope: Some(Scope { instance: 1 }),
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, &status.to_string()))?
        .into_inner();

    // Everything an operator may write, so the form they render next has the
    // value they just set and not a blank. Neither password is here, a
    // credential read back is a credential in a log, a browser cache and
    // whatever proxy sits in between.
    Ok(Json(starling_runtime::settings::to_json(&snapshot)))
}

/// The channel tree.
///
/// **Not visibility-filtered, and that is deliberate**; it is the same
/// property Ice's `getChannels` had, and the channel viewer relies on knowing
/// it. This is the operator plane: it answers for the server, not for some
/// session, so there is no viewer whose permissions could filter it. A caller
/// that wants a *user's* view must filter by that user's `SeeChannel`, and the
/// `hidden` flag is surfaced below precisely so it can.
async fn list_channels(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::metadata::TreeRequest;
    use starling_proto_fancy::metadata::metadata_client::MetadataClient;

    let _ = admit(&api, &headers, "metadata:read", "GET /v1/channels")?;
    let channel = api
        .resolver()
        .channel("metadata")
        .map_err(|error| refuse(StatusCode::BAD_GATEWAY, &error.to_string()))?;

    let tree = MetadataClient::new(channel)
        .max_decoding_message_size(api.resolver().max_tree_message())
        .get_tree(TreeRequest {
            scope: Some(Scope { instance: 1 }),
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner();

    // `flags` is a bitfield on the wire; unpacked here so a client does not
    // have to know the bit layout to answer "is this channel hidden".
    let channels: Vec<serde_json::Value> = tree
        .channels
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "parent": c.parent,
                "name": c.name,
                "description": c.description,
                "position": c.position,
                "max_users": c.max_users,
                "links": c.links,
                "hidden": c.flags & CHANNEL_HIDDEN != 0,
                "temporary": c.flags & CHANNEL_TEMPORARY != 0,
                "detached": c.flags & CHANNEL_DETACHED != 0,
                "created_at_ms": c.created_at_ms,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "version": tree.version,
        "channels": channels,
    })))
}

/// Who is connected, and where.
///
/// The viewer's other half: a channel tree without occupants is a directory,
/// not a view of the server.
async fn list_sessions(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::sessionview::SubscribeRequest;
    use starling_proto_fancy::sessionview::session_view_client::SessionViewClient;

    let _ = admit(&api, &headers, "session-view:read", "GET /v1/sessions")?;
    let channel = api
        .resolver()
        .channel("session-view")
        .map_err(|error| refuse(StatusCode::BAD_GATEWAY, &error.to_string()))?;

    let sessions = SessionViewClient::new(channel)
        .list(SubscribeRequest {
            scope: Some(Scope { instance: 1 }),
            subscriber: "operator-api".to_owned(),
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner();

    let users: Vec<serde_json::Value> = sessions
        .sessions
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "session": s.session,
                "name": s.name,
                "channel": s.channel,
                // Through `identity`, never `account` alone: an unregistered
                // guest and the SuperUser are both account 0, and only the
                // `registered` flag tells them apart.
                "user_id": starling_proto_fancy::identity::account(s.registered, s.account),
                "mute": s.mute,
                "deaf": s.deaf,
                "self_mute": s.self_mute,
                "self_deaf": s.self_deaf,
                "suppress": s.suppress,
                "priority_speaker": s.priority_speaker,
                "connected_at_ms": s.connected_at_ms,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "version": sessions.version,
        "users": users,
    })))
}

/// What creating a channel takes.
#[derive(Debug, Deserialize)]
struct NewChannel {
    name: String,
    /// The root channel is 0, and a channel created without a parent belongs
    /// there, which is what murmur does and what makes `parent` omissible.
    #[serde(default)]
    parent: u32,
    #[serde(default)]
    description: String,
    #[serde(default)]
    position: i32,
    #[serde(default)]
    max_users: u32,
    #[serde(default)]
    temporary: bool,
    /// Registered accounts to admit, which makes it a private room: `@all` is
    /// denied see|enter|traverse and each of these is granted them. Empty
    /// leaves the channel public, which is what an operator asking for nothing
    /// in particular means.
    #[serde(default)]
    invitee_user_ids: Vec<u32>,
}

/// A change to one channel. Absent fields are left alone, as for an account.
#[derive(Debug, Default, Deserialize)]
struct ChannelUpdate {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    parent: Option<u32>,
    #[serde(default)]
    position: Option<i32>,
    #[serde(default)]
    max_users: Option<u32>,
}

/// One channel, as JSON, the same shape `GET /v1/channels` returns per entry.
fn channel_json(c: &starling_proto_fancy::metadata::Channel) -> serde_json::Value {
    serde_json::json!({
        "id": c.id,
        "parent": c.parent,
        "name": c.name,
        "description": c.description,
        "position": c.position,
        "max_users": c.max_users,
        "links": c.links,
        "hidden": c.flags & CHANNEL_HIDDEN != 0,
        "temporary": c.flags & CHANNEL_TEMPORARY != 0,
        "detached": c.flags & CHANNEL_DETACHED != 0,
        "created_at_ms": c.created_at_ms,
    })
}

/// Turn a `ChannelResult` into a response.
///
/// `metadata` reports a rejected change as `applied = false` with a reason
/// rather than as a gRPC error, so a caller that only checked for transport
/// failure would read "a channel with that name already exists here" as
/// success.
fn applied(
    result: &starling_proto_fancy::metadata::ChannelResult,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    if !result.applied {
        // The refusals are all statements about the request, an absent parent,
        // a duplicate name, an empty name, so they are the caller's fault.
        return Err(refuse(StatusCode::CONFLICT, &result.refused));
    }
    Ok(Json(serde_json::json!({
        "version": result.version,
        "channel": result.channel.as_ref().map(channel_json),
    })))
}

async fn create_channel(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Json(new): Json<NewChannel>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::metadata::metadata_client::MetadataClient;
    use starling_proto_fancy::metadata::{Channel, CreateRequest};

    let subject = admit(&api, &headers, "metadata:write", "POST /v1/channels")?;
    let channel = dial(&api, "metadata")?;

    let result = MetadataClient::new(channel)
        .create(CreateRequest {
            scope: scope(),
            actor: operator_actor(subject, "metadata:write"),
            channel: Some(Channel {
                // Assigned by `metadata`; whatever is sent here is overwritten.
                id: 0,
                parent: Some(new.parent),
                name: new.name,
                description: new.description,
                position: new.position,
                max_users: new.max_users,
                ..Channel::default()
            }),
            temporary: new.temporary,
            invitee_user_ids: new.invitee_user_ids,
            // An operator naming a channel that exists is told so. Reuse
            // exists for a caller provisioning a room it expects to find
            // again; here it would turn "create" into "create or hand me
            // somebody else's room", which is not what the verb says.
            reuse_existing: false,
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner();

    applied(&result)
}

async fn update_channel(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(id): Path<u32>,
    Json(change): Json<ChannelUpdate>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::metadata::metadata_client::MetadataClient;
    use starling_proto_fancy::metadata::{Channel, UpdateRequest};

    let subject = admit(
        &api,
        &headers,
        "metadata:write",
        &format!("PUT /v1/channels/{id}"),
    )?;

    let mut values = Channel::default();
    let mut fields = Vec::new();
    if let Some(name) = change.name {
        values.name = name;
        fields.push("name".to_owned());
    }
    if let Some(description) = change.description {
        values.description = description;
        fields.push("description".to_owned());
    }
    if let Some(parent) = change.parent {
        values.parent = Some(parent);
        fields.push("parent".to_owned());
    }
    if let Some(position) = change.position {
        values.position = position;
        fields.push("position".to_owned());
    }
    if let Some(max_users) = change.max_users {
        values.max_users = max_users;
        fields.push("max_users".to_owned());
    }
    if fields.is_empty() {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "no fields to change; send at least one of name, description, parent, position, max_users",
        ));
    }

    let channel = dial(&api, "metadata")?;
    let result = MetadataClient::new(channel)
        .update(UpdateRequest {
            scope: scope(),
            actor: operator_actor(subject, "metadata:write"),
            channel: id,
            fields,
            values: Some(values),
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner();

    applied(&result)
}

async fn delete_channel(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(id): Path<u32>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::metadata::RemoveRequest;
    use starling_proto_fancy::metadata::metadata_client::MetadataClient;

    let subject = admit(
        &api,
        &headers,
        "metadata:write",
        &format!("DELETE /v1/channels/{id}"),
    )?;
    let channel = dial(&api, "metadata")?;

    let result = MetadataClient::new(channel)
        .remove(RemoveRequest {
            scope: scope(),
            actor: operator_actor(subject, "metadata:write"),
            channel: id,
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner();

    if !result.applied {
        return Err(refuse(StatusCode::CONFLICT, &result.refused));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// One ACL entry, as JSON.
///
/// `grant` and `deny` are `Perm` bit sets. They stay numeric rather than
/// becoming name arrays because the numbers are what murmur's own ACL editor,
/// the wire protocol and the database all use, translating here would put a
/// name table in three places and make a new permission bit a change to all of
/// them.
#[derive(Debug, Serialize, Deserialize)]
struct AclEntryJson {
    #[serde(default)]
    apply_here: bool,
    #[serde(default)]
    apply_subs: bool,
    /// True when the entry comes from an ancestor. Read-only: sending an
    /// inherited entry back does not move it, and `SetAcl` writes only the
    /// entries that belong to this channel.
    #[serde(default)]
    inherited: bool,
    #[serde(default)]
    account: Option<u64>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    grant: u32,
    #[serde(default)]
    deny: u32,
}

/// One group, as JSON.
#[derive(Debug, Serialize, Deserialize)]
struct GroupJson {
    name: String,
    #[serde(default)]
    inherited: bool,
    #[serde(default)]
    inherit: bool,
    #[serde(default)]
    inheritable: bool,
    #[serde(default)]
    add: Vec<u64>,
    #[serde(default)]
    remove: Vec<u64>,
    #[serde(default)]
    inherited_members: Vec<u64>,
}

/// A channel's whole ACL, which is how it is always read and written.
#[derive(Debug, Serialize, Deserialize)]
struct AclJson {
    #[serde(default)]
    inherit: bool,
    #[serde(default)]
    acls: Vec<AclEntryJson>,
    #[serde(default)]
    groups: Vec<GroupJson>,
}

async fn get_acl(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(id): Path<u32>,
) -> Result<Json<AclJson>, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::permissions::AclRequest;
    use starling_proto_fancy::permissions::permissions_client::PermissionsClient;

    let _ = admit(
        &api,
        &headers,
        "permissions:read",
        &format!("GET /v1/channels/{id}/acl"),
    )?;
    let channel = dial(&api, "permissions")?;

    let set = PermissionsClient::new(channel)
        .get_acl(AclRequest {
            scope: scope(),
            channel: id,
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner();

    Ok(Json(AclJson {
        inherit: set.inherit,
        acls: set
            .acls
            .into_iter()
            .map(|a| AclEntryJson {
                apply_here: a.apply_here,
                apply_subs: a.apply_subs,
                inherited: a.inherited,
                account: a.account,
                group: a.group,
                grant: a.grant,
                deny: a.deny,
            })
            .collect(),
        groups: set
            .groups
            .into_iter()
            .map(|g| GroupJson {
                name: g.name,
                inherited: g.inherited,
                inherit: g.inherit,
                inheritable: g.inheritable,
                add: g.add,
                remove: g.remove,
                inherited_members: g.inherited_members,
            })
            .collect(),
    }))
}

/// Replace a channel's ACL.
///
/// A whole-object replace, unlike the field-list updates elsewhere in this
/// file, because that is what an ACL is: the entries are ordered and evaluated
/// as a sequence, so "change entry 3" is not a well-defined request. Read it,
/// edit it, write it back.
async fn set_acl(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path(id): Path<u32>,
    Json(body): Json<AclJson>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::permissions::permissions_client::PermissionsClient;
    use starling_proto_fancy::permissions::{AclEntry, AclSet, Group, SetAclRequest};

    let subject = admit(
        &api,
        &headers,
        "permissions:write",
        &format!("PUT /v1/channels/{id}/acl"),
    )?;
    let channel = dial(&api, "permissions")?;

    let result = PermissionsClient::new(channel)
        .set_acl(SetAclRequest {
            scope: scope(),
            actor: operator_actor(subject, "permissions:write"),
            acls: Some(AclSet {
                channel: id,
                inherit: body.inherit,
                acls: body
                    .acls
                    .into_iter()
                    // Inherited entries are shown on a read so an operator can
                    // see the effective set, and dropped on a write because
                    // they belong to an ancestor. Writing them back would
                    // copy an ancestor's rule into this channel, where it
                    // would then stop tracking the ancestor.
                    .filter(|a| !a.inherited)
                    .map(|a| AclEntry {
                        apply_here: a.apply_here,
                        apply_subs: a.apply_subs,
                        inherited: false,
                        account: a.account,
                        group: a.group,
                        grant: a.grant,
                        deny: a.deny,
                    })
                    .collect(),
                groups: body
                    .groups
                    .into_iter()
                    .filter(|g| !g.inherited)
                    .map(|g| Group {
                        name: g.name,
                        inherited: false,
                        inherit: g.inherit,
                        inheritable: g.inheritable,
                        add: g.add,
                        remove: g.remove,
                        inherited_members: Vec::new(),
                    })
                    .collect(),
            }),
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
        .into_inner();

    if !result.applied {
        return Err(refuse(StatusCode::CONFLICT, &result.refused));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Who is being put in, or taken out of, a group.
///
/// Exactly one of the two, and the distinction is the whole point of the
/// feature rather than a convenience. An `account` grant lasts until it is
/// removed; a `session` grant is tied to one live connection and is the only
/// way to put an **unregistered** user in a named group, since permanent
/// membership is recorded by account id and a guest has none.
#[derive(Debug, Deserialize)]
struct TemporaryMember {
    #[serde(default)]
    account: Option<u64>,
    #[serde(default)]
    session: Option<u32>,
}

impl TemporaryMember {
    /// The gRPC form, or the reason it is not a well-formed request.
    fn resolve(
        &self,
    ) -> Result<starling_proto_fancy::permissions::temporary_group_request::Member, &'static str>
    {
        use starling_proto_fancy::permissions::temporary_group_request::Member;
        match (self.account, self.session) {
            (Some(_), Some(_)) => {
                Err("name either an account or a session, not both: they are different grants")
            }
            (Some(account), None) => Ok(Member::Account(account)),
            (None, Some(session)) => Ok(Member::Session(session)),
            (None, None) => Err("name an account or a session"),
        }
    }
}

/// Put somebody in a group without editing the ACL table.
///
/// murmur's `addUserToGroup` (`MumbleServer.ice:728`), which Starling reaches
/// here because it has no Ice and never will (`GAP-ANALYSIS.md` S6).
///
/// **Not durable, deliberately**, upstream says so of its own ("This state is
/// not saved"), and a session-scoped grant that survived a restart would be
/// attached to a session id belonging to whoever connects next. It is an
/// external authority's live decision, not configuration.
async fn add_temporary_group(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path((id, group)): Path<(u32, String)>,
    Json(member): Json<TemporaryMember>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    temporary_group(api, headers, id, group, member, true).await
}

/// Take a temporary membership away again.
async fn remove_temporary_group(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Path((id, group)): Path<(u32, String)>,
    Json(member): Json<TemporaryMember>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    temporary_group(api, headers, id, group, member, false).await
}

/// Both directions, which differ only in the call they end in.
///
/// Written once because the two drifting apart is how a grant comes to be
/// validated differently from the revocation meant to undo it, and of the two,
/// the revocation failing is the dangerous one.
async fn temporary_group(
    api: Arc<OperatorApi>,
    headers: HeaderMap,
    id: u32,
    group: String,
    member: TemporaryMember,
    add: bool,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::permissions::TemporaryGroupRequest;
    use starling_proto_fancy::permissions::permissions_client::PermissionsClient;

    let verb = if add { "POST" } else { "DELETE" };
    let subject = admit(
        &api,
        &headers,
        "permissions:write",
        &format!("{verb} /v1/channels/{id}/groups/{group}/members"),
    )?;
    let member = member
        .resolve()
        .map_err(|why| refuse(StatusCode::BAD_REQUEST, why))?;
    let channel = dial(&api, "permissions")?;

    let request = TemporaryGroupRequest {
        scope: scope(),
        actor: operator_actor(subject, "permissions:write"),
        channel: id,
        group,
        member: Some(member),
    };
    let mut client = PermissionsClient::new(channel);
    let result = if add {
        client.add_temporary_group(request).await
    } else {
        client.remove_temporary_group(request).await
    }
    .map_err(|status| refuse(StatusCode::BAD_GATEWAY, status.message()))?
    .into_inner();

    if !result.applied {
        return Err(refuse(StatusCode::CONFLICT, &result.refused));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// A message from the server to connected users.
#[derive(Debug, Deserialize)]
struct NewMessage {
    #[serde(default)]
    sessions: Vec<u32>,
    #[serde(default)]
    channels: Vec<u32>,
    #[serde(default)]
    tree: bool,
    body: String,
    #[serde(default)]
    store: bool,
}

async fn send_message(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Json(message): Json<NewMessage>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    use starling_proto_fancy::text::AnnounceRequest;
    use starling_proto_fancy::text::text_client::TextClient;

    let subject = admit(&api, &headers, "text:write", "POST /v1/messages")?;
    let channel = dial(&api, "text")?;

    let result = TextClient::new(channel)
        .announce(AnnounceRequest {
            scope: scope(),
            actor: operator_actor(subject, "text:write"),
            sessions: message.sessions,
            channels: message.channels,
            tree: message.tree,
            body: message.body,
            store: message.store,
        })
        .await
        .map_err(|status| match status.code() {
            // `text` refuses an empty body or an unaddressed message, and both
            // are the caller's mistake, not a server fault.
            tonic::Code::InvalidArgument => refuse(StatusCode::BAD_REQUEST, status.message()),
            _ => refuse(StatusCode::BAD_GATEWAY, status.message()),
        })?
        .into_inner();

    // Nobody connected is reported, not refused: a notice to an offline user is
    // a normal outcome and the caller may well want to fall back to email.
    Ok(Json(serde_json::json!({
        "delivered": result.applied,
        "reason": result.refused,
    })))
}

async fn set_config(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
    Json(values): Json<serde_json::Value>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let _ = admit(&api, &headers, "server-config:write", "POST /v1/config")?;
    let channel = api
        .resolver()
        .channel("server-config")
        .map_err(|error| refuse(StatusCode::BAD_GATEWAY, &error.to_string()))?;

    // Every setting `server-config` accepts, not the two this used to know
    // about. An operator could not write `messagelimit`, `certrequired`,
    // `channelnestinglimit`, `logdays` or the obfuscation through the surface
    // built for exactly that, so the whole of `GAP-ANALYSIS.md` §5 could be
    // enforced by the server and still be unreachable.
    //
    // The mapping lives in `starling_runtime::settings` beside the defaults and
    // the field-wise merge, so a setting added there is settable here without a
    // second edit and the two cannot disagree about a name.
    let (mut snapshot, fields) = starling_runtime::settings::from_json(&values);
    snapshot.instance = 1;
    if fields.is_empty() {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "no settable configuration field was named",
        ));
    }

    let _ = ServerConfigClient::new(channel)
        .set(starling_proto_fancy::serverconfig::SetRequest {
            scope: Some(Scope { instance: 1 }),
            actor: None,
            fields,
            values: Some(snapshot),
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, &status.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Who the caller is, which is the cheapest way to check a credential works.
async fn whoami(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let subject = admit(&api, &headers, "*", "POST /v1/whoami")?;
    Ok(Json(serde_json::json!({ "subject": subject })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unauthenticated_call_is_distinguishable_from_an_unauthorised_one() {
        // 401 means "who are you"; 403 means "not you". Collapsing them sends
        // an operator to the wrong file.
        for (refusal, expected) in [
            (Refusal::Missing, StatusCode::UNAUTHORIZED),
            (Refusal::Malformed, StatusCode::UNAUTHORIZED),
            (Refusal::Rejected, StatusCode::FORBIDDEN),
            (Refusal::Unscoped, StatusCode::FORBIDDEN),
        ] {
            let status = match refusal {
                Refusal::Missing | Refusal::Malformed => StatusCode::UNAUTHORIZED,
                Refusal::Rejected | Refusal::Unscoped => StatusCode::FORBIDDEN,
            };
            assert_eq!(status, expected);
        }
    }
}
