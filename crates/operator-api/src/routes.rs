//! The REST surface.
//!
//! Every handler does the same three things in the same order: identify the
//! caller, check the scope the operation needs, and record the action before
//! answering. The order matters — a record written after the answer is a record
//! that can be missing for an action that happened.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
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
        .route("/v1/bans", get(list_bans))
        .route("/v1/config", get(get_config).post(set_config))
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

/// Identify, authorise and record — in that order.
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

/// One account, as JSON.
#[derive(Debug, Serialize, Deserialize)]
struct AccountJson {
    id: u64,
    name: String,
    email: String,
}

impl From<Account> for AccountJson {
    fn from(account: Account) -> Self {
        Self {
            id: account.id,
            name: account.name,
            email: account.email,
        }
    }
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
/// `Option` per field rather than `String`: "not mentioned" and "set to empty"
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
    /// Which virtual server the account belongs to. Defaults to the first.
    #[serde(default)]
    virtual_server: Option<u32>,
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
        fields
    }
}

async fn list_accounts(
    State(api): State<Arc<OperatorApi>>,
    headers: HeaderMap,
) -> Result<Json<Vec<AccountJson>>, (StatusCode, Json<ApiError>)> {
    let _ = admit(&api, &headers, "userdata:read", "GET /v1/accounts")?;
    let channel = api
        .resolver()
        .channel("userdata")
        .map_err(|error| refuse(StatusCode::BAD_GATEWAY, &error.to_string()))?;

    let page = UserDataClient::new(channel)
        .list(ListRequest {
            scope: Some(Scope { virtual_server: 1 }),
            name_prefix: String::new(),
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
            scope: Some(Scope { virtual_server: 1 }),
            actor: None,
            account: Some(Account {
                name: new.name,
                email: new.email,
                ..Account::default()
            }),
            password: new.password,
        })
        .await
        .map_err(|status| refuse(StatusCode::CONFLICT, status.message()))?;

    Ok(Json(AccountJson::from(account.into_inner())))
}

/// Change named fields of one account.
///
/// Only the fields present in the body are written, which is what makes this a
/// general edit rather than a whole-object replace: two operators changing
/// different settings must not silently overwrite each other, and userdata
/// enforces that with an explicit field list rather than by diffing.
///
/// **This is also how the SuperUser password is set** — the administrator is
/// simply account `0`:
///
/// ```text
/// PUT /v1/accounts/0  {"password":"…"}
/// ```
///
/// There is deliberately no separate superuser route. One would be this endpoint
/// with a hard-coded id, and it would drift: a change to how a password is
/// written here would have to be remembered there.
///
/// The account has to exist. For the administrator it always does — userdata
/// creates it on first boot — but a userdata database restored from before that
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
    // are different, so they are distinguished rather than both defaulted.
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
            "no fields to change; send at least one of password, name, email",
        ));
    }

    let scope = Some(Scope {
        virtual_server: change.virtual_server.unwrap_or(1),
    });
    let channel = api
        .resolver()
        .channel("userdata")
        .map_err(|error| refuse(StatusCode::BAD_GATEWAY, &error.to_string()))?;
    let mut userdata = UserDataClient::new(channel);

    // Asked about before it is changed, so a missing id is a 404 rather than the
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
            scope: Some(Scope { virtual_server: 1 }),
            actor: None,
            id,
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, &status.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
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
        .list_bans(Scope { virtual_server: 1 })
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
            scope: Some(Scope { virtual_server: 1 }),
        })
        .await
        .map_err(|status| refuse(StatusCode::BAD_GATEWAY, &status.to_string()))?
        .into_inner();

    // The password is not read back, here or anywhere.
    Ok(Json(serde_json::json!({
        "version": snapshot.version,
        "welcome_text": snapshot.welcome_text,
        "max_users": snapshot.max_users,
        "max_bandwidth": snapshot.max_bandwidth,
        "message_limit": snapshot.message_limit,
        "message_burst": snapshot.message_burst,
        "allow_html": snapshot.allow_html,
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

    let mut snapshot = starling_proto_fancy::serverconfig::Snapshot {
        virtual_server: 1,
        ..starling_proto_fancy::serverconfig::Snapshot::default()
    };
    let mut fields = Vec::new();
    if let Some(text) = values.get("welcome_text").and_then(|v| v.as_str()) {
        snapshot.welcome_text = text.to_owned();
        fields.push("welcome_text".to_owned());
    }
    if let Some(users) = values.get("max_users").and_then(serde_json::Value::as_u64) {
        snapshot.max_users = users as u32;
        fields.push("max_users".to_owned());
    }

    let _ = ServerConfigClient::new(channel)
        .set(starling_proto_fancy::serverconfig::SetRequest {
            scope: Some(Scope { virtual_server: 1 }),
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
