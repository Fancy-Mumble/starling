//! The `OpenAPI` description.
//!
//! Hand-written rather than derived, for the same reason the surface is HTTP at
//! all: it is the contract an admin client is written against, and it should be
//! reviewable as a document rather than assembled from attributes scattered
//! across handlers.

/// Every operation: path, method, summary, and the scope it needs.
///
/// Grouped by path when rendered, because `paths` is a JSON object keyed by
/// path — emitting one entry per method would repeat the key, and a generator
/// reading that keeps whichever it saw last.
const OPERATIONS: &[(&str, &str, &str, &str)] = &[
    (
        "/v1/accounts",
        "get",
        "List registered accounts; ?name= is an exact lookup, ?prefix= a scan",
        "userdata:read",
    ),
    (
        "/v1/accounts",
        "post",
        "Register an account",
        "userdata:write",
    ),
    (
        "/v1/accounts/{id}",
        "put",
        "Change an account; id 0 is the SuperUser, so this sets its password",
        "userdata:write",
    ),
    (
        "/v1/accounts/{id}",
        "delete",
        "Delete an account",
        "userdata:write",
    ),
    (
        "/v1/accounts/{id}/texture",
        "get",
        "Read an account's avatar as raw bytes",
        "userdata:read",
    ),
    (
        "/v1/accounts/{id}/texture",
        "put",
        "Replace an account's avatar with the raw request body",
        "userdata:write",
    ),
    (
        "/v1/accounts/{id}/texture",
        "delete",
        "Remove an account's avatar",
        "userdata:write",
    ),
    (
        "/v1/accounts/{id}/comment",
        "get",
        "Read an account's comment as text; absent reads as empty",
        "userdata:read",
    ),
    (
        "/v1/accounts/{id}/comment",
        "put",
        "Replace an account's comment with the request body",
        "userdata:write",
    ),
    ("/v1/bans", "get", "List bans", "moderation:read"),
    (
        "/v1/channels",
        "get",
        "The channel tree, unfiltered by any viewer's permissions",
        "metadata:read",
    ),
    ("/v1/channels", "post", "Create a channel", "metadata:write"),
    (
        "/v1/channels/{id}",
        "put",
        "Change named fields of a channel",
        "metadata:write",
    ),
    (
        "/v1/channels/{id}",
        "delete",
        "Remove a channel and its subchannels",
        "metadata:write",
    ),
    (
        "/v1/channels/{id}/acl",
        "get",
        "Read a channel's ACL and groups, including inherited entries",
        "permissions:read",
    ),
    (
        "/v1/channels/{id}/acl",
        "put",
        "Replace a channel's ACL and groups; inherited entries are ignored",
        "permissions:write",
    ),
    (
        "/v1/channels/{id}/groups/{group}/members",
        "post",
        "Put an account or a live session in a group without editing the ACL table; \
         not durable, and a session grant ends with the session",
        "permissions:write",
    ),
    (
        "/v1/channels/{id}/groups/{group}/members",
        "delete",
        "Take a temporary group membership away",
        "permissions:write",
    ),
    (
        "/v1/config",
        "get",
        "Read operational settings",
        "server-config:read",
    ),
    (
        "/v1/config",
        "post",
        "Change operational settings",
        "server-config:write",
    ),
    (
        "/v1/messages",
        "post",
        "Send a message from the server to sessions or channels",
        "text:write",
    ),
    (
        "/v1/sessions",
        "get",
        "Who is connected, and where",
        "session-view:read",
    ),
    (
        "/v1/events",
        "get",
        "Upgrade to the live channel: what changed, as it changes",
        "session-view:read",
    ),
    ("/v1/whoami", "post", "Identify the caller", "*"),
];

/// The description, as JSON.
#[must_use]
pub fn description() -> String {
    let mut body = String::from(
        "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Starling operator API\",\"version\":\"1\"},\
         \"components\":{\"securitySchemes\":{\"bearer\":{\"type\":\"http\",\"scheme\":\"bearer\"}}},\
         \"paths\":{",
    );

    let mut seen: Vec<&str> = Vec::new();
    let mut first_path = true;
    for (path, _, _, _) in OPERATIONS {
        if seen.contains(path) {
            continue;
        }
        seen.push(path);

        if !first_path {
            body.push(',');
        }
        first_path = false;
        body.push_str(&format!("\"{path}\":{{"));

        let mut first_method = true;
        for (other, method, summary, scope) in OPERATIONS {
            if other != path {
                continue;
            }
            if !first_method {
                body.push(',');
            }
            first_method = false;
            body.push_str(&format!(
                "\"{method}\":{{\"summary\":\"{summary}\",\
                  \"security\":[{{\"bearer\":[\"{scope}\"]}}],\
                  \"responses\":{{\"200\":{{\"description\":\"ok\"}},\
                  \"401\":{{\"description\":\"no credential\"}},\
                  \"403\":{{\"description\":\"insufficient scope\"}},\
                  \"503\":{{\"description\":\"the action could not be recorded\"}}}}}}"
            ));
        }
        body.push('}');
    }
    body.push_str("}}");
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_description_names_the_scope_each_operation_needs() {
        // An admin client author should not have to read the source to learn
        // which scope a call takes.
        let description = description();
        assert!(description.contains("userdata:read"));
        assert!(description.contains("server-config:write"));
    }

    #[test]
    fn the_description_documents_the_fail_closed_audit_response() {
        // 503 for "not recorded" is part of the contract, not an accident.
        assert!(description().contains("could not be recorded"));
    }

    #[test]
    fn every_method_on_a_path_survives_into_one_object() {
        // `paths` is keyed by path, so a path emitted once per method loses
        // every method but the last — and silently, because duplicate keys are
        // not a parse error. This is the document a client is generated from.
        let parsed: serde_json::Value =
            serde_json::from_str(&description()).expect("the description is valid JSON");
        let paths = parsed["paths"].as_object().expect("paths is an object");

        for (path, method, _, _) in OPERATIONS {
            assert!(
                paths[*path].get(*method).is_some(),
                "{method} {path} is missing from the description"
            );
        }
        // And the grouping is what makes that possible: one key per path.
        let distinct = OPERATIONS
            .iter()
            .map(|(path, _, _, _)| *path)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(paths.len(), distinct.len());
    }
}
