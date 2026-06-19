//! The `OpenAPI` description.
//!
//! Hand-written rather than derived, for the same reason the surface is HTTP at
//! all: it is the contract an admin client is written against, and it should be
//! reviewable as a document rather than assembled from attributes scattered
//! across handlers.

/// The description, as JSON.
#[must_use]
pub fn description() -> String {
    let paths = [
        (
            "/v1/accounts",
            "get",
            "List registered accounts",
            "userdata:read",
        ),
        (
            "/v1/accounts",
            "post",
            "Register an account",
            "userdata:write",
        ),
        ("/v1/bans", "get", "List bans", "moderation:read"),
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
        ("/v1/whoami", "post", "Identify the caller", "*"),
    ];

    let mut body = String::from(
        "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Starling operator API\",\"version\":\"1\"},\
         \"components\":{\"securitySchemes\":{\"bearer\":{\"type\":\"http\",\"scheme\":\"bearer\"}}},\
         \"paths\":{",
    );
    let mut first = true;
    for (path, method, summary, scope) in paths {
        if !first {
            body.push(',');
        }
        first = false;
        body.push_str(&format!(
            "\"{path}\":{{\"{method}\":{{\"summary\":\"{summary}\",\
              \"security\":[{{\"bearer\":[\"{scope}\"]}}],\
              \"responses\":{{\"200\":{{\"description\":\"ok\"}},\
              \"401\":{{\"description\":\"no credential\"}},\
              \"403\":{{\"description\":\"insufficient scope\"}},\
              \"503\":{{\"description\":\"the action could not be recorded\"}}}}}}}}"
        ));
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
}
