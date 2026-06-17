//! Authentication for the admin plane, which is a Strategy chosen in the TOML.
//!
//! The operator surface can create users, rewrite ACLs, ban and read the
//! database — the highest-privilege plane in the system. So authentication is
//! **whatever the operator already runs** rather than something we invent, and
//! a new mode is a new implementation rather than a new arm in a `match`
//! (`docs/ARCHITECTURE.md` §3).
//!
//! Against Ice, which this replaces: `icesecret` is one static string that *is*
//! the identity, has no scope, and rotates by editing a file and restarting.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Which authentication strategy the admin plane uses.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct OperatorAuth {
    /// `oidc` | `jwt` | `mtls` | `token`.
    pub mode: AuthMode,
    /// Keycloak, Authentik, Auth0, Entra: a JWT validated against the issuer's
    /// JWKS, so key rotation needs no restart.
    pub oidc: Option<OidcAuth>,
    /// A bare token signed by a key you hold, for setups without an `IdP`.
    pub jwt: Option<JwtAuth>,
    /// Client certificates, when a PKI already exists.
    pub mtls: Option<MtlsAuth>,
    /// A static bearer token. The weakest option: no identity, no expiry. It
    /// exists so nobody reinvents `icesecret` badly.
    pub token: Option<TokenAuth>,
}

impl Default for OperatorAuth {
    fn default() -> Self {
        Self {
            mode: AuthMode::Token,
            oidc: None,
            jwt: None,
            mtls: None,
            token: None,
        }
    }
}

/// The four modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// An `OpenID` Connect provider.
    Oidc,
    /// A JWT signed by a key in the configuration.
    Jwt,
    /// Client certificates.
    Mtls,
    /// A static bearer token.
    #[default]
    Token,
}

/// `OpenID` Connect.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct OidcAuth {
    /// The issuer URL; its JWKS is discovered from here.
    pub issuer: String,
    /// The audience every accepted token must carry.
    pub audience: String,
    /// Which claim carries authorisation.
    pub scope_claim: String,
    /// An existing `IdP` role becomes a Starling authorisation, without code.
    pub map: BTreeMap<String, Vec<String>>,
}

/// A self-signed JWT.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct JwtAuth {
    /// PEM public key the token is verified against.
    pub public_key: PathBuf,
    /// The audience every accepted token must carry.
    pub audience: String,
    /// Which claim carries the scopes.
    pub scope_claim: String,
}

/// Client certificates.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct MtlsAuth {
    /// The CA client certificates are validated against.
    pub client_ca: PathBuf,
    /// Certificate subject to scopes.
    pub map: BTreeMap<String, Vec<String>>,
}

/// Static bearer tokens.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct TokenAuth {
    /// Each entry names an environment variable rather than holding the secret,
    /// so a configuration file can be committed and a secret cannot.
    pub tokens: Vec<StaticToken>,
}

/// One static token.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct StaticToken {
    /// The environment variable holding the value.
    pub value_env: String,
    /// What this token may do. `*` is everything.
    pub scopes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idp_role_maps_to_scopes_without_code() {
        let auth: OperatorAuth = toml::from_str(
            r#"
            mode = "oidc"
            [oidc]
            issuer = "https://keycloak.example.org/realms/starling"
            audience = "starling-admin"
            scope_claim = "roles"
            [oidc.map]
            "starling-auditor" = ["userdata:read", "audit:read"]
            "#,
        )
        .expect("documented shape must parse");

        assert_eq!(auth.mode, AuthMode::Oidc);
        let oidc = auth.oidc.expect("oidc block");
        assert_eq!(
            oidc.map.get("starling-auditor").map(Vec::as_slice),
            Some(["userdata:read".to_owned(), "audit:read".to_owned()].as_slice())
        );
    }

    #[test]
    fn a_static_token_names_an_environment_variable_never_a_secret() {
        let auth: OperatorAuth = toml::from_str(
            r#"
            mode = "token"
            [token]
            tokens = [{ value_env = "STARLING_ADMIN_TOKEN", scopes = ["*"] }]
            "#,
        )
        .expect("documented shape must parse");
        let tokens = auth.token.expect("token block").tokens;
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].value_env, "STARLING_ADMIN_TOKEN");
    }
}
