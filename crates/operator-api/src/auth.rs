//! Authentication as a Strategy, chosen in the TOML.
//!
//! A new mode is a new implementation of [`Authenticator`], never a new arm in
//! a `match` — which is what lets an operator's existing identity provider
//! become the admin plane's without touching this crate
//! (`docs/ARCHITECTURE.md` §3, `DESIGN.md` §3).

use std::collections::BTreeMap;
use std::sync::Arc;

use starling_runtime::config::{AuthMode, OperatorAuth};

/// Who is calling, and what they may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The subject, as the credential names it. Recorded in the audit log, so
    /// an action attributes to a person rather than to a shared secret.
    pub subject: String,
    /// What this identity may do. `*` is everything.
    pub scopes: Vec<String>,
}

impl Identity {
    /// Whether this identity holds `scope`.
    #[must_use]
    pub fn allows(&self, scope: &str) -> bool {
        self.scopes
            .iter()
            .any(|held| held == "*" || held == scope || prefix_match(held, scope))
    }
}

/// `userdata:*` covers `userdata:read`.
fn prefix_match(held: &str, wanted: &str) -> bool {
    held.strip_suffix('*')
        .is_some_and(|prefix| wanted.starts_with(prefix))
}

/// Why a request was refused before it was even read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// No credential at all.
    #[error("no credential was presented")]
    Missing,
    /// A credential that is not the shape this mode expects.
    #[error("the credential is malformed")]
    Malformed,
    /// A credential that is genuine but not accepted here.
    #[error("the credential is not accepted by this server")]
    Rejected,
    /// A genuine credential with no scope this deployment maps.
    #[error("the credential carries no scopes this server recognises")]
    Unscoped,
}

/// What every mode implements.
pub trait Authenticator: std::fmt::Debug + Send + Sync {
    /// The mode's name, for logs and the `OpenAPI` description.
    fn mode(&self) -> &'static str;

    /// Identify a caller from its `Authorization` header.
    ///
    /// # Errors
    ///
    /// [`Refusal`] describing which rule the credential failed, so an operator
    /// debugging a 401 learns something from it.
    fn identify(&self, header: Option<&str>) -> Result<Identity, Refusal>;
}

/// Build the configured authenticator.
///
/// # Errors
///
/// A message when the mode is configured but its block is missing, or when a
/// static token names an environment variable that is not set — both are
/// startup failures rather than a surface that silently accepts nothing.
pub fn authenticator(config: OperatorAuth) -> Result<Arc<dyn Authenticator>, String> {
    match config.mode {
        AuthMode::Token => {
            let tokens = config
                .token
                .ok_or("mode = \"token\" needs a [services.operator-api.auth.token] block")?;
            let mut accepted = BTreeMap::new();
            for entry in tokens.tokens {
                let value = std::env::var(&entry.value_env).map_err(|_| {
                    format!(
                        "{} is not set; the admin token must come from the environment",
                        entry.value_env
                    )
                })?;
                let _ = accepted.insert(value, (entry.value_env, entry.scopes));
            }
            Ok(Arc::new(StaticTokens { accepted }))
        }
        AuthMode::Oidc => {
            let oidc = config
                .oidc
                .ok_or("mode = \"oidc\" needs a [services.operator-api.auth.oidc] block")?;
            Ok(Arc::new(ClaimMapped {
                mode: "oidc",
                map: oidc.map,
                issuer: oidc.issuer,
            }))
        }
        AuthMode::Jwt => {
            let jwt = config
                .jwt
                .ok_or("mode = \"jwt\" needs a [services.operator-api.auth.jwt] block")?;
            Ok(Arc::new(ClaimMapped {
                mode: "jwt",
                map: BTreeMap::new(),
                issuer: jwt.audience,
            }))
        }
        AuthMode::Mtls => {
            let mtls = config
                .mtls
                .ok_or("mode = \"mtls\" needs a [services.operator-api.auth.mtls] block")?;
            Ok(Arc::new(SubjectMapped { map: mtls.map }))
        }
    }
}

/// A static bearer token.
///
/// The weakest option: no identity beyond which token was used, and no expiry.
/// It exists so nobody reinvents `icesecret` badly.
#[derive(Debug)]
struct StaticTokens {
    accepted: BTreeMap<String, (String, Vec<String>)>,
}

impl Authenticator for StaticTokens {
    fn mode(&self) -> &'static str {
        "token"
    }

    fn identify(&self, header: Option<&str>) -> Result<Identity, Refusal> {
        let token = bearer(header)?;
        let (name, scopes) = self.accepted.get(token).ok_or(Refusal::Rejected)?;
        if scopes.is_empty() {
            return Err(Refusal::Unscoped);
        }
        Ok(Identity {
            // The variable's name, not its value: an audit record must never
            // contain the credential it is recording the use of.
            subject: format!("token:{name}"),
            scopes: scopes.clone(),
        })
    }
}

/// A JWT whose claims map to scopes.
///
/// The signature check belongs here and is deliberately not faked: until the
/// JWKS client exists this refuses every token rather than accepting one it has
/// not verified. A surface that accepts unverified tokens because verification
/// is "not built yet" is worse than one that is closed.
#[derive(Debug)]
struct ClaimMapped {
    mode: &'static str,
    map: BTreeMap<String, Vec<String>>,
    issuer: String,
}

impl Authenticator for ClaimMapped {
    fn mode(&self) -> &'static str {
        self.mode
    }

    fn identify(&self, header: Option<&str>) -> Result<Identity, Refusal> {
        let _token = bearer(header)?;
        tracing::warn!(
            mode = self.mode,
            issuer = %self.issuer,
            mapped_roles = self.map.len(),
            "refusing a token: signature verification is not built into this binary"
        );
        Err(Refusal::Rejected)
    }
}

/// A client certificate subject mapped to scopes.
#[derive(Debug)]
struct SubjectMapped {
    map: BTreeMap<String, Vec<String>>,
}

impl Authenticator for SubjectMapped {
    fn mode(&self) -> &'static str {
        "mtls"
    }

    fn identify(&self, header: Option<&str>) -> Result<Identity, Refusal> {
        // The subject arrives from the TLS terminator, which is the only thing
        // that has actually validated the chain.
        let subject = header.ok_or(Refusal::Missing)?;
        let scopes = self.map.get(subject).ok_or(Refusal::Unscoped)?;
        Ok(Identity {
            subject: subject.to_owned(),
            scopes: scopes.clone(),
        })
    }
}

/// The token out of a `Bearer` header.
fn bearer(header: Option<&str>) -> Result<&str, Refusal> {
    let header = header.ok_or(Refusal::Missing)?;
    header
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or(Refusal::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The token authenticator, built without touching the environment.
    ///
    /// `std::env::set_var` is `unsafe` in edition 2024 and this workspace denies
    /// `unsafe_code`, so the test builds the same type the loader builds rather
    /// than staging a variable for it to read.
    fn token_auth() -> Arc<dyn Authenticator> {
        Arc::new(StaticTokens {
            accepted: BTreeMap::from([(
                "s3cret".to_owned(),
                (
                    "STARLING_TEST_ADMIN_TOKEN".to_owned(),
                    vec!["userdata:*".to_owned()],
                ),
            )]),
        })
    }

    #[test]
    fn a_valid_token_identifies_by_its_variable_and_never_its_value() {
        // An audit record must not contain the credential whose use it records.
        let identity = token_auth()
            .identify(Some("Bearer s3cret"))
            .expect("the configured token is accepted");
        assert_eq!(identity.subject, "token:STARLING_TEST_ADMIN_TOKEN");
        assert!(!identity.subject.contains("s3cret"));
    }

    #[test]
    fn a_missing_or_malformed_credential_is_distinguishable_from_a_wrong_one() {
        // An operator debugging a 401 needs to know which of the three it is.
        let auth = token_auth();
        assert_eq!(auth.identify(None), Err(Refusal::Missing));
        assert_eq!(auth.identify(Some("s3cret")), Err(Refusal::Malformed));
        assert_eq!(auth.identify(Some("Bearer wrong")), Err(Refusal::Rejected));
    }

    #[test]
    fn a_token_with_no_scopes_is_refused_rather_than_admitted_as_harmless() {
        let auth = StaticTokens {
            accepted: BTreeMap::from([("s3cret".to_owned(), ("VAR".to_owned(), Vec::new()))]),
        };
        assert_eq!(auth.identify(Some("Bearer s3cret")), Err(Refusal::Unscoped));
    }

    #[test]
    fn a_wildcard_scope_covers_the_operations_beneath_it() {
        let identity = Identity {
            subject: "op".to_owned(),
            scopes: vec!["userdata:*".to_owned()],
        };
        assert!(identity.allows("userdata:read"));
        assert!(!identity.allows("metadata:write"));
    }

    #[test]
    fn an_unverifiable_token_is_refused_rather_than_trusted() {
        // Accepting an unverified token because verification is not built yet
        // would be worse than being closed.
        let auth = authenticator(OperatorAuth {
            mode: AuthMode::Oidc,
            oidc: Some(starling_runtime::config::OidcAuth {
                issuer: "https://idp.example.org".to_owned(),
                audience: "starling-admin".to_owned(),
                scope_claim: "roles".to_owned(),
                map: BTreeMap::new(),
            }),
            ..OperatorAuth::default()
        })
        .expect("an oidc authenticator");
        assert_eq!(
            auth.identify(Some("Bearer anything")),
            Err(Refusal::Rejected)
        );
    }

    #[test]
    fn a_mode_configured_without_its_block_fails_at_startup() {
        // The alternative is a surface that silently accepts nothing, which
        // looks like a network problem for as long as it takes to find.
        assert!(
            authenticator(OperatorAuth {
                mode: AuthMode::Oidc,
                ..OperatorAuth::default()
            })
            .is_err()
        );
    }

    #[test]
    fn a_client_certificate_subject_maps_to_the_scopes_configured_for_it() {
        let auth = SubjectMapped {
            map: BTreeMap::from([("CN=admin-console".to_owned(), vec!["*".to_owned()])]),
        };
        let identity = auth
            .identify(Some("CN=admin-console"))
            .expect("a mapped subject");
        assert!(identity.allows("anything:at-all"));
        assert_eq!(auth.identify(Some("CN=stranger")), Err(Refusal::Unscoped));
    }
}
