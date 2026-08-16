//! The service account, and the assertion it signs to buy an access token.
//!
//! Google does not hand out a long-lived key for FCM. The credentials file is
//! an RSA private key and an address; what it authenticates is a short JWT the
//! server signs itself and exchanges, once an hour, for a bearer token. So this
//! file is the whole of the credential handling: read the file, sign the
//! assertion, and say clearly which of the two failed.
//!
//! Nothing here does I/O beyond reading the credentials file once. The exchange
//! is in [`crate::fcm`], with the rest of the outbound HTTP, which leaves the
//! part that can be tested without a network testable without one.

use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};

/// Where an assertion is exchanged for an access token.
pub(crate) const TOKEN_HOST: &str = "oauth2.googleapis.com";

/// The path on [`TOKEN_HOST`].
pub(crate) const TOKEN_PATH: &str = "/token";

/// The audience the assertion names, which is the endpoint it is sent to.
const AUDIENCE: &str = "https://oauth2.googleapis.com/token";

/// The one scope this needs. Anything broader would be a key that can do more
/// than send notifications sitting in the deployment's configuration.
const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// How long the assertion claims to be good for. Google caps the token it
/// returns at an hour regardless, so asking for more buys nothing.
pub(crate) const ASSERTION_LIFETIME: Duration = Duration::from_secs(3600);

/// Base64url, unpadded: what a JWT is made of, in all three positions.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Why the credentials could not be used.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The file is not there, or not a file.
    ///
    /// Separate from [`Self::Unreadable`] because it is the mistake operators
    /// actually make -- a path that names a directory, or one that is right on
    /// the host and wrong inside the container.
    #[error("the push credentials at {path} are not a regular file")]
    NotAFile {
        /// Where they were looked for.
        path: String,
    },
    /// The file is there and could not be read.
    #[error("reading the push credentials at {path}: {reason}")]
    Unreadable {
        /// Where they were looked for.
        path: String,
        /// What the filesystem said.
        reason: String,
    },
    /// It is not the JSON a service-account key is.
    #[error("the push credentials are not a service-account key: {0}")]
    Malformed(String),
    /// The private key inside it is not one that can sign.
    #[error("the private key in the push credentials was rejected: {0}")]
    Key(String),
    /// Signing failed, which at this point means the key is unusable.
    #[error("signing the authentication assertion failed")]
    Signing,
}

/// A Google service account: an address, and the key that proves it.
#[derive(Debug)]
pub struct ServiceAccount {
    /// The project named by the credentials file, which is what the deployment
    /// is talking to unless the configuration overrides it.
    project: Option<String>,
    /// `client_email`: both issuer and subject of every assertion.
    client_email: String,
    /// `private_key`, parsed. RSA, because that is what Google issues.
    key: RsaKeyPair,
    /// Padding randomness. Held rather than made per signature; making one is
    /// not free and this signs once an hour forever.
    rng: SystemRandom,
}

impl ServiceAccount {
    /// Read a service-account key from disk.
    ///
    /// # Errors
    ///
    /// [`CredentialError`] when the path is not a readable file, is not the
    /// JSON a service-account key is, or carries a key that cannot sign.
    pub fn load(path: &Path) -> Result<Self, CredentialError> {
        let shown = path.display().to_string();
        // Checked before reading rather than after failing, so the message for
        // "you pointed this at a directory" is that sentence and not a parse
        // error about byte zero.
        let metadata = std::fs::metadata(path).map_err(|error| CredentialError::Unreadable {
            path: shown.clone(),
            reason: error.to_string(),
        })?;
        if !metadata.is_file() {
            return Err(CredentialError::NotAFile { path: shown });
        }
        let json = std::fs::read_to_string(path).map_err(|error| CredentialError::Unreadable {
            path: shown,
            reason: error.to_string(),
        })?;
        Self::from_json(&json)
    }

    /// Parse a service-account key.
    ///
    /// # Errors
    ///
    /// [`CredentialError`] when a field is missing or the key is unusable.
    pub fn from_json(json: &str) -> Result<Self, CredentialError> {
        let document: serde_json::Value = serde_json::from_str(json)
            .map_err(|error| CredentialError::Malformed(error.to_string()))?;
        let string = |key: &str| document.get(key).and_then(serde_json::Value::as_str);
        let client_email = string("client_email")
            .ok_or_else(|| CredentialError::Malformed("no client_email".to_owned()))?;
        let private_key = string("private_key")
            .ok_or_else(|| CredentialError::Malformed("no private_key".to_owned()))?;

        // The PEM is PKCS#8, which is what `RsaKeyPair` wants -- in DER, so the
        // armour comes off here. `rustls_pemfile` rather than a hand-rolled
        // strip: the key is one line of the JSON with `\n` escapes in it, and
        // getting that wrong silently yields a key that rejects every signature.
        let mut reader = std::io::BufReader::new(private_key.as_bytes());
        let der = rustls_pemfile::private_key(&mut reader)
            .map_err(|error| CredentialError::Key(error.to_string()))?
            .ok_or_else(|| CredentialError::Key("no private key in the PEM".to_owned()))?;
        let key = RsaKeyPair::from_pkcs8(der.secret_der())
            .map_err(|error| CredentialError::Key(error.to_string()))?;

        Ok(Self {
            project: string("project_id").map(str::to_owned),
            client_email: client_email.to_owned(),
            key,
            rng: SystemRandom::new(),
        })
    }

    /// The project the credentials belong to, when they say.
    #[must_use]
    pub fn project(&self) -> Option<&str> {
        self.project.as_deref()
    }

    /// A signed assertion, good from `issued_at` (seconds since the epoch, on
    /// *Google's* clock) for the assertion lifetime.
    ///
    /// The caller passes the time rather than this reading the clock, because
    /// the clock this has to agree with is not necessarily the local one; see
    /// [`crate::fcm::Fcm`] for the skew correction that produces the argument.
    ///
    /// # Errors
    ///
    /// [`CredentialError::Signing`] when the key cannot sign, which at this
    /// point is a broken key and not a transient failure.
    pub fn assertion(&self, issued_at: u64) -> Result<String, CredentialError> {
        let expires = issued_at.saturating_add(ASSERTION_LIFETIME.as_secs());
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
        let claims = serde_json::json!({
            "iss": self.client_email,
            "sub": self.client_email,
            "aud": AUDIENCE,
            "scope": SCOPE,
            "iat": issued_at,
            "exp": expires,
        });
        let signed = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );

        let mut signature = vec![0_u8; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &self.rng,
                signed.as_bytes(),
                &mut signature,
            )
            .map_err(|_| CredentialError::Signing)?;

        Ok(format!("{signed}.{}", B64.encode(&signature)))
    }
}

/// The form body that exchanges an assertion for a token.
#[must_use]
pub(crate) fn exchange_body(assertion: &str) -> String {
    // The grant type is percent-encoded by hand because it is a constant: it
    // is the only value here that needs it, and the assertion never does --
    // base64url has no character a form body would change.
    format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway 2048-bit key in the shape Google ships one: PKCS#8 PEM,
    /// inside a JSON string, escapes and all.
    fn credentials() -> String {
        let pem = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/service-account-key.pem"
        ))
        .expect("the test key");
        serde_json::json!({
            "type": "service_account",
            "project_id": "starling-test",
            "client_email": "push@starling-test.iam.gserviceaccount.com",
            "private_key": pem,
        })
        .to_string()
    }

    #[test]
    fn a_service_account_key_parses_into_something_that_can_sign() {
        let account = ServiceAccount::from_json(&credentials()).expect("the key parses");
        assert_eq!(account.project(), Some("starling-test"));

        let assertion = account.assertion(1_700_000_000).expect("it signs");
        let parts: Vec<_> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3, "a JWT is three dot-separated parts");

        let claims: serde_json::Value =
            serde_json::from_slice(&B64.decode(parts[1]).expect("base64url claims"))
                .expect("json claims");
        assert_eq!(claims["aud"], AUDIENCE);
        assert_eq!(claims["scope"], SCOPE);
        assert_eq!(claims["iat"], 1_700_000_000_u64);
        // The window is what makes a signed assertion a credential rather than
        // a password: an hour, from the time the caller passed in.
        assert_eq!(claims["exp"], 1_700_003_600_u64);
        assert_eq!(
            claims["iss"], "push@starling-test.iam.gserviceaccount.com",
            "issuer and subject are both the service account"
        );
    }

    #[test]
    fn credentials_missing_a_field_are_refused_by_name() {
        // The failure to avoid is a server that starts, looks configured, and
        // never sends anything.
        let without_key = serde_json::json!({ "client_email": "a@b.example" }).to_string();
        assert!(matches!(
            ServiceAccount::from_json(&without_key),
            Err(CredentialError::Malformed(reason)) if reason.contains("private_key")
        ));

        let without_email =
            serde_json::json!({ "private_key": "-----BEGIN PRIVATE KEY-----" }).to_string();
        assert!(matches!(
            ServiceAccount::from_json(&without_email),
            Err(CredentialError::Malformed(reason)) if reason.contains("client_email")
        ));
    }

    #[test]
    fn a_path_that_is_not_a_file_says_so_rather_than_failing_to_parse() {
        let error = ServiceAccount::load(Path::new("/")).expect_err("a directory is not a key");
        assert!(matches!(error, CredentialError::NotAFile { .. }));
    }

    #[test]
    fn the_exchange_body_encodes_the_grant_type_and_leaves_the_assertion_alone() {
        let body = exchange_body("aaa.bbb.ccc");
        assert!(body.contains("grant-type%3Ajwt-bearer"), "{body}");
        assert!(body.ends_with("assertion=aaa.bbb.ccc"), "{body}");
    }
}
