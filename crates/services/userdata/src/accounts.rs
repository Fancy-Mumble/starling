//! The account store: typed columns, the indexes its queries need, and the
//! in-memory cache authentication reads from.
//!
//! `docs/STORAGE.md` L1 and L2 in one table, no entity-attribute-value rows,
//! a unique index on the name and one on the certificate hash, because those
//! are exactly the two lookups authentication performs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use starling_proto_fancy::identity;
use starling_proto_fancy::userdata::{
    Account, AccountPage, AuthRequest, AuthResult, BlobRef, UpdateRequest, auth_result,
};
use starling_runtime::ids::now_ms;
use starling_runtime::names::{NameRule, is_user_name};
use starling_runtime::settings::{Settings, USER_NAME_PATTERN};
use starling_runtime::storage::{Migration, Store, StoreError};

use crate::secret::{Secret, verify_totp};

/// How many characters a generated SuperUser password has.
///
/// Twenty from a 56-character alphabet is about 116 bits, which is far past
/// anything that matters, the length is chosen for what it *cannot* be, namely
/// short enough for somebody to decide it is fine to leave as it is.
const GENERATED_PASSWORD_LEN: usize = 20;

/// The alphabet a generated password is drawn from.
///
/// No `0`/`O`, `1`/`l`/`I`: this is read off a terminal and typed into a client
/// by hand, and a password that cannot be transcribed reliably gets replaced by
/// a short one the operator chose instead.
const PASSWORD_ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// A fresh SuperUser password.
fn generated_password() -> String {
    use rand::RngExt as _;
    let mut rng = rand::rng();
    (0..GENERATED_PASSWORD_LEN)
        .map(|_| char::from(PASSWORD_ALPHABET[rng.random_range(0..PASSWORD_ALPHABET.len())]))
        .collect()
}

/// The schema.
const SCHEMA: &[Migration<'static>] = &[Migration::new(
    "0001_account",
    &[
        "CREATE TABLE IF NOT EXISTS account (\
             server_id BIGINT NOT NULL, id BIGINT NOT NULL, \
             name VARCHAR(190) NOT NULL, email VARCHAR(190) NOT NULL, \
             cert_hash BLOB NULL, password BLOB NULL, totp_secret BLOB NULL, \
             texture_hash BLOB NULL, comment_hash BLOB NULL, \
             created_at_ms BIGINT NOT NULL, last_active_ms BIGINT NOT NULL, \
             PRIMARY KEY (server_id, id))",
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_account_name ON account(server_id, name)",
        "CREATE INDEX IF NOT EXISTS ix_account_cert ON account(server_id, cert_hash)",
        "CREATE TABLE IF NOT EXISTS blob (\
             hash BLOB NOT NULL PRIMARY KEY, bytes BLOB NOT NULL, \
             size BIGINT NOT NULL, refs BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS account_setting (\
             server_id BIGINT NOT NULL, account_id BIGINT NOT NULL, \
             k VARCHAR(190) NOT NULL, v TEXT NOT NULL, \
             PRIMARY KEY (server_id, account_id, k))",
    ],
)];

/// One account as a migration hands it over.
///
/// Deliberately not [`Account`]: that is the wire type, and three of the things
/// an import must carry never appear on a wire. The password is one (it is a
/// stored hash, not a plaintext), the TOTP secret is another (it never leaves
/// the server), and the comment and avatar are the third -- they arrive as
/// *bytes* here and are content-addressed on the way in, whereas the wire only
/// ever names them by hash.
#[derive(Debug, Clone, Default)]
pub struct Import {
    /// The id murmur gave this account. Kept, see [`Accounts::import`].
    pub id: u64,
    /// The registered name.
    pub name: String,
    /// The address, if the account has one.
    pub email: String,
    /// The profile text, as bytes to store rather than as a hash.
    pub comment: String,
    /// The certificate fingerprint, decoded from murmur's hex.
    pub cert_hash: Vec<u8>,
    /// The stored password, in whatever form murmur left it.
    pub password: Option<Secret>,
    /// The second factor's shared secret, decoded from base32.
    pub totp_secret: Option<Vec<u8>>,
    /// The avatar, as bytes to store.
    pub texture: Vec<u8>,
    /// When the account was created, as far as murmur recorded it.
    pub created_at_ms: u64,
    /// When it was last seen.
    pub last_active_ms: u64,
}

/// Accounts, cached in memory and written through.
#[derive(Debug, Clone)]
pub struct Accounts {
    store: Store,
    cache: Arc<Mutex<HashMap<(u32, u64), Record>>>,
    next_id: Arc<Mutex<u64>>,
    /// The operator's `user_name_regex`, compiled once and re-used.
    ///
    /// Here rather than in the service above because the rule has four callers
    /// that each decide a name, login, registration, an administrator's rename
    /// and a user's own, and murmur checks all four
    /// (`Messages.cpp:428`, `:3220`, `:4918`, `Server.cpp:3372`). A check in the
    /// service would be a check each of those four could forget, and three of
    /// them do not go through the service at all.
    names: Arc<NameRule>,
    /// Where the live pattern is read from, when this is running in a server.
    ///
    /// `None` for the callers that have no `server-config` to ask, the first-run
    /// path, the `set-superuser-password` command and the tests. Those fall back
    /// to murmur's own pattern rather than to "no rule": a name this build would
    /// refuse at login must not be creatable from the command line either.
    settings: Option<Settings>,
}

#[derive(Debug, Clone)]
struct Record {
    account: Account,
    password: Option<Secret>,
    totp: Option<Vec<u8>>,
}

/// What the peer has already proved by the time the password is considered.
///
/// The distinction matters only in one case, and that case is a security hole:
/// an account with no stored password. Reached by certificate that is fine, the
/// certificate *was* the proof. Reached by name it is not, and the two paths are
/// otherwise identical enough to be confused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proof {
    /// The certificate matched this account.
    Certificate,
    /// Only a name was given; the password is the whole of the evidence.
    PasswordOnly,
}

impl Accounts {
    /// Open over `store`, applying the schema and warming the cache.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the schema cannot be applied.
    pub async fn open(store: Store) -> Result<Self, StoreError> {
        store.migrate(SCHEMA).await?;
        let accounts = Self {
            store,
            cache: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(2)),
            names: Arc::new(NameRule::new()),
            settings: None,
        };
        accounts.warm().await;
        Ok(accounts)
    }

    /// Load every account into memory.
    ///
    /// Authentication is a synchronous, pure check because of this: a query
    /// inside the login path would stall every session behind the slowest disk
    /// read (`docs/STORAGE.md` D1).
    async fn warm(&self) {
        use sqlx::Row as _;
        let Ok(rows) = sqlx::query(
            "SELECT server_id, id, name, email, cert_hash, password, totp_secret, \
                    texture_hash, comment_hash, created_at_ms, last_active_ms FROM account",
        )
        .fetch_all(self.store.pool())
        .await
        else {
            return;
        };
        let (Ok(mut cache), Ok(mut next)) = (self.cache.lock(), self.next_id.lock()) else {
            return;
        };
        for row in rows {
            let scope = row.try_get::<i64, _>("server_id").unwrap_or(1) as u32;
            let id = row.try_get::<i64, _>("id").unwrap_or_default() as u64;
            let record = Record {
                account: Account {
                    id,
                    name: row.try_get("name").unwrap_or_default(),
                    email: row.try_get("email").unwrap_or_default(),
                    cert_hash: row.try_get("cert_hash").unwrap_or_default(),
                    texture_hash: row.try_get("texture_hash").unwrap_or_default(),
                    comment_hash: row.try_get("comment_hash").unwrap_or_default(),
                    created_at_ms: row.try_get::<i64, _>("created_at_ms").unwrap_or_default()
                        as u64,
                    last_active_ms: row.try_get::<i64, _>("last_active_ms").unwrap_or_default()
                        as u64,
                    totp_enabled: row
                        .try_get::<Option<Vec<u8>>, _>("totp_secret")
                        .ok()
                        .flatten()
                        .is_some(),
                    settings: HashMap::new(),
                },
                password: row
                    .try_get::<Option<Vec<u8>>, _>("password")
                    .ok()
                    .flatten()
                    .and_then(|bytes| Secret::from_bytes(&bytes)),
                totp: row
                    .try_get::<Option<Vec<u8>>, _>("totp_secret")
                    .ok()
                    .flatten(),
            };
            *next = (*next).max(id + 1);
            let _ = cache.insert((scope, id), record);
        }
    }

    /// Read the operator's name rule from `server-config` from now on.
    ///
    /// Not a constructor argument: `Accounts::open` has four callers and only
    /// one of them is a running server, so the setting is opted into by the one
    /// that has somewhere to read it from.
    #[must_use]
    pub fn watching(mut self, settings: Settings) -> Self {
        self.settings = Some(settings);
        self
    }

    /// Whether `name` satisfies the operator's `user_name_regex`.
    fn name_allowed(&self, scope: u32, name: &str) -> bool {
        let pattern = self.settings.as_ref().map_or_else(
            || USER_NAME_PATTERN.to_owned(),
            |settings| settings.get(scope).user_name_regex,
        );
        is_user_name(&self.names, &pattern, name)
    }

    /// Decide whether a peer may in, and as whom.
    ///
    /// The name-taken case is murmur's impersonation guard: a registered name
    /// belongs to the certificate that registered it, so a stranger presenting
    /// it is refused rather than let in as a guest with that name.
    pub fn authenticate(&self, scope: u32, request: &AuthRequest) -> AuthResult {
        use auth_result::Outcome;

        if request.name.trim().is_empty() {
            return outcome(Outcome::InvalidName, None);
        }
        // The operator's name rule, and the SuperUser is exempt from it for the
        // same reason `cert_required` exempts them (`handshake.rs`): a pattern
        // that happens to exclude the administrator's name locks out the only
        // account that could change the pattern back, and the way in is then to
        // edit the database by hand.
        if request.name != identity::SUPERUSER_NAME && !self.name_allowed(scope, &request.name) {
            return outcome(Outcome::InvalidName, None);
        }
        let by_cert = if request.cert_hash.is_empty() {
            None
        } else {
            self.record_by_cert(scope, &request.cert_hash)
        };
        let by_name = self.record_by_name(scope, &request.name);

        match by_cert {
            // A certificate that matches an account is the strongest signal
            // murmur has, but it authenticates **that account and no other**.
            //
            // This arm used to be `(Some(record), _)`, matching on the
            // certificate alone and ignoring the name the peer asked for. The
            // failure that exposed it: a client whose certificate had been
            // bound to some account by an earlier registration then connected
            // as `SuperUser`, and the server resolved it to the *certificate's*
            // account and checked the typed administrator password against
            // **that** account's secret. It refused with "wrong password",
            // which is a true statement about a question nobody asked.
            //
            // Refusing was the safe direction of a wrong answer, and the wrong
            // answer is the point: selecting an identity the peer did not claim
            // is silent substitution. Had the certificate's account carried no
            // password, the same path would have *admitted* the peer as
            // somebody else entirely.
            Some(record) if record.account.name == request.name => {
                self.finish(record, request, Proof::Certificate)
            }
            // The certificate belongs to a different account than the one being
            // claimed, so it proves nothing about this login and is set aside.
            // Resolution falls to the name, which carries its own proof, and
            // the impersonation guard below still applies, so a peer cannot use
            // one account's certificate to take another's name.
            _ => match by_name {
                Some(record) => {
                    if record.account.cert_hash.is_empty() {
                        // Only a name was offered, so only the password can
                        // prove it belongs to this peer.
                        self.finish(record, request, Proof::PasswordOnly)
                    } else {
                        outcome(Outcome::NameTaken, None)
                    }
                }
                // An unregistered name is a guest, which is what a Mumble
                // server does by default. Whether guests are allowed at all is
                // server-config's question, not this one's.
                //
                // Reached by a peer holding a valid certificate for another
                // account too. That is a *downgrade*, they take no privileges
                // with them, so it is allowed, and it is the only way for
                // somebody to connect under a second, unregistered name from a
                // machine they have already registered from.
                None => AuthResult {
                    outcome: Outcome::Ok as i32,
                    account: None,
                    guest: true,
                },
            },
        }
    }

    fn finish(&self, record: Record, request: &AuthRequest, proof: Proof) -> AuthResult {
        use auth_result::Outcome;
        match (&record.password, proof) {
            (Some(secret), _) if !secret.verify(&request.password) => {
                return outcome(Outcome::WrongPassword, None);
            }
            // A registered account with no stored password, claimed by name
            // alone. There is nothing here to check, so accepting would hand
            // the account (and every permission it holds) to whoever typed
            // the name. It is refused rather than downgraded to a guest,
            // because a guest wearing a registered name is the impersonation
            // the name-taken branch above exists to prevent.
            //
            // Reachable through data, not just code: an account row written
            // before passwords were stored has a NULL there, and a SuperUser in
            // that state is a server anyone can administer.
            (None, Proof::PasswordOnly) => {
                tracing::warn!(
                    name = %record.account.name,
                    account = record.account.id,
                    "refusing a registered account that has no password to check"
                );
                return outcome(Outcome::WrongPassword, None);
            }
            _ => {}
        }
        if let Some(totp) = &record.totp {
            if request.totp.is_empty() {
                return outcome(Outcome::TotpRequired, None);
            }
            if !verify_totp(totp, &request.totp, now_ms() / 1000) {
                return outcome(Outcome::TotpInvalid, None);
            }
        }
        outcome(Outcome::Ok, Some(record.account))
    }

    /// One account by id.
    pub fn by_id(&self, scope: u32, id: u64) -> Option<Account> {
        self.cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&(scope, id)).map(|record| record.account.clone()))
    }

    /// One account by name.
    pub fn by_name(&self, scope: u32, name: &str) -> Option<Account> {
        self.record_by_name(scope, name)
            .map(|record| record.account)
    }

    /// One account by certificate hash.
    pub fn by_cert(&self, scope: u32, hash: &[u8]) -> Option<Account> {
        self.record_by_cert(scope, hash)
            .map(|record| record.account)
    }

    /// One account by name, **case-insensitively**.
    ///
    /// # Why case-insensitively
    ///
    /// This compared with `==`, and the live-session check beside it does not:
    /// `duplicate_of` uses `eq_ignore_ascii_case` (`session-lifecycle`'s
    /// `state.rs`), as murmur does by lowercasing both sides
    /// (`Messages.cpp:487`). That single asymmetry defeated the impersonation
    /// guard this lookup exists to serve, and only while the owner was *away*:
    /// a registered `Alice` who was offline could be worn by a guest calling
    /// themselves `alice`, because `NameTaken` is reachable only through here.
    /// A registration that protects a name only while its owner is connected
    /// protects nothing, being connected is what already protects it.
    ///
    /// It also made `identity.rs`'s claim untrue, that the SuperUser name is
    /// "matched case-insensitively ... because every Mumble client offers it as
    /// the administrator login". Now it is.
    ///
    /// # Why an exact match still wins
    ///
    /// A database written before this change may already hold `Alice` and
    /// `alice` as two accounts. Collapsing them would take one person's login
    /// away, so an exact match is preferred and returned immediately: both
    /// legacy accounts keep working, and only a *third* spelling resolves by
    /// fold. New collisions cannot be created, `register` and `rename` gate on
    /// this same lookup, so `alice` is now refused while `Alice` exists.
    ///
    /// Ties are broken by the lowest account id rather than by iteration order.
    /// The cache is a `HashMap`, so "whichever came first" is a different
    /// answer in every process, and an authentication that depends on hash
    /// seeding is not one anybody can reason about.
    fn record_by_name(&self, scope: u32, name: &str) -> Option<Record> {
        let cache = self.cache.lock().ok()?;
        let in_scope = || {
            cache
                .iter()
                .filter(|((server, _), _)| *server == scope)
                .map(|(_, record)| record)
        };
        // Two chains rather than one loop, and `min_by_key` rather than "the
        // first one found": this walks a `HashMap`, so the *only* orders that
        // may decide an authentication are ones written down here.
        in_scope()
            .find(|record| record.account.name == name)
            .or_else(|| {
                in_scope()
                    .filter(|record| record.account.name.eq_ignore_ascii_case(name))
                    .min_by_key(|record| record.account.id)
            })
            .cloned()
    }

    fn record_by_cert(&self, scope: u32, hash: &[u8]) -> Option<Record> {
        if hash.is_empty() {
            return None;
        }
        let cache = self.cache.lock().ok()?;
        cache
            .iter()
            .find(|((s, _), record)| *s == scope && record.account.cert_hash == hash)
            .map(|(_, record)| record.clone())
    }

    /// A page of accounts, ordered by id.
    pub fn list(&self, scope: u32, prefix: &str, limit: u32, after: u64) -> AccountPage {
        let limit = starling_proto_fancy::page::page_size(limit, 50, 500) as usize;
        let mut accounts: Vec<Account> = self
            .cache
            .lock()
            .map(|cache| {
                cache
                    .iter()
                    .filter(|((s, id), record)| {
                        *s == scope && *id > after && record.account.name.starts_with(prefix)
                    })
                    .map(|(_, record)| record.account.clone())
                    .collect()
            })
            .unwrap_or_default();
        accounts.sort_by_key(|account| account.id);
        let more = accounts.len() > limit;
        accounts.truncate(limit);
        AccountPage { accounts, more }
    }

    /// Register a new account.
    ///
    /// # Errors
    ///
    /// The name, if it is taken. Refusing is the whole point: a second account
    /// with one name is how impersonation starts.
    pub async fn register(
        &self,
        scope: u32,
        mut account: Account,
        password: &str,
    ) -> Result<Account, String> {
        if !self.name_allowed(scope, &account.name) {
            return Err(format!("the name {:?} is not allowed here", account.name));
        }
        if self.record_by_name(scope, &account.name).is_some() {
            return Err(format!("the name {:?} is already registered", account.name));
        }
        let id = {
            let Ok(mut next) = self.next_id.lock() else {
                return Err("the account table is unavailable".to_owned());
            };
            let id = *next;
            *next += 1;
            id
        };
        account.id = id;
        account.created_at_ms = now_ms();
        account.last_active_ms = account.created_at_ms;

        let secret = (!password.is_empty()).then(|| Secret::new(password));
        let record = Record {
            account: account.clone(),
            password: secret,
            totp: None,
        };
        self.write(scope, &record).await;
        if let Ok(mut cache) = self.cache.lock() {
            let _ = cache.insert((scope, id), record);
        }
        Ok(account)
    }

    /// Rename an account on somebody else's authority.
    ///
    /// Separate from [`Self::update`] because the two rest on different
    /// evidence. `update` treats a name change as sensitive and demands the
    /// account's current password, which is right when a user is editing their
    /// own profile: a hijacked session must not be able to rename the account
    /// out from under its owner. It is *impossible* for the other caller, an
    /// administrator holding `Register` renaming somebody through the
    /// registered-user dialog, who does not know that person's password and
    /// must not need to. Folding the two together would mean either weakening
    /// the self-service guard or having no working rename at all.
    ///
    /// # Errors
    ///
    /// The name, if it is empty or already registered. Uniqueness is checked
    /// here rather than left to the `ux_account_name` index: a violated index
    /// fails inside `Self::write`, which only logs, so the cache would keep
    /// the new name while the table kept the old one, and the two would disagree
    /// until the next restart.
    pub async fn rename(&self, scope: u32, id: u64, name: &str) -> Result<Account, String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("a name cannot be empty".to_owned());
        }
        // After the trim, as murmur checks it (`Messages.cpp:3219` trims before
        // calling `validateUserName`), so a rename with an edge space is
        // accepted and stored trimmed rather than refused for a space the user
        // cannot see.
        if !self.name_allowed(scope, name) {
            return Err(format!("the name {name:?} is not allowed here"));
        }
        let Some(mut record) = self
            .cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&(scope, id)).cloned())
        else {
            return Err("no such account".to_owned());
        };
        if record.account.name == name {
            return Ok(record.account);
        }
        if self.record_by_name(scope, name).is_some() {
            return Err(format!("the name {name:?} is already registered"));
        }

        record.account.name = name.to_owned();
        record.account.last_active_ms = now_ms();
        self.write(scope, &record).await;
        if let Ok(mut cache) = self.cache.lock() {
            let _ = cache.insert((scope, id), record.clone());
        }
        Ok(record.account)
    }

    /// Create the SuperUser for this server instance if it has none.
    ///
    /// Returns the password it generated, and **only** when it generated one.
    /// `None` means the account was already there, which is what makes this safe
    /// to call on every boot: the credential is announced exactly once, at
    /// creation, and a restart never prints it again. murmur does the same thing
    /// for the same reason, an operator who missed the line uses
    /// `set-superuser-password` rather than expecting it to reappear.
    pub async fn ensure_superuser(&self, scope: u32) -> Option<String> {
        if self.by_id(scope, identity::SUPERUSER).is_some() {
            return None;
        }
        let password = generated_password();
        self.write_superuser(scope, &password).await;
        Some(password)
    }

    /// Set the SuperUser's password, creating the account if it is missing.
    ///
    /// Create-or-update rather than update: a deployment whose userdata database
    /// was restored from before the account existed must still be recoverable,
    /// and "no such account" would be a dead end with no other way out.
    pub async fn set_superuser_password(&self, scope: u32, password: &str) {
        self.write_superuser(scope, password).await;
    }

    /// Write the SuperUser record for `scope` with `password`.
    async fn write_superuser(&self, scope: u32, password: &str) {
        let now = now_ms();
        let existing = self
            .cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&(scope, identity::SUPERUSER)).cloned());

        let mut record = existing.unwrap_or_else(|| Record {
            account: Account {
                id: identity::SUPERUSER,
                name: identity::SUPERUSER_NAME.to_owned(),
                created_at_ms: now,
                ..Account::default()
            },
            password: None,
            totp: None,
        });
        // Deliberately leaves `cert_hash` empty. A certificate on this account
        // would authenticate it *without* the password, and the administrator
        // login is the one place that must always be something you know.
        record.password = Some(Secret::new(password));
        record.account.last_active_ms = now;

        self.write(scope, &record).await;
        if let Ok(mut cache) = self.cache.lock() {
            let _ = cache.insert((scope, identity::SUPERUSER), record);
        }
    }

    /// Update named fields of an account.
    ///
    /// # Errors
    ///
    /// A message when the current password is required and wrong, a hijacked
    /// session must not be able to lock the owner out of their own account.
    pub async fn update(&self, scope: u32, request: UpdateRequest) -> Result<Account, String> {
        let Some(mut record) = self
            .cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&(scope, request.id)).cloned())
        else {
            return Err("no such account".to_owned());
        };
        let sensitive = request
            .fields
            .iter()
            .any(|field| matches!(field.as_str(), "password" | "email" | "name" | "totp"));
        let operator = matches!(
            request.actor.as_ref().and_then(|actor| actor.who.as_ref()),
            Some(starling_proto_fancy::common::actor::Who::Operator(_))
        );
        if sensitive && !operator {
            match &record.password {
                Some(secret) if secret.verify(&request.current_password) => {}
                Some(_) => return Err("the current password is wrong".to_owned()),
                None => {}
            }
        }

        let values = request.values.unwrap_or_default();
        for field in &request.fields {
            match field.as_str() {
                "name" => record.account.name = values.name.clone(),
                "email" => record.account.email = values.email.clone(),
                "cert_hash" => record.account.cert_hash = values.cert_hash.clone(),
                "texture_hash" => record.account.texture_hash = values.texture_hash.clone(),
                "comment_hash" => record.account.comment_hash = values.comment_hash.clone(),
                "password" => record.password = Some(Secret::new(&request.password)),
                "settings" => record.account.settings = values.settings.clone(),
                other => tracing::warn!(field = other, "ignoring an unknown account field"),
            }
        }
        record.account.last_active_ms = now_ms();
        self.write(scope, &record).await;
        if let Ok(mut cache) = self.cache.lock() {
            let _ = cache.insert((scope, request.id), record.clone());
        }
        Ok(record.account)
    }

    /// Whether `password` is this account's current password.
    ///
    /// **Blocking**, 210 000 PBKDF2 rounds, and the caller is responsible for
    /// running it somewhere that may block, the same rule
    /// [`Accounts::authenticate`] carries, and for the same reason: 30 ms in
    /// release and 1.45 s in a debug build, on a runtime worker that serves
    /// every other client meanwhile.
    ///
    /// An account with **no** stored password answers `false` for any input,
    /// including the empty string. Those accounts are reached by certificate,
    /// and a self-service action must not become free because the owner logs in
    /// with one.
    #[must_use]
    pub fn password_matches(&self, scope: u32, id: u64, password: &str) -> bool {
        let stored = self
            .cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&(scope, id)).and_then(|r| r.password.clone()));
        stored.is_some_and(|secret| secret.verify(password))
    }

    /// Whether `code` is a current TOTP code for this account.
    ///
    /// False when the account has no TOTP at all, deliberately: the caller
    /// asking is usually about to take a second factor *off*, and "there was
    /// nothing to prove" must not read as "the proof succeeded".
    #[must_use]
    pub fn totp_matches(&self, scope: u32, id: u64, code: &str) -> bool {
        self.cache
            .lock()
            .ok()
            .and_then(|cache| {
                cache
                    .get(&(scope, id))
                    .and_then(|record| record.totp.clone())
            })
            .is_some_and(|secret| verify_totp(&secret, code, now_ms() / 1000))
    }

    /// Whether this account has a second factor enabled.
    #[must_use]
    pub fn totp_enabled(&self, scope: u32, id: u64) -> bool {
        self.cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&(scope, id)).map(|record| record.totp.is_some()))
            .unwrap_or_default()
    }

    /// Turn the second factor on with `secret`, or off with `None`.
    ///
    /// Separate from [`Accounts::update`] because a TOTP secret is not a field
    /// a caller supplies: enabling one is a server-generated secret confirmed
    /// by a code derived from it, and `UpdateRequest` has a shape for neither.
    /// `"totp"` was in `update`'s *sensitive* list with no arm to match it, so
    /// a caller asking to change it was answered `Ok` and nothing happened.
    ///
    /// # Errors
    ///
    /// A message when there is no such account.
    pub async fn set_totp(
        &self,
        scope: u32,
        id: u64,
        secret: Option<Vec<u8>>,
    ) -> Result<(), String> {
        let Some(mut record) = self
            .cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&(scope, id)).cloned())
        else {
            return Err("no such account".to_owned());
        };
        record.totp = secret;
        record.account.totp_enabled = record.totp.is_some();
        record.account.last_active_ms = now_ms();
        self.write(scope, &record).await;
        if let Ok(mut cache) = self.cache.lock() {
            let _ = cache.insert((scope, id), record);
        }
        Ok(())
    }

    /// Whether this server instance's SuperUser has a password set.
    ///
    /// For the operator surface, which should be able to say "the administrator
    /// login exists" without being able to read what it is.
    pub fn has_superuser(&self, scope: u32) -> bool {
        self.by_id(scope, identity::SUPERUSER).is_some()
    }

    /// Whether this account's password came from murmur and is still in
    /// murmur's form.
    ///
    /// The question `starling migrate-db` leaves behind: an imported hash
    /// verifies, but it is not the hash this server would have made, so the
    /// next successful login re-derives it. Answered from the cache, because
    /// the caller asks it on the login path.
    #[must_use]
    pub fn password_is_carried(&self, scope: u32, id: u64) -> bool {
        self.cache
            .lock()
            .ok()
            .and_then(|cache| {
                cache
                    .get(&(scope, id))
                    .map(|record| record.password.as_ref().is_some_and(|s| !s.is_native()))
            })
            .unwrap_or_default()
    }

    /// Replace an imported password with `secret`, which was derived natively.
    ///
    /// Called after a login that already succeeded, so this neither decides nor
    /// influences one: if it does nothing, the account keeps the hash it came in
    /// with and still works. It is how murmur's unsalted SHA-1 leaves a migrated
    /// database rather than living in it forever.
    ///
    /// Takes an already-derived [`Secret`] rather than the plaintext, so the
    /// expensive half runs wherever the caller decided blocking was allowed and
    /// this half is a write.
    pub async fn store_password(&self, scope: u32, id: u64, secret: Secret) {
        let Some(mut record) = self
            .cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&(scope, id)).cloned())
        else {
            return;
        };
        // Checked again here rather than trusted from the caller: two logins for
        // one account can race, and the loser would otherwise overwrite a
        // password the winner had already upgraded.
        if record.password.as_ref().is_none_or(Secret::is_native) {
            return;
        }
        record.password = Some(secret);
        self.write(scope, &record).await;
        if let Ok(mut cache) = self.cache.lock() {
            let _ = cache.insert((scope, id), record);
        }
        tracing::info!(
            account = id,
            instance = scope,
            "an imported password was re-derived on login"
        );
    }

    /// Write accounts that came from a murmur database, ids and all.
    ///
    /// Returns what it **refused**, one line each, so a migration can report
    /// its losses rather than count a silent failure as a success
    /// (`docs/STORAGE.md` §4, requirement 4).
    ///
    /// Three things make this different from [`Self::register`], and each of
    /// them is the point:
    ///
    /// * **The id is kept.** Every ACL entry, group membership and channel
    ///   listener in the rest of the migration names an account by murmur's id,
    ///   so an account that arrived with a new one would silently lose every
    ///   permission it had.
    /// * **The password is taken as given**, in whichever form murmur left it.
    ///   See [`Secret`]: a hash cannot be re-derived, and dropping it would lock
    ///   out every user on the day the server moved.
    /// * **It upserts.** A migration that has to be run twice -- because it was
    ///   interrupted, or because the first pass was a rehearsal -- must be able
    ///   to be (`docs/STORAGE.md` §4, requirement 3).
    pub async fn import(&self, scope: u32, accounts: &[Import]) -> Vec<String> {
        let mut refused = Vec::new();
        for account in accounts {
            if account.name.trim().is_empty() {
                refused.push(format!("account {} has no name", account.id));
                continue;
            }
            // Exactly, not by fold: murmur's own index is case-sensitive, so a
            // server can genuinely hold `Alice` and `alice`, and refusing the
            // second would take somebody's login away in the name of tidiness.
            // A collision on the *same* spelling is a different matter: the
            // unique index would refuse it anyway, and doing so here says which
            // two accounts collided.
            if let Some(owner) = self.exact_name_owner(scope, &account.name)
                && owner != account.id
            {
                refused.push(format!(
                    "account {} is called {:?}, which account {owner} already has",
                    account.id, account.name
                ));
                continue;
            }

            let comment_hash = self.store_content(scope, account.comment.as_bytes()).await;
            let texture_hash = self.store_content(scope, &account.texture).await;

            let record = Record {
                account: Account {
                    id: account.id,
                    name: account.name.clone(),
                    email: account.email.clone(),
                    cert_hash: account.cert_hash.clone(),
                    texture_hash,
                    comment_hash,
                    created_at_ms: account.created_at_ms,
                    last_active_ms: account.last_active_ms,
                    totp_enabled: account.totp_secret.is_some(),
                    settings: HashMap::new(),
                },
                password: account.password.clone(),
                totp: account.totp_secret.clone(),
            };
            self.write(scope, &record).await;
            if let Ok(mut cache) = self.cache.lock() {
                let _ = cache.insert((scope, account.id), record);
            }
            if let Ok(mut next) = self.next_id.lock() {
                // Or the first account registered after a migration would be
                // handed an id an imported account already has, and the two
                // would be one account with two owners.
                *next = (*next).max(account.id + 1);
            }
        }
        refused
    }

    /// Store `bytes` as a blob and return its hash, or nothing for nothing.
    ///
    /// An empty comment and an absent avatar are the same thing here, and both
    /// must leave the hash empty: a hash of zero bytes is a perfectly valid hash
    /// that clients would then ask for.
    async fn store_content(&self, scope: u32, bytes: &[u8]) -> Vec<u8> {
        if bytes.is_empty() {
            return Vec::new();
        }
        self.put_blob(scope, bytes).await.hash
    }

    /// Which account holds `name` exactly, if any.
    fn exact_name_owner(&self, scope: u32, name: &str) -> Option<u64> {
        let cache = self.cache.lock().ok()?;
        cache
            .iter()
            .find(|((server, _), record)| *server == scope && record.account.name == name)
            .map(|((_, id), _)| *id)
    }

    /// How many accounts `scope` holds, read from the table.
    ///
    /// Deliberately **not** `list(...).accounts.len()`. `list` paginates with
    /// `after`, which starts at zero and is exclusive, so it can never return
    /// account 0 -- and account 0 is the SuperUser, on every Mumble server there
    /// has ever been. Counting that way makes a migration of *n* accounts report
    /// *n - 1* and look as though it lost one.
    ///
    /// Read through a query rather than from the cache, because a caller asking
    /// how many there are is asking what is in the database.
    pub async fn count(&self, scope: u32) -> usize {
        use sqlx::Row as _;
        match sqlx::query("SELECT COUNT(*) AS n FROM account WHERE server_id = ?")
            .bind(i64::from(scope))
            .fetch_one(self.store.pool())
            .await
        {
            Ok(row) => row.try_get::<i64, _>("n").unwrap_or_default().max(0) as usize,
            Err(error) => {
                tracing::error!(%error, "could not count accounts");
                0
            }
        }
    }

    /// Delete an account.
    pub async fn delete(&self, scope: u32, id: u64) {
        if let Ok(mut cache) = self.cache.lock() {
            let _ = cache.remove(&(scope, id));
        }
        let _ = sqlx::query("DELETE FROM account WHERE server_id = ? AND id = ?")
            .bind(i64::from(scope))
            .bind(id as i64)
            .execute(self.store.pool())
            .await;
    }

    /// A blob by hash.
    pub async fn blob(&self, _scope: u32, hash: &[u8]) -> Option<Vec<u8>> {
        use sqlx::Row as _;
        if hash.is_empty() {
            return None;
        }
        let row = sqlx::query("SELECT bytes FROM blob WHERE hash = ?")
            .bind(hash)
            .fetch_optional(self.store.pool())
            .await
            .ok()??;
        row.try_get("bytes").ok()
    }

    /// Store a blob, deduplicated by content hash.
    pub async fn put_blob(&self, _scope: u32, bytes: &[u8]) -> BlobRef {
        use sha2::{Digest as _, Sha256};
        let hash = Sha256::digest(bytes).to_vec();
        let _ = sqlx::query(
            "INSERT INTO blob (hash, bytes, size, refs) VALUES (?, ?, ?, 1) \
             ON CONFLICT (hash) DO UPDATE SET refs = blob.refs + 1",
        )
        .bind(hash.as_slice())
        .bind(bytes)
        .bind(bytes.len() as i64)
        .execute(self.store.pool())
        .await;
        BlobRef {
            hash,
            size: bytes.len() as u64,
        }
    }

    async fn write(&self, scope: u32, record: &Record) {
        let password = record.password.as_ref().map(Secret::to_bytes);
        let result = sqlx::query(
            "INSERT INTO account (server_id, id, name, email, cert_hash, password, totp_secret, \
                 texture_hash, comment_hash, created_at_ms, last_active_ms) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (server_id, id) DO UPDATE SET \
                 name = excluded.name, email = excluded.email, cert_hash = excluded.cert_hash, \
                 password = excluded.password, totp_secret = excluded.totp_secret, \
                 texture_hash = excluded.texture_hash, comment_hash = excluded.comment_hash, \
                 last_active_ms = excluded.last_active_ms",
        )
        .bind(i64::from(scope))
        .bind(record.account.id as i64)
        .bind(&record.account.name)
        .bind(&record.account.email)
        .bind(record.account.cert_hash.as_slice())
        .bind(password)
        .bind(record.totp.clone())
        .bind(record.account.texture_hash.as_slice())
        .bind(record.account.comment_hash.as_slice())
        .bind(record.account.created_at_ms as i64)
        .bind(record.account.last_active_ms as i64)
        .execute(self.store.pool())
        .await;
        if let Err(error) = result {
            tracing::error!(%error, "could not persist an account");
        }
    }
}

fn outcome(outcome: auth_result::Outcome, account: Option<Account>) -> AuthResult {
    AuthResult {
        outcome: outcome as i32,
        account,
        guest: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn accounts() -> Accounts {
        // A name unique per call: `cache=shared` makes same-named in-memory
        // databases visible to every connection that names them, so two tests
        // sharing one name would race on the same `starling_migration` row.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let store = Store::open(
            &format!("sqlite:file:userdata-test-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("in-memory database");
        Accounts::open(store).await.expect("schema")
    }

    fn auth(name: &str, password: &str) -> AuthRequest {
        AuthRequest {
            scope: None,
            name: name.to_owned(),
            password: password.to_owned(),
            cert_hash: Vec::new(),
            strong_cert: false,
            totp: String::new(),
        }
    }

    #[tokio::test]
    async fn the_superuser_is_created_once_and_announced_once() {
        // Announcing on every boot would leave a live administrator password in
        // every log the deployment ships to.
        let accounts = accounts().await;

        let password = accounts
            .ensure_superuser(1)
            .await
            .expect("the first boot creates the account");
        assert_eq!(password.len(), GENERATED_PASSWORD_LEN);
        assert!(
            accounts.ensure_superuser(1).await.is_none(),
            "a second boot must not create or re-announce anything"
        );
    }

    #[tokio::test]
    async fn the_generated_password_actually_logs_in_as_the_superuser() {
        // The whole point, and the thing a constant-mismatch bug would break
        // silently: the announced password must authenticate, and the result
        // must be the SuperUser's account rather than a guest with that name.
        let accounts = accounts().await;
        let password = accounts.ensure_superuser(1).await.expect("created");

        let result = accounts.authenticate(1, &auth(identity::SUPERUSER_NAME, &password));

        assert_eq!(result.outcome, auth_result::Outcome::Ok as i32);
        assert!(!result.guest, "the SuperUser is not a guest");
        let account = result.account.expect("an account");
        assert_eq!(account.id, identity::SUPERUSER);
        assert!(identity::is_superuser(true, account.id));
    }

    /// An authentication request carrying a certificate.
    fn auth_with_cert(name: &str, password: &str, cert: &[u8]) -> AuthRequest {
        AuthRequest {
            cert_hash: cert.to_vec(),
            ..auth(name, password)
        }
    }

    #[tokio::test]
    async fn a_registered_name_cannot_be_worn_by_changing_its_case() {
        // The impersonation guard was reachable only through a case-sensitive
        // lookup, so it protected a registered name **only while its owner was
        // connected**, the live-session check beside it has always folded case.
        // Being connected is what already protects a name; the registration is
        // supposed to protect it when they are not.
        let accounts = accounts().await;
        let _ = accounts
            .register(
                1,
                Account {
                    name: "Alice".to_owned(),
                    cert_hash: b"alices-machine".to_vec(),
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("registered");

        // Alice is offline: nothing but this lookup stands in the way.
        for worn in ["alice", "ALICE", "aLiCe"] {
            let result = accounts.authenticate(1, &auth(worn, ""));
            assert_eq!(
                result.outcome,
                auth_result::Outcome::NameTaken as i32,
                "{worn:?} must not be admitted as a guest wearing a registered name"
            );
            assert!(!result.guest, "{worn:?} was admitted as a guest");
        }
    }

    #[tokio::test]
    async fn the_administrator_login_is_case_insensitive_as_documented() {
        // `identity.rs` states the SuperUser name is matched case-insensitively
        // "because every Mumble client offers it as the administrator login".
        // It said so while the lookup compared with `==`.
        let accounts = accounts().await;
        let password = accounts.ensure_superuser(1).await.expect("created");

        for spelling in ["SuperUser", "superuser", "SUPERUSER"] {
            let result = accounts.authenticate(1, &auth(spelling, &password));
            assert_eq!(
                result.outcome,
                auth_result::Outcome::Ok as i32,
                "{spelling:?} must reach the administrator account"
            );
            assert_eq!(
                result.account.expect("an account").id,
                identity::SUPERUSER,
                "{spelling:?} resolved to something other than the SuperUser"
            );
        }
    }

    #[tokio::test]
    async fn a_name_that_differs_only_in_case_cannot_be_registered() {
        // Where the collision would otherwise be created in the first place.
        let accounts = accounts().await;
        let _ = accounts
            .register(
                1,
                Account {
                    name: "Alice".to_owned(),
                    ..Account::default()
                },
                "secret",
            )
            .await
            .expect("registered");

        for taken in ["alice", "ALICE"] {
            assert!(
                accounts
                    .register(
                        1,
                        Account {
                            name: taken.to_owned(),
                            ..Account::default()
                        },
                        "secret",
                    )
                    .await
                    .is_err(),
                "{taken:?} collides with a registered name and must be refused"
            );
        }
    }

    #[tokio::test]
    async fn two_legacy_accounts_differing_only_in_case_both_keep_their_login() {
        // A database written before the fold may already hold both. Collapsing
        // them would take somebody's login away, so an exact match wins and is
        // returned immediately; only a third spelling resolves by fold, and
        // then to the lowest account id rather than to whatever the hash map
        // happened to yield first.
        let accounts = accounts().await;
        let upper = accounts
            .register(
                1,
                Account {
                    name: "Alice".to_owned(),
                    ..Account::default()
                },
                "upper-secret",
            )
            .await
            .expect("registered");
        // Written straight into the cache, as a legacy row would be: `register`
        // now refuses this, which is the point of the fix.
        let lower = Record {
            account: Account {
                id: upper.id + 1,
                name: "alice".to_owned(),
                ..Account::default()
            },
            password: Some(Secret::new("lower-secret")),
            totp: None,
        };
        if let Ok(mut cache) = accounts.cache.lock() {
            let _ = cache.insert((1, lower.account.id), lower.clone());
        }

        let as_upper = accounts.authenticate(1, &auth("Alice", "upper-secret"));
        assert_eq!(as_upper.outcome, auth_result::Outcome::Ok as i32);
        assert_eq!(as_upper.account.expect("account").id, upper.id);

        let as_lower = accounts.authenticate(1, &auth("alice", "lower-secret"));
        assert_eq!(as_lower.outcome, auth_result::Outcome::Ok as i32);
        assert_eq!(as_lower.account.expect("account").id, lower.account.id);
    }

    #[tokio::test]
    async fn a_certificate_authenticates_its_own_account_and_no_other() {
        // The bug this exists for, and it is a *security* bug rather than the
        // login failure that exposed it: the account used to be selected by
        // certificate alone, ignoring the name the peer asked for. A client
        // whose certificate belonged to one account, connecting under another
        // name, was resolved to the certificate's account.
        //
        // It surfaced as "wrong password", the typed administrator password
        // checked against somebody else's secret, which is the safe direction
        // of a wrong answer. The unsafe direction is the same code path: had
        // the certificate's account carried no password, the peer would have
        // been *admitted* as an identity they never claimed.
        let accounts = accounts().await;
        let cert = b"a-registered-machine".to_vec();
        let _ = accounts
            .register(
                1,
                Account {
                    name: "mallory".to_owned(),
                    cert_hash: cert.clone(),
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("registered by certificate, as a client registration does");

        let superuser = accounts.ensure_superuser(1).await.expect("created");

        // The same machine, the same certificate, asking to be the SuperUser.
        let result = accounts.authenticate(
            1,
            &auth_with_cert(identity::SUPERUSER_NAME, &superuser, &cert),
        );

        assert_eq!(
            result.outcome,
            auth_result::Outcome::Ok as i32,
            "the administrator password must authenticate the administrator"
        );
        let account = result.account.expect("an account");
        assert_eq!(
            account.id,
            identity::SUPERUSER,
            "the certificate's account must not be substituted for the claimed one"
        );
    }

    #[tokio::test]
    async fn one_accounts_certificate_cannot_take_another_accounts_name() {
        // The impersonation guard has to survive the change above: setting the
        // certificate aside must fall through to the *name*, where a registered
        // name bound to a different certificate is still refused.
        let accounts = accounts().await;
        let _ = accounts
            .register(
                1,
                Account {
                    name: "victim".to_owned(),
                    cert_hash: b"the-victims-machine".to_vec(),
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("registered");
        let attacker = b"the-attackers-machine".to_vec();
        let _ = accounts
            .register(
                1,
                Account {
                    name: "attacker".to_owned(),
                    cert_hash: attacker.clone(),
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("registered");

        let result = accounts.authenticate(1, &auth_with_cert("victim", "", &attacker));

        assert_eq!(
            result.outcome,
            auth_result::Outcome::NameTaken as i32,
            "a certificate must not be a way to take somebody else's name"
        );
        assert!(result.account.is_none());
        assert!(!result.guest);
    }

    #[tokio::test]
    async fn a_registered_machine_may_still_connect_under_an_unregistered_name() {
        // A downgrade, so it is allowed: the peer takes no privileges with
        // them. It is also the only way to connect as a second, unregistered
        // identity from a machine that has already registered one.
        let accounts = accounts().await;
        let cert = b"a-registered-machine".to_vec();
        let _ = accounts
            .register(
                1,
                Account {
                    name: "registered".to_owned(),
                    cert_hash: cert.clone(),
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("registered");

        let result = accounts.authenticate(1, &auth_with_cert("a-guest-name", "", &cert));

        assert_eq!(result.outcome, auth_result::Outcome::Ok as i32);
        assert!(result.guest, "an unregistered name is a guest");
        assert!(
            result.account.is_none(),
            "a guest must carry no account, or it inherits the certificate's privileges"
        );
    }

    #[tokio::test]
    async fn a_certificate_still_authenticates_the_account_it_belongs_to() {
        // The behaviour that must not regress: a client registration stores no
        // password, so the certificate is the whole of the credential and has
        // to keep working on its own.
        let accounts = accounts().await;
        let cert = b"my-own-machine".to_vec();
        let registered = accounts
            .register(
                1,
                Account {
                    name: "owner".to_owned(),
                    cert_hash: cert.clone(),
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("registered");

        let result = accounts.authenticate(1, &auth_with_cert("owner", "", &cert));

        assert_eq!(result.outcome, auth_result::Outcome::Ok as i32);
        assert_eq!(result.account.expect("an account").id, registered.id);
    }

    #[tokio::test]
    async fn a_registered_account_with_no_password_cannot_be_claimed_by_name() {
        // Reachable through data, not code: an account row written before
        // passwords were stored carries a NULL, and the check used to be
        // skipped entirely when there was nothing to check, so the name alone
        // was enough. For a SuperUser in that state it hands over the server.
        let accounts = accounts().await;
        let _ = accounts
            .register(
                1,
                Account {
                    name: "legacy".to_owned(),
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("registered without a password, as an old row would be");

        for attempt in ["", "guess", "anything at all"] {
            let result = accounts.authenticate(1, &auth("legacy", attempt));
            assert_eq!(
                result.outcome,
                auth_result::Outcome::WrongPassword as i32,
                "{attempt:?} must not be accepted as proof of a passwordless account"
            );
            assert!(result.account.is_none());
            assert!(
                !result.guest,
                "and it must not fall back to a guest wearing the registered name"
            );
        }
    }

    #[tokio::test]
    async fn a_certificate_still_authenticates_an_account_that_has_no_password() {
        // The other half of the rule above: a certificate *is* the proof, so
        // requiring a password on top of it would lock out every account that
        // registered by certificate, which is how Mumble expects it to work.
        let accounts = accounts().await;
        let hash = vec![9_u8, 9, 9, 9];
        let _ = accounts
            .register(
                1,
                Account {
                    name: "by-cert".to_owned(),
                    cert_hash: hash.clone(),
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("registered");

        let result = accounts.authenticate(
            1,
            &AuthRequest {
                cert_hash: hash,
                ..auth("by-cert", "")
            },
        );
        assert_eq!(result.outcome, auth_result::Outcome::Ok as i32);
        assert!(result.account.is_some());
    }

    #[tokio::test]
    async fn the_wrong_superuser_password_is_refused_rather_than_downgraded() {
        // The failure that would matter most: falling back to a guest session
        // named "SuperUser" would let anyone in under the administrator's name.
        let accounts = accounts().await;
        let _ = accounts.ensure_superuser(1).await.expect("created");

        let result = accounts.authenticate(1, &auth(identity::SUPERUSER_NAME, "not the password"));

        assert_eq!(result.outcome, auth_result::Outcome::WrongPassword as i32);
        assert!(result.account.is_none());
        assert!(!result.guest);
    }

    #[tokio::test]
    async fn setting_the_password_replaces_the_generated_one() {
        let accounts = accounts().await;
        let generated = accounts.ensure_superuser(1).await.expect("created");

        accounts
            .set_superuser_password(1, "chosen by the operator")
            .await;

        assert_eq!(
            accounts
                .authenticate(1, &auth(identity::SUPERUSER_NAME, &generated))
                .outcome,
            auth_result::Outcome::WrongPassword as i32,
            "the generated password must stop working"
        );
        assert_eq!(
            accounts
                .authenticate(1, &auth(identity::SUPERUSER_NAME, "chosen by the operator"))
                .outcome,
            auth_result::Outcome::Ok as i32
        );
    }

    #[tokio::test]
    async fn the_password_can_be_set_before_the_account_exists() {
        // The recovery path: a userdata database restored from before the
        // account existed must not be a dead end.
        let accounts = accounts().await;
        assert!(!accounts.has_superuser(1));

        accounts.set_superuser_password(1, "recovered").await;

        assert!(accounts.has_superuser(1));
        assert_eq!(
            accounts
                .authenticate(1, &auth(identity::SUPERUSER_NAME, "recovered"))
                .outcome,
            auth_result::Outcome::Ok as i32
        );
    }

    #[tokio::test]
    async fn each_server_instance_gets_its_own_administrator() {
        // One password across every server instance would make them one server
        // for the only purpose that matters.
        let accounts = accounts().await;
        let first = accounts.ensure_superuser(1).await.expect("created");
        let second = accounts.ensure_superuser(2).await.expect("created");
        assert_ne!(first, second);

        assert_eq!(
            accounts
                .authenticate(2, &auth(identity::SUPERUSER_NAME, &first))
                .outcome,
            auth_result::Outcome::WrongPassword as i32,
            "one server's administrator password must not open another"
        );
    }

    #[tokio::test]
    async fn a_registered_account_never_collides_with_the_superuser() {
        // Ids are handed out from 2, so the administrator's 0 is unreachable by
        // registration. If that ever changed, the first two users to register
        // would silently become administrators.
        let accounts = accounts().await;
        let _ = accounts.ensure_superuser(1).await.expect("created");

        let registered = accounts
            .register(
                1,
                Account {
                    name: "alice".to_owned(),
                    ..Account::default()
                },
                "pw",
            )
            .await
            .expect("registered");

        assert!(registered.id > identity::SUPERUSER);
        assert!(!identity::is_superuser(true, registered.id));
    }

    #[tokio::test]
    async fn an_unregistered_name_connects_as_a_guest() {
        // What a Mumble server does by default; whether guests are allowed at
        // all is server-config's question.
        let result = accounts().await.authenticate(1, &auth("visitor", ""));
        assert_eq!(result.outcome, auth_result::Outcome::Ok as i32);
        assert!(result.guest);
    }

    #[tokio::test]
    async fn a_wrong_password_is_refused_and_says_which_failure_it_was() {
        let accounts = accounts().await;
        let _ = accounts
            .register(
                1,
                Account {
                    name: "alice".to_owned(),
                    ..Account::default()
                },
                "hunter2",
            )
            .await
            .expect("register");

        let wrong = accounts.authenticate(1, &auth("alice", "hunter3"));
        assert_eq!(wrong.outcome, auth_result::Outcome::WrongPassword as i32);

        let right = accounts.authenticate(1, &auth("alice", "hunter2"));
        assert_eq!(right.outcome, auth_result::Outcome::Ok as i32);
        assert!(!right.guest);
    }

    #[tokio::test]
    async fn a_name_registered_to_a_certificate_cannot_be_borrowed() {
        // murmur's impersonation guard: the name belongs to the certificate
        // that registered it.
        let accounts = accounts().await;
        let _ = accounts
            .register(
                1,
                Account {
                    name: "bob".to_owned(),
                    cert_hash: vec![1, 2, 3],
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("register");

        let stranger = accounts.authenticate(1, &auth("bob", ""));
        assert_eq!(stranger.outcome, auth_result::Outcome::NameTaken as i32);
    }

    #[tokio::test]
    async fn registering_a_taken_name_is_refused() {
        let accounts = accounts().await;
        let account = Account {
            name: "carol".to_owned(),
            ..Account::default()
        };
        let _ = accounts
            .register(1, account.clone(), "")
            .await
            .expect("first");
        assert!(accounts.register(1, account, "").await.is_err());
    }

    #[tokio::test]
    async fn an_administrator_renames_an_account_without_its_password() {
        // The whole reason `rename` exists next to `update`. Renaming somebody
        // through the registered-user dialog is authorised by `Register` on the
        // caller, and the caller does not know (and must not need) the
        // password of the account they are renaming.
        let accounts = accounts().await;
        let account = accounts
            .register(
                1,
                Account {
                    name: "dave".to_owned(),
                    ..Account::default()
                },
                "a password the admin has never seen",
            )
            .await
            .expect("registered");

        let renamed = accounts
            .rename(1, account.id, "  david  ")
            .await
            .expect("an administrator may rename");
        assert_eq!(renamed.name, "david", "the name is trimmed");

        // And the account is still the same account, still reachable by its new
        // name and no longer by its old one.
        assert_eq!(accounts.by_name(1, "david").map(|a| a.id), Some(account.id));
        assert!(accounts.by_name(1, "dave").is_none());
    }

    #[tokio::test]
    async fn renaming_onto_a_taken_name_is_refused_before_it_is_written() {
        // `ux_account_name` would refuse this in the table, and `write` only
        // logs a failure, so without the check here the cache would hold two
        // accounts with one name while the table held the old one, and the two
        // would disagree until a restart resolved it in favour of the row
        // nobody asked for.
        let accounts = accounts().await;
        let first = accounts
            .register(
                1,
                Account {
                    name: "erin".to_owned(),
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("registered");
        let second = accounts
            .register(
                1,
                Account {
                    name: "frank".to_owned(),
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("registered");

        assert!(accounts.rename(1, second.id, "erin").await.is_err());
        assert_eq!(
            accounts.by_id(1, second.id).map(|a| a.name),
            Some("frank".to_owned())
        );
        assert_eq!(accounts.by_name(1, "erin").map(|a| a.id), Some(first.id));
    }

    #[tokio::test]
    async fn renaming_an_account_to_the_name_it_already_has_is_not_a_collision() {
        // It would otherwise find *itself* in the name index and refuse, which
        // makes a dialog that submits every row it is showing fail on the rows
        // nobody edited.
        let accounts = accounts().await;
        let account = accounts
            .register(
                1,
                Account {
                    name: "grace".to_owned(),
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("registered");
        assert_eq!(
            accounts
                .rename(1, account.id, "grace")
                .await
                .map(|a| a.name),
            Ok("grace".to_owned())
        );
    }

    #[tokio::test]
    async fn a_rename_needs_a_name_and_a_real_account() {
        let accounts = accounts().await;
        let account = accounts
            .register(
                1,
                Account {
                    name: "heidi".to_owned(),
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("registered");
        assert!(accounts.rename(1, account.id, "   ").await.is_err());
        assert!(accounts.rename(1, 9_999, "someone").await.is_err());
        // The name it had is untouched by either refusal.
        assert_eq!(accounts.by_name(1, "heidi").map(|a| a.id), Some(account.id));
    }

    #[tokio::test]
    async fn one_server_instances_names_do_not_block_anothers() {
        // The name index is per server, and a rename that consulted it globally
        // would make every account name on a shared deployment first-come.
        let accounts = accounts().await;
        let _ = accounts
            .register(
                1,
                Account {
                    name: "ivan".to_owned(),
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("registered");
        let elsewhere = accounts
            .register(
                2,
                Account {
                    name: "judy".to_owned(),
                    ..Account::default()
                },
                "",
            )
            .await
            .expect("registered");
        assert!(accounts.rename(2, elsewhere.id, "ivan").await.is_ok());
    }

    #[tokio::test]
    async fn two_identical_avatars_are_stored_once() {
        // Content addressing (`docs/STORAGE.md` L4): the protocol already
        // works this way, and storage now matches it.
        let accounts = accounts().await;
        let first = accounts.put_blob(1, b"an avatar").await;
        let second = accounts.put_blob(1, b"an avatar").await;
        assert_eq!(first.hash, second.hash);
        assert_eq!(
            accounts.blob(1, &first.hash).await,
            Some(b"an avatar".to_vec())
        );
    }

    /// One account as `starling migrate-db` would hand it over.
    fn imported(id: u64, name: &str, password: Option<Secret>) -> Import {
        Import {
            id,
            name: name.to_owned(),
            email: format!("{name}@example.test"),
            comment: "hello".to_owned(),
            password,
            texture: b"an avatar".to_vec(),
            created_at_ms: 1_700_000_000_000,
            last_active_ms: 1_700_000_001_000,
            ..Import::default()
        }
    }

    #[tokio::test]
    async fn an_imported_account_keeps_the_id_murmur_gave_it() {
        // Every ACL entry, group membership and listener in the rest of a
        // migration names an account by that id. Renumbering here would leave
        // each of them pointing at somebody else.
        let accounts = accounts().await;
        assert!(
            accounts
                .import(1, &[imported(97, "alice", None)])
                .await
                .is_empty()
        );

        let alice = accounts.by_id(1, 97).expect("the imported account");
        assert_eq!(alice.name, "alice");
        assert_eq!(alice.email, "alice@example.test");
        assert_eq!(alice.created_at_ms, 1_700_000_000_000);
    }

    #[tokio::test]
    async fn a_password_imported_from_murmur_logs_in() {
        // The whole point of carrying the hash: without it, the day a server
        // moves is the day every registered user is locked out of it.
        let accounts = accounts().await;
        let secret = Secret::MurmurLegacy {
            digest: crate::secret::sha1(b"hunter2").to_vec(),
        };
        let _ = accounts
            .import(1, &[imported(5, "bob", Some(secret))])
            .await;

        let result = accounts.authenticate(1, &auth("bob", "hunter2"));
        assert_eq!(result.outcome, auth_result::Outcome::Ok as i32);
        assert_eq!(
            accounts.authenticate(1, &auth("bob", "wrong")).outcome,
            auth_result::Outcome::WrongPassword as i32
        );
    }

    #[tokio::test]
    async fn an_imported_password_is_re_derived_once_and_then_left_alone() {
        // How murmur's unsalted SHA-1 leaves a migrated database. The account
        // must still log in afterwards, which is the half that would fail
        // silently if the upgrade wrote the wrong thing.
        let accounts = accounts().await;
        let _ = accounts
            .import(
                1,
                &[imported(
                    5,
                    "bob",
                    Some(Secret::MurmurLegacy {
                        digest: crate::secret::sha1(b"hunter2").to_vec(),
                    }),
                )],
            )
            .await;
        assert!(accounts.password_is_carried(1, 5));

        accounts.store_password(1, 5, Secret::new("hunter2")).await;
        assert!(!accounts.password_is_carried(1, 5));
        assert_eq!(
            accounts.authenticate(1, &auth("bob", "hunter2")).outcome,
            auth_result::Outcome::Ok as i32
        );

        // A second upgrade must not overwrite the first, or two logins racing
        // would let the loser install a secret derived from a stale plaintext.
        accounts
            .store_password(1, 5, Secret::new("something else"))
            .await;
        assert_eq!(
            accounts.authenticate(1, &auth("bob", "hunter2")).outcome,
            auth_result::Outcome::Ok as i32
        );
    }

    #[tokio::test]
    async fn the_account_count_includes_the_administrator() {
        // murmur's SuperUser is account 0, and `list` cannot return it: it
        // paginates with an exclusive `after` that starts at zero. A migration
        // verified that way reports one account short of what it moved.
        let accounts = accounts().await;
        let _ = accounts
            .import(
                1,
                &[imported(0, "SuperUser", None), imported(1, "alice", None)],
            )
            .await;

        assert_eq!(accounts.count(1).await, 2);
        assert_eq!(
            accounts.list(1, "", 50, 0).accounts.len(),
            1,
            "this is the trap the count exists to avoid"
        );
    }

    #[tokio::test]
    async fn importing_twice_writes_the_same_account_rather_than_two() {
        // A migration that was interrupted has to be runnable again
        // (`docs/STORAGE.md` §4, requirement 3).
        let accounts = accounts().await;
        for _ in 0..2 {
            assert!(
                accounts
                    .import(1, &[imported(97, "alice", None)])
                    .await
                    .is_empty(),
                "a re-run must not collide with what the first run wrote"
            );
        }
        assert_eq!(accounts.list(1, "", 50, 0).accounts.len(), 1);
    }

    #[tokio::test]
    async fn an_imported_name_that_is_already_taken_is_refused_and_said_so() {
        // Silently skipping it would report a migration that moved every
        // account, having dropped one.
        let accounts = accounts().await;
        let _ = accounts.import(1, &[imported(1, "alice", None)]).await;
        let refused = accounts.import(1, &[imported(2, "alice", None)]).await;
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused.first().is_some_and(|note| note.contains("alice")));
    }

    #[tokio::test]
    async fn an_imported_comment_and_avatar_are_content_addressed() {
        let accounts = accounts().await;
        let _ = accounts.import(1, &[imported(3, "carol", None)]).await;
        let carol = accounts.by_id(1, 3).expect("carol");
        assert_eq!(
            accounts.blob(1, &carol.comment_hash).await,
            Some(b"hello".to_vec())
        );
        assert_eq!(
            accounts.blob(1, &carol.texture_hash).await,
            Some(b"an avatar".to_vec())
        );
    }

    #[tokio::test]
    async fn an_account_registered_after_a_migration_gets_a_free_id() {
        // Without this the first registration after an import is handed an id
        // an imported account already has, and the two are one account with two
        // owners.
        let accounts = accounts().await;
        let _ = accounts.import(1, &[imported(400, "alice", None)]).await;
        let fresh = accounts
            .register(
                1,
                Account {
                    name: "dave".to_owned(),
                    ..Account::default()
                },
                "pw",
            )
            .await
            .expect("registered");
        assert!(fresh.id > 400, "id {} collides with an import", fresh.id);
    }
}
