//! The account store: typed columns, the indexes its queries need, and the
//! in-memory cache authentication reads from.
//!
//! `docs/STORAGE.md` L1 and L2 in one table — no entity-attribute-value rows,
//! a unique index on the name and one on the certificate hash, because those
//! are exactly the two lookups authentication performs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use starling_proto_fancy::userdata::{
    Account, AccountPage, AuthRequest, AuthResult, BlobRef, UpdateRequest, auth_result,
};
use starling_runtime::ids::now_ms;
use starling_runtime::storage::{Migration, Store, StoreError};

use crate::secret::{Secret, verify_totp};

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

/// Accounts, cached in memory and written through.
#[derive(Debug, Clone)]
pub struct Accounts {
    store: Store,
    cache: Arc<Mutex<HashMap<(u32, u64), Record>>>,
    next_id: Arc<Mutex<u64>>,
}

#[derive(Debug, Clone)]
struct Record {
    account: Account,
    password: Option<Secret>,
    totp: Option<Vec<u8>>,
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
                    created_at_ms: row.try_get::<i64, _>("created_at_ms").unwrap_or_default() as u64,
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
                totp: row.try_get::<Option<Vec<u8>>, _>("totp_secret").ok().flatten(),
            };
            *next = (*next).max(id + 1);
            let _ = cache.insert((scope, id), record);
        }
    }

    /// Decide whether a peer may in, and as whom.
    ///
    /// The name-taken case is murmur's impersonation guard: a registered name
    /// belongs to the certificate that registered it, so a stranger presenting
    /// it is refused rather than let in as a guest with that name.
    pub async fn authenticate(&self, scope: u32, request: &AuthRequest) -> AuthResult {
        use auth_result::Outcome;

        if request.name.trim().is_empty() {
            return outcome(Outcome::InvalidName, None);
        }
        let by_cert = if request.cert_hash.is_empty() {
            None
        } else {
            self.record_by_cert(scope, &request.cert_hash)
        };
        let by_name = self.record_by_name(scope, &request.name);

        match (by_cert, by_name) {
            // A certificate that matches an account is the strongest signal
            // murmur has, and it authenticates on its own.
            (Some(record), _) => self.finish(record, request),
            (None, Some(record)) => {
                if record.account.cert_hash.is_empty() {
                    self.finish(record, request)
                } else {
                    outcome(Outcome::NameTaken, None)
                }
            }
            // An unregistered name is a guest, which is what a Mumble server
            // does by default. Whether guests are allowed at all is
            // server-config's question, not this one's.
            (None, None) => AuthResult {
                outcome: Outcome::Ok as i32,
                account: None,
                guest: true,
            },
        }
    }

    fn finish(&self, record: Record, request: &AuthRequest) -> AuthResult {
        use auth_result::Outcome;
        if let Some(secret) = &record.password
            && !secret.verify(&request.password) {
                return outcome(Outcome::WrongPassword, None);
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
    pub async fn by_id(&self, scope: u32, id: u64) -> Option<Account> {
        self.cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&(scope, id)).map(|record| record.account.clone()))
    }

    /// One account by name.
    pub async fn by_name(&self, scope: u32, name: &str) -> Option<Account> {
        self.record_by_name(scope, name).map(|record| record.account)
    }

    /// One account by certificate hash.
    pub async fn by_cert(&self, scope: u32, hash: &[u8]) -> Option<Account> {
        self.record_by_cert(scope, hash).map(|record| record.account)
    }

    fn record_by_name(&self, scope: u32, name: &str) -> Option<Record> {
        let cache = self.cache.lock().ok()?;
        cache
            .iter()
            .find(|((s, _), record)| *s == scope && record.account.name == name)
            .map(|(_, record)| record.clone())
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
    pub async fn list(&self, scope: u32, prefix: &str, limit: u32, after: u64) -> AccountPage {
        let limit = limit.clamp(1, 500) as usize;
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

    /// Update named fields of an account.
    ///
    /// # Errors
    ///
    /// A message when the current password is required and wrong — a hijacked
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
    async fn an_unregistered_name_connects_as_a_guest() {
        // What a Mumble server does by default; whether guests are allowed at
        // all is server-config's question.
        let result = accounts().await.authenticate(1, &auth("visitor", "")).await;
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

        let wrong = accounts.authenticate(1, &auth("alice", "hunter3")).await;
        assert_eq!(wrong.outcome, auth_result::Outcome::WrongPassword as i32);

        let right = accounts.authenticate(1, &auth("alice", "hunter2")).await;
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

        let stranger = accounts.authenticate(1, &auth("bob", "")).await;
        assert_eq!(stranger.outcome, auth_result::Outcome::NameTaken as i32);
    }

    #[tokio::test]
    async fn registering_a_taken_name_is_refused() {
        let accounts = accounts().await;
        let account = Account {
            name: "carol".to_owned(),
            ..Account::default()
        };
        let _ = accounts.register(1, account.clone(), "").await.expect("first");
        assert!(accounts.register(1, account, "").await.is_err());
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
}
