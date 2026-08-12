//! Writing operational settings that came from somewhere else.
//!
//! murmur keeps its settings in two places and means the same thing by both: a
//! `mumble-server.ini` states what the server starts with, and its `config`
//! **table** holds what an operator changed while it was running, key for key,
//! overriding the file. `starling migrate-config` already carries the file into
//! `[instances.settings]`; this carries the table, which is the half that
//! contains everything anybody actually adjusted after the first day.
//!
//! # The `owned` column is the whole design
//!
//! A stored snapshot here is not "the settings". It is *the settings an operator
//! chose*, listed by name, layered over the deployment file's defaults at boot
//! (`starting_point`). An import that wrote the whole snapshot and claimed every
//! field would freeze the server at murmur's defaults for every setting the
//! operator never touched, and the deployment file would silently stop meaning
//! anything.
//!
//! So this claims exactly the fields murmur's `config` table actually held, and
//! nothing else.

use std::collections::BTreeSet;

use prost::Message as _;
use starling_proto_fancy::serverconfig::Snapshot;
use starling_runtime::config::ServerSettings;
use starling_runtime::storage::{Store, StoreError};

use crate::snapshot::defaults;

/// Write `settings` as the stored configuration for server instance `scope`.
///
/// Returns the field names it claimed, so a migration can report what it moved
/// rather than a bare "done". An empty list means murmur's `config` table said
/// nothing this build understands, which is a perfectly ordinary outcome for a
/// server whose operator only ever edited the `.ini`.
///
/// # Errors
///
/// [`StoreError`] if the schema cannot be applied or the row cannot be written.
/// Unlike the other importers this one **is** fatal on a failed write: it is a
/// single row, so there is no partial state to preserve, and a server that came
/// up with murmur's limits silently replaced by Starling's defaults is the kind
/// of failure nobody notices until somebody hits one.
pub async fn import(
    store: &Store,
    scope: u32,
    settings: &ServerSettings,
) -> Result<Vec<String>, StoreError> {
    store.migrate(crate::SCHEMA).await?;

    let mut snapshot = defaults(scope);
    // `overlay` writes only the fields that are `Some` and hands back their
    // names. That list is the whole point: it is what an operator stated, and
    // therefore exactly what the stored row may claim.
    let named = settings.overlay(&mut snapshot);
    let owned: BTreeSet<String> = named.iter().cloned().collect();

    // Merged rather than replaced, for the same reason the service merges:
    // a re-run, or an import over a server somebody has already configured,
    // must not un-claim fields that were claimed before it.
    let existing = stored_fields(store, scope).await;
    let owned: BTreeSet<String> = owned.union(&existing).cloned().collect();

    sqlx::query(
        "INSERT INTO server_config (server_id, version, settings, owned) VALUES (?, ?, ?, ?) \
         ON CONFLICT (server_id) DO UPDATE SET version = excluded.version, \
         settings = excluded.settings, owned = excluded.owned",
    )
    .bind(i64::from(scope))
    .bind(snapshot.version as i64)
    .bind(snapshot.encode_to_vec())
    .bind(
        owned
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .execute(store.pool())
    .await
    .map(|_| ())
    .map_err(|error| StoreError::Query(format!("server_config: {error}")))?;

    Ok(named)
}

/// Which fields the stored row already claims.
///
/// Absent, unreadable, or the `*` marker a pre-`owned` row carries: all three
/// answer "nothing new to preserve". `*` in particular must not be added to a
/// set that is about to be written as a list of field names, since it is a
/// marker rather than a field, and a row claiming a field called `*` claims
/// nothing at all.
async fn stored_fields(store: &Store, scope: u32) -> BTreeSet<String> {
    use sqlx::Row as _;
    let Ok(Some(row)) = sqlx::query("SELECT owned FROM server_config WHERE server_id = ?")
        .bind(i64::from(scope))
        .fetch_optional(store.pool())
        .await
    else {
        return BTreeSet::new();
    };
    row.try_get::<String, _>("owned")
        .unwrap_or_default()
        .split('\n')
        .filter(|field| !field.is_empty() && *field != "*")
        .map(ToOwned::to_owned)
        .collect()
}

/// The stored snapshot for `scope`, if there is one.
///
/// For `--verify`, which re-reads what it wrote rather than trusting the write.
pub async fn stored(store: &Store, scope: u32) -> Option<Snapshot> {
    use sqlx::Row as _;
    let row = sqlx::query("SELECT settings FROM server_config WHERE server_id = ?")
        .bind(i64::from(scope))
        .fetch_optional(store.pool())
        .await
        .ok()??;
    let bytes: Vec<u8> = row.try_get("settings").ok()?;
    Snapshot::decode(bytes.as_slice()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> Store {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        Store::open(
            &format!("sqlite:file:server-config-import-{id}?mode=memory&cache=shared"),
            1,
        )
        .await
        .expect("an in-memory database")
    }

    #[tokio::test]
    async fn the_settings_murmur_held_are_the_settings_that_are_stored() {
        let store = store().await;
        let settings = ServerSettings {
            max_users: Some(42),
            welcome_text: Some("hello".to_owned()),
            ..ServerSettings::default()
        };
        let named = import(&store, 1, &settings).await.expect("import");
        assert!(named.contains(&"max_users".to_owned()), "{named:?}");

        let stored = stored(&store, 1).await.expect("a stored snapshot");
        assert_eq!(stored.max_users, 42);
        assert_eq!(stored.welcome_text, "hello");
    }

    #[tokio::test]
    async fn a_setting_murmur_never_held_is_not_claimed() {
        // Claiming everything would freeze the server at murmur's defaults for
        // every setting nobody touched, and the deployment file would quietly
        // stop meaning anything from then on.
        let store = store().await;
        let named = import(
            &store,
            1,
            &ServerSettings {
                max_users: Some(42),
                ..ServerSettings::default()
            },
        )
        .await
        .expect("import");

        assert_eq!(named, vec!["max_users".to_owned()]);
        assert_eq!(stored_fields(&store, 1).await.len(), 1);
    }

    #[tokio::test]
    async fn importing_over_an_existing_row_adds_to_it_rather_than_replacing_it() {
        // A second pass, or an import onto a server somebody already configured.
        // Un-claiming a field here would hand it back to the deployment file
        // without anyone asking.
        let store = store().await;
        let _ = import(
            &store,
            1,
            &ServerSettings {
                max_users: Some(42),
                ..ServerSettings::default()
            },
        )
        .await
        .expect("first");
        let _ = import(
            &store,
            1,
            &ServerSettings {
                allow_html: Some(false),
                ..ServerSettings::default()
            },
        )
        .await
        .expect("second");

        let fields = stored_fields(&store, 1).await;
        assert!(fields.contains("max_users"), "{fields:?}");
        assert!(fields.contains("allow_html"), "{fields:?}");
    }

    #[tokio::test]
    async fn an_empty_block_stores_a_row_that_claims_nothing() {
        // Which is what a server whose operator only ever edited the `.ini`
        // migrates to, and it must not be an error.
        let store = store().await;
        let named = import(&store, 1, &ServerSettings::default())
            .await
            .expect("import");
        assert!(named.is_empty());
        assert!(stored(&store, 1).await.is_some());
    }
}
