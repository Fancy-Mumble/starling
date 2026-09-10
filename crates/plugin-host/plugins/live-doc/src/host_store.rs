//! Documents kept in the server's own storage, through the plugin host.
//!
//! The other half of `persistence`, and the one that should win. That module
//! stores a document by HTTP-ing it to a *sibling plugin* with an admin token,
//! which only exists because the server offered plugins nowhere to write. It
//! does now (`docs/STORAGE-UNIFICATION.md` D5), so a document is an object in
//! this plugin's own namespace with a name pointing at it, and the share list
//! is a key in this plugin's own storage.
//!
//! What that buys, stated plainly: a server needs no file-server plugin, no
//! `file_server_url`, and no admin token for live documents to survive a
//! restart. The old path stays for servers still configured that way.
//!
//! **A document belongs to whichever store answered for it.** `state` records
//! that the first time one does and keeps it, so a document seeded from the
//! plugin is saved to the plugin and one seeded from here is saved here. That
//! matters because nothing here can tell a host without storage from a host
//! whose storage failed for a moment - `name_latest` answers nothing in both
//! cases - so a per-call decision would eventually seed from one store and
//! save to the other, writing whichever copy was older over the newer one.
//!
//! **Every host call goes through `spawn_blocking`.** The facade is sync FFI,
//! and on the far side the host does `Handle::block_on`; calling that from
//! inside this plugin's own runtime panics with "cannot start a runtime from
//! within a runtime". The bytes themselves move over HTTP to a signed URL, so
//! only the small calls are blocking ones.

use std::sync::Arc;

use crate::doc::{DocMeta, DocRoom};
use crate::host_facade::HostFacade;
use crate::persistence::{extract_meta, extract_snapshot, render_document};

/// Which key one document's share list lives under.
///
/// Prefixed rather than bare so this plugin's storage can grow other kinds of
/// record without a name colliding with a document's.
fn shared_key(filename: &str) -> Vec<u8> {
    format!("shared-with/{filename}").into_bytes()
}

/// Read one document back out of host storage.
///
/// `Ok(None)` is a document that has never been stored, which is the ordinary
/// first-open answer. `Err` is a host that could not be reached, and the
/// caller must not treat that as an empty document - overwriting a stored one
/// with a blank room is the failure this whole module exists to avoid.
pub(crate) async fn load(
    ctx: &Arc<dyn HostFacade>,
    http: &reqwest::Client,
    server_id: u32,
    filename: &str,
) -> Result<Option<String>, String> {
    let owned = Arc::clone(ctx);
    let name = filename.to_owned();
    let key = tokio::task::spawn_blocking(move || owned.name_latest(server_id, &name))
        .await
        .map_err(|error| format!("host call failed: {error}"))?;
    let Some(key) = key else {
        return Ok(None);
    };

    let owned = Arc::clone(ctx);
    let url = tokio::task::spawn_blocking(move || owned.object_url(server_id, &key))
        .await
        .map_err(|error| format!("host call failed: {error}"))?
        .ok_or_else(|| "the host would not sign a read for a document it named".to_owned())?;

    let body = http
        .get(&url)
        .send()
        .await
        .map_err(|error| format!("fetching the document failed: {error}"))?;
    if !body.status().is_success() {
        return Err(format!("fetching the document failed: {}", body.status()));
    }
    let text = body
        .text()
        .await
        .map_err(|error| format!("reading the document failed: {error}"))?;
    Ok(Some(text))
}

/// Write one document into host storage.
///
/// Every revision is kept: a document's history is the point of it, and
/// trimming is the caller's decision to make later rather than this one's.
pub(crate) async fn save(
    ctx: &Arc<dyn HostFacade>,
    http: &reqwest::Client,
    server_id: u32,
    filename: &str,
    snapshot: &[u8],
    meta: &DocMeta,
) -> Result<(), String> {
    let body = render_document(snapshot, meta);
    let size = body.len() as u64;

    let owned = Arc::clone(ctx);
    let name = filename.to_owned();
    let slot = tokio::task::spawn_blocking(move || owned.object_reserve(server_id, &name, size))
        .await
        .map_err(|error| format!("host call failed: {error}"))?
        .ok_or_else(|| "the host would not open a slot for the document".to_owned())?;

    let sent = http
        .put(slot.url.to_string())
        .body(body)
        .send()
        .await
        .map_err(|error| format!("storing the document failed: {error}"))?;
    if !sent.status().is_success() {
        return Err(format!("storing the document failed: {}", sent.status()));
    }

    // The name last: an object nothing points at is collectable waste, while a
    // name pointing at bytes that never arrived is a document that reads as
    // empty. Only one of those loses work.
    let owned = Arc::clone(ctx);
    let name = filename.to_owned();
    let key = slot.key.to_string();
    tokio::task::spawn_blocking(move || owned.name_put(server_id, &name, &key, 0))
        .await
        .map_err(|error| format!("host call failed: {error}"))?
        .map(|_| ())
        .map_err(|error| format!("naming the document failed: {error}"))
}

/// The share list for one document, as this plugin stored it.
pub(crate) async fn shared_with(
    ctx: &Arc<dyn HostFacade>,
    server_id: u32,
    filename: &str,
) -> Option<Vec<String>> {
    let ctx = Arc::clone(ctx);
    let key = shared_key(filename);
    let stored = tokio::task::spawn_blocking(move || ctx.kv_get(server_id, &key))
        .await
        .ok()
        .flatten()?;
    serde_json::from_slice(&stored).ok()
}

/// Replace the share list for one document.
pub(crate) async fn set_shared_with(
    ctx: &Arc<dyn HostFacade>,
    server_id: u32,
    filename: &str,
    members: &[String],
) -> Result<(), String> {
    let value = serde_json::to_vec(members).map_err(|error| error.to_string())?;
    let ctx = Arc::clone(ctx);
    let key = shared_key(filename);
    tokio::task::spawn_blocking(move || ctx.kv_put(server_id, &key, &value))
        .await
        .map_err(|error| format!("host call failed: {error}"))?
        .map_err(|error| format!("storing the share list failed: {error}"))
}

/// Seed a room from host storage, saying whether it is now safe to persist.
///
/// The distinction is the same one `persistence::try_seed_room` draws: a room
/// that could not be read from is a room whose stored contents are unknown,
/// and flushing it would write a blank document over a real one.
pub(crate) async fn try_seed_room(
    ctx: &Arc<dyn HostFacade>,
    http: &reqwest::Client,
    server_id: u32,
    room: &DocRoom,
) -> bool {
    let filename = room.key().as_filename();
    match load(ctx, http, server_id, &filename).await {
        Ok(Some(contents)) => {
            // This crate is on edition 2021, where a let-chain does not parse.
            if let Some(snapshot) = extract_snapshot(&contents) {
                if let Err(error) = room.seed_from_snapshot(&snapshot).await {
                    // The bytes are there and unreadable, which is not the
                    // same as absent: persisting over them would destroy a
                    // document whose only problem may be this build.
                    tracing::warn!(
                        ?error,
                        ?filename,
                        "live-doc could not apply a stored snapshot"
                    );
                    return false;
                }
            }
            if let Some(meta) = extract_meta(&contents) {
                room.set_meta(meta).await;
            }
            if let Some(members) = shared_with(ctx, server_id, &filename).await {
                for member in members {
                    room.add_member(member).await;
                }
            }
            room.mark_persist_safe().await;
            true
        }
        Ok(None) => {
            // Never stored: a new document, and safe to persist.
            room.mark_persist_safe().await;
            true
        }
        Err(error) => {
            tracing::warn!(%error, ?filename, "live-doc could not read the document from host storage");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use std::sync::Mutex;

    use mumble_plugin_api::{ObjectSlot, Permissions, PluginError};

    use super::*;
    use crate::host_facade::{FacadeResult, PluginMessageArgs};

    /// A host whose storage answers, recording the order it was called in.
    #[derive(Debug, Default)]
    struct Fake {
        /// Every storage call, in order, so an ordering rule can be asserted
        /// rather than assumed.
        calls: Mutex<Vec<String>>,
        /// What `name_latest` answers with.
        named: Mutex<Option<String>>,
        /// Whether the host has storage at all.
        has_storage: bool,
        kv: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    }

    impl Fake {
        fn with_storage() -> Arc<Self> {
            Arc::new(Self {
                has_storage: true,
                ..Self::default()
            })
        }

        fn note(&self, what: &str) {
            self.calls.lock().unwrap().push(what.to_owned());
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl HostFacade for Fake {
        fn send_plugin_data(
            &self,
            _server_id: u32,
            _target_session: u32,
            _data_id: &str,
            _data: &[u8],
        ) -> FacadeResult<()> {
            Ok(())
        }

        fn is_session_active(&self, _server_id: u32, _session: u32) -> bool {
            true
        }

        fn user_has_channel_access(&self, _server_id: u32, _session: u32, _channel: u32) -> bool {
            true
        }

        fn has_permission(
            &self,
            _server_id: u32,
            _session: u32,
            _channel: u32,
            _perm: Permissions,
        ) -> bool {
            true
        }

        fn get_config(&self, _key: &str) -> Option<String> {
            None
        }

        fn send_plugin_message(&self, _args: PluginMessageArgs<'_>) -> FacadeResult<()> {
            Ok(())
        }

        fn object_reserve(
            &self,
            _server_id: u32,
            _filename: &str,
            _size: u64,
        ) -> Option<ObjectSlot> {
            self.note("object_reserve");
            self.has_storage.then(|| ObjectSlot {
                key: "p/fancy-live-doc/018f/notes.md".into(),
                url: "http://127.0.0.1:1/p/fancy-live-doc/018f/notes.md".into(),
                method: "PUT".into(),
                expires_at_ms: 0,
            })
        }

        fn object_url(&self, _server_id: u32, _key: &str) -> Option<String> {
            self.note("object_url");
            self.has_storage
                .then(|| "http://127.0.0.1:1/read".to_owned())
        }

        fn name_put(
            &self,
            _server_id: u32,
            _name: &str,
            _key: &str,
            _keep: u64,
        ) -> FacadeResult<u64> {
            self.note("name_put");
            if self.has_storage {
                Ok(1)
            } else {
                Err(PluginError::Other("no storage".into()))
            }
        }

        fn name_latest(&self, _server_id: u32, _name: &str) -> Option<String> {
            self.note("name_latest");
            self.named.lock().unwrap().clone()
        }

        fn kv_get(&self, _server_id: u32, key: &[u8]) -> Option<Vec<u8>> {
            self.note("kv_get");
            self.kv
                .lock()
                .unwrap()
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
        }

        fn kv_put(&self, _server_id: u32, key: &[u8], value: &[u8]) -> FacadeResult<()> {
            self.note("kv_put");
            if !self.has_storage {
                return Err(PluginError::Other("no storage".into()));
            }
            let Ok(mut kv) = self.kv.lock() else {
                return Err(PluginError::Other("poisoned".into()));
            };
            kv.push((key.to_vec(), value.to_vec()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_name_nothing_has_been_stored_under_is_absent_rather_than_an_error() {
        // The ordinary first open. An error here would make the caller refuse
        // to persist, so a brand-new document would never be saved at all.
        let fake = Fake::with_storage();
        let ctx: Arc<dyn HostFacade> = fake.clone();

        let loaded = load(&ctx, &reqwest::Client::new(), 1, "notes").await;

        assert!(matches!(loaded, Ok(None)));
        assert_eq!(fake.calls(), vec!["name_latest".to_owned()]);
    }

    #[tokio::test]
    async fn a_host_with_no_storage_reports_an_error_rather_than_an_empty_document() {
        // The distinction the fallback turns on: "this host keeps nothing" must
        // not read as "this document is empty", or the file-server copy would
        // be overwritten by a blank one.
        let fake = Arc::new(Fake::default());
        let ctx: Arc<dyn HostFacade> = fake.clone();

        let saved = save(
            &ctx,
            &reqwest::Client::new(),
            1,
            "notes",
            b"snapshot",
            &DocMeta::default(),
        )
        .await;

        assert!(
            saved.is_err(),
            "a host without storage must not report success"
        );
    }

    #[tokio::test]
    async fn the_bytes_are_stored_before_the_name_points_at_them() {
        // Ordering is the whole safety property here. A name written first
        // would, if the upload then failed, point at bytes that never arrived -
        // and the document would open empty. The other way round leaves an
        // unreferenced object, which is collectable waste and loses nothing.
        let fake = Fake::with_storage();
        let ctx: Arc<dyn HostFacade> = fake.clone();

        // The upload goes to a port nothing listens on, so it fails.
        let saved = save(
            &ctx,
            &reqwest::Client::new(),
            1,
            "notes",
            b"snapshot",
            &DocMeta::default(),
        )
        .await;

        assert!(saved.is_err());
        assert_eq!(
            fake.calls(),
            vec!["object_reserve".to_owned()],
            "the name must not be written when the bytes did not arrive"
        );
    }

    #[tokio::test]
    async fn a_share_list_reads_back_as_it_was_written() {
        let fake = Fake::with_storage();
        let ctx: Arc<dyn HostFacade> = fake.clone();
        let members = vec!["aa".to_owned(), "bb".to_owned()];

        set_shared_with(&ctx, 1, "notes", &members).await.unwrap();

        assert_eq!(shared_with(&ctx, 1, "notes").await, Some(members));
    }

    #[tokio::test]
    async fn a_share_list_for_a_document_nobody_shared_is_absent() {
        let fake = Fake::with_storage();
        let ctx: Arc<dyn HostFacade> = fake.clone();

        assert_eq!(shared_with(&ctx, 1, "notes").await, None);
    }

    #[tokio::test]
    async fn one_documents_share_list_is_not_anothers() {
        let fake = Fake::with_storage();
        let ctx: Arc<dyn HostFacade> = fake.clone();

        set_shared_with(&ctx, 1, "notes", &["aa".to_owned()])
            .await
            .unwrap();

        assert_eq!(shared_with(&ctx, 1, "other").await, None);
    }
}
