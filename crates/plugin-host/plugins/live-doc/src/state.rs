//! Process-global state shared by the WS server and the plugin
//! lifecycle hooks.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use mumble_plugin_api::{ChannelId, ServerId, SessionId};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::config::LiveDocConfig;
use crate::doc::{DocKey, DocMeta, DocRoom};
use crate::host_facade::HostFacade;
use crate::host_store;
use crate::persistence::{
    SharedMember, fetch_shared_with_members, persist_room, record_shared_with, try_seed_room,
};

/// Stable identity of a connected session, captured from `ClientInfo`
/// at connect time so the document layer can attribute ownership and
/// shares without a per-call host round-trip.
#[derive(Debug, Clone, Default)]
pub struct Identity {
    /// Stable hex-encoded SHA-1 of the client's TLS cert (may be empty
    /// for a guest with no certificate).
    pub cert_hash: String,
    /// Registered Mumble user id, or `-1` for a guest.
    pub user_id: i64,
    /// Display name at connect time.
    pub name: String,
}

/// Wallclock state shared across the plugin.
#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

/// Which store a document was seeded from, and therefore where it is saved.
///
/// Recorded per document rather than decided per call. A server can have both
/// stores configured, and the two are not kept in step: seeding from one and
/// saving to the other writes whichever copy was older over whichever was
/// newer. Nothing about a *probe* can prevent that reliably - a host with
/// storage that fails transiently is indistinguishable from one without - so
/// the decision is made once, when a store actually answers, and then kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocStore {
    /// The server's own object and name store, through the plugin host.
    Host,
    /// The file-server plugin, over HTTP.
    Plugin,
}

#[derive(Debug)]
struct AppStateInner {
    cfg: Arc<LiveDocConfig>,
    ctx: Arc<dyn HostFacade>,
    jwt_secret: Vec<u8>,
    /// Shared HTTP client used for all file-server I/O.  Configured
    /// with a tight per-request timeout so a slow / unreachable
    /// file-server can't wedge the live-doc state machine.
    http_client: reqwest::Client,
    rooms: Mutex<HashMap<DocKey, RoomEntry>>,
    /// Connected-session identities captured from `ClientInfo`.
    identities: Mutex<HashMap<(ServerId, SessionId), Identity>>,
    /// Access-control metadata cached independently of the live room, so
    /// a teardown (which frees the CRDT room) never drops *who* may
    /// reconnect.  Without this, a recreated room could only recover the
    /// owner / share list from the file-server; if that persistence is
    /// not configured the legitimate owner would be locked out and the
    /// client would retry the handshake forever.  Keyed by [`DocKey`].
    acls: Mutex<HashMap<DocKey, CachedAcl>>,
    /// Which store each document belongs to, once one has answered for it.
    ///
    /// Outlives the room for the same reason [`AppStateInner::acls`] does: a
    /// document torn down and reopened must not get a second chance to pick a
    /// different store, because that is precisely how the older copy wins.
    stores: Mutex<HashMap<DocKey, DocStore>>,
}

/// Cached access-control state for a document, retained across room
/// teardown so the owner and recorded share recipients can always
/// reconnect within the process lifetime.
#[derive(Debug, Clone)]
struct CachedAcl {
    /// Document metadata (owner, title, channel binding, visibility) as
    /// of the last time the room was torn down.
    meta: DocMeta,
    /// Cert hashes the document had been shared with (besides the owner).
    shared_with: HashSet<String>,
}

#[derive(Debug)]
struct RoomEntry {
    room: Arc<DocRoom>,
    /// Sessions currently editing this doc.  Cleared when the WS
    /// drops or the client disconnects from Mumble.
    sessions: Vec<SessionId>,
    /// Background teardown task scheduled when the last subscriber
    /// left.  Reset to `None` if someone re-joins inside the grace
    /// window.
    teardown_task: Option<JoinHandle<()>>,
}

/// Maximum time a single file-server request is allowed to take
/// before reqwest aborts it.  Tight on purpose so a stuck file-server
/// can't stall the whole plugin.
const FILE_SERVER_TIMEOUT_SECS: u64 = 5;
/// Maximum time we allow for the initial TCP connect to the
/// file-server.  Separate from the overall request timeout so that
/// "host unreachable" fails fast instead of eating the full budget.
const FILE_SERVER_CONNECT_TIMEOUT_SECS: u64 = 2;

impl AppState {
    /// Construct fresh state and load (or generate) the JWT secret.
    pub fn new(cfg: Arc<LiveDocConfig>, ctx: Arc<dyn HostFacade>) -> Self {
        let jwt_secret = cfg
            .jwt_secret
            .as_ref()
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_else(generate_secret);
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(FILE_SERVER_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(FILE_SERVER_CONNECT_TIMEOUT_SECS))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            inner: Arc::new(AppStateInner {
                cfg,
                ctx,
                jwt_secret,
                http_client,
                rooms: Mutex::new(HashMap::new()),
                identities: Mutex::new(HashMap::new()),
                acls: Mutex::new(HashMap::new()),
                stores: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Record a connected session's identity (called from the Mumble
    /// `on_client_connected` hook).
    pub async fn set_identity(&self, server_id: ServerId, session: SessionId, identity: Identity) {
        let _ = self
            .inner
            .identities
            .lock()
            .await
            .insert((server_id, session), identity);
    }

    /// Look up a connected session's identity.
    pub async fn identity(&self, server_id: ServerId, session: SessionId) -> Option<Identity> {
        self.inner
            .identities
            .lock()
            .await
            .get(&(server_id, session))
            .cloned()
    }

    /// Configuration handle.
    pub fn cfg(&self) -> &LiveDocConfig {
        &self.inner.cfg
    }

    /// JWT signing secret bytes.
    pub fn jwt_secret(&self) -> &[u8] {
        &self.inner.jwt_secret
    }

    /// Plugin context handle.
    pub fn ctx(&self) -> &Arc<dyn HostFacade> {
        &self.inner.ctx
    }

    /// Get-or-create a room for the given key.
    ///
    /// On creation, the room is inserted into the registry *before*
    /// seeding so the registry mutex isn't held across the
    /// file-server HTTP call.  Concurrent callers all observe the
    /// same `Arc<DocRoom>`; the seed and any client edits are
    /// applied to the shared doc and commute via Yjs CRDT semantics,
    /// so it does not matter which happens first.
    pub async fn ensure_room(&self, key: DocKey) -> Arc<DocRoom> {
        let (room, needs_seed) = {
            let mut rooms = self.inner.rooms.lock().await;
            if let Some(existing) = rooms.get_mut(&key) {
                if let Some(t) = existing.teardown_task.take() {
                    t.abort();
                }
                (existing.room.clone(), false)
            } else {
                let room = Arc::new(DocRoom::new(key.clone()));
                let _ = rooms.insert(
                    key,
                    RoomEntry {
                        room: room.clone(),
                        sessions: Vec::new(),
                        teardown_task: None,
                    },
                );
                (room, true)
            }
        };
        if needs_seed {
            self.seed_room(&room).await;
            // Overlay the cached ACL so an owner / share grant established
            // earlier this process survives a teardown even when neither
            // store answered.
            self.restore_acl(&room).await;
        }
        room
    }

    /// Which server instance this plugin's storage is scoped to.
    ///
    /// The host keys plugin storage by the instance it serves, and this plugin
    /// is loaded once per host, so there is one answer. Named rather than
    /// spelled `1` at six call sites.
    fn storage_scope(&self) -> u32 {
        1
    }

    /// Seed a room, from host storage where the host has any.
    ///
    /// The host's own store first: it needs no sibling plugin, no admin token
    /// and no configuration, so a server that has it is already set up. The
    /// file-server path is tried only when the host has no storage, which is
    /// what an older server looks like.
    async fn seed_room(&self, room: &DocRoom) {
        // A document that has already chosen a store keeps it, whatever either
        // store says today: re-deciding is how a stale copy gets promoted.
        if let Some(store) = self.store_of(room.key()).await {
            match store {
                DocStore::Host => {
                    let _ = host_store::try_seed_room(
                        &self.inner.ctx,
                        &self.inner.http_client,
                        self.storage_scope(),
                        room,
                    )
                    .await;
                }
                DocStore::Plugin => {
                    try_seed_room(&self.inner.cfg, &self.inner.http_client, room).await;
                }
            }
            return;
        }

        if host_store::try_seed_room(
            &self.inner.ctx,
            &self.inner.http_client,
            self.storage_scope(),
            room,
        )
        .await
        {
            self.remember_store(room.key(), DocStore::Host).await;
            return;
        }
        try_seed_room(&self.inner.cfg, &self.inner.http_client, room).await;
        // Only when the plugin is actually configured: without a URL its seed
        // is a warning and nothing else, and binding the document to a store
        // that cannot answer would keep it from ever reaching the host.
        if self.inner.cfg.file_server_url.is_some() {
            self.remember_store(room.key(), DocStore::Plugin).await;
        }
    }

    /// Which store this document belongs to, if one has answered for it.
    async fn store_of(&self, key: &DocKey) -> Option<DocStore> {
        self.inner.stores.lock().await.get(key).copied()
    }

    /// Bind a document to the store that answered for it.
    ///
    /// First writer wins: a document that already has a store keeps it, which
    /// is the whole point of recording one.
    async fn remember_store(&self, key: &DocKey, store: DocStore) {
        let _ = self
            .inner
            .stores
            .lock()
            .await
            .entry(key.clone())
            .or_insert(store);
    }

    /// Persist a room, to host storage where the host has any.
    ///
    /// Guarded by `is_persist_safe` before either path, for the reason the
    /// file-server path documents: a room that never confirmed its state
    /// against storage would otherwise flush an empty document over a real one.
    async fn save_room(&self, room: &DocRoom) {
        if !room.is_persist_safe().await {
            tracing::warn!("live-doc skipping persist: room state not confirmed against storage");
            return;
        }
        let snapshot = room.encode_snapshot();
        let meta = room.meta().await;
        if snapshot.is_empty() && meta.owner_cert_hash.is_empty() {
            return;
        }
        let filename = room.key().as_filename();

        // The store this document was seeded from, and only that one. A save
        // that fell through to the other store on an error would write this
        // room's state over a copy it was never compared against.
        if self.store_of(room.key()).await == Some(DocStore::Plugin) {
            persist_room(&self.inner.cfg, &self.inner.http_client, room).await;
            return;
        }

        match host_store::save(
            &self.inner.ctx,
            &self.inner.http_client,
            self.storage_scope(),
            &filename,
            &snapshot,
            &meta,
        )
        .await
        {
            Ok(()) => {
                self.remember_store(room.key(), DocStore::Host).await;
                room.mark_saved().await;
            }
            Err(error) => {
                // Not marked saved, so the next flush tries again. Falling
                // through to the plugin here is what this exists to prevent.
                tracing::warn!(%error, ?filename, "live-doc could not save the document");
            }
        }
    }

    /// Re-apply a previously cached ACL onto a freshly-created room.
    ///
    /// The cached metadata only fills in the owner when seeding produced
    /// none (file-server unavailable or first open), so an authoritative
    /// file-server record always wins.  Share recipients are unioned in,
    /// never dropped.
    async fn restore_acl(&self, room: &DocRoom) {
        let cached = {
            let acls = self.inner.acls.lock().await;
            acls.get(room.key()).cloned()
        };
        let Some(cached) = cached else {
            return;
        };
        if room.meta().await.owner_cert_hash.is_empty() {
            room.set_meta(cached.meta).await;
        }
        #[expect(
            clippy::iter_over_hash_type,
            reason = "every member is added; the set does not depend on the order they arrive"
        )]
        for cert in cached.shared_with {
            room.add_member(cert).await;
        }
    }

    /// Snapshot a room's current access-control state into the cache so it
    /// outlives the room.  Rooms with no claimed owner carry no grant
    /// worth preserving and are skipped.
    async fn remember_acl(&self, key: &DocKey, room: &DocRoom) {
        let meta = room.meta().await;
        if meta.owner_cert_hash.is_empty() {
            return;
        }
        let shared_with = room.members().await;
        let _ = self
            .inner
            .acls
            .lock()
            .await
            .insert(key.clone(), CachedAcl { meta, shared_with });
    }

    /// Mark a session as actively subscribed to a room.  Idempotent.
    pub async fn register_session(&self, key: &DocKey, session: SessionId) {
        let mut rooms = self.inner.rooms.lock().await;
        let Some(entry) = rooms.get_mut(key) else {
            return;
        };
        if !entry.sessions.contains(&session) {
            entry.sessions.push(session);
        }
        if let Some(t) = entry.teardown_task.take() {
            t.abort();
        }
    }

    /// Unregister a session.  If the room becomes empty, schedules a
    /// teardown after [`LiveDocConfig::teardown_grace_secs`] which
    /// persists the final snapshot and evicts the room.
    pub async fn unregister_session(&self, key: &DocKey, session: SessionId) {
        let mut rooms = self.inner.rooms.lock().await;
        let Some(entry) = rooms.get_mut(key) else {
            return;
        };
        entry.sessions.retain(|s| *s != session);
        if entry.sessions.is_empty() && entry.teardown_task.is_none() {
            entry.teardown_task = Some(self.spawn_teardown(key.clone()));
        }
    }

    /// Drop sessions belonging to a disconnected client across every
    /// room.  Called from the Mumble `on_client_disconnected` hook.
    pub async fn handle_client_gone(&self, server_id: ServerId, session: SessionId) {
        let _ = self
            .inner
            .identities
            .lock()
            .await
            .remove(&(server_id, session));
        let mut to_teardown: Vec<DocKey> = Vec::new();
        let mut rooms = self.inner.rooms.lock().await;
        #[expect(
            clippy::iter_over_hash_type,
            reason = "each room is torn down independently of the others"
        )]
        for (key, entry) in rooms.iter_mut() {
            if key.server_id != server_id {
                continue;
            }
            entry.sessions.retain(|s| *s != session);
            if entry.sessions.is_empty() && entry.teardown_task.is_none() {
                to_teardown.push(key.clone());
            }
        }
        drop(rooms);
        for key in to_teardown {
            let mut rooms = self.inner.rooms.lock().await;
            if let Some(entry) = rooms.get_mut(&key) {
                entry.teardown_task = Some(self.spawn_teardown(key.clone()));
            }
        }
    }

    /// Returns `true` if the session is active and holds enter +
    /// text-message permission on `channel_id`.  Used at *open* time to
    /// decide whether a channel grants access to a published document.
    pub fn has_channel_permission(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel_id: ChannelId,
    ) -> bool {
        use mumble_plugin_api::Permissions;
        let ctx = &self.inner.ctx;
        ctx.is_session_active(server_id, session)
            && ctx.has_permission(
                server_id,
                session,
                channel_id,
                Permissions::ENTER | Permissions::TEXT_MESSAGE,
            )
    }

    /// Returns `true` if the session is a server administrator (holds `Write`
    /// on the root channel).  Admins may open any document - consistent with
    /// the admin file-server documents dashboard, which can already list,
    /// preview and delete every document.
    pub fn is_server_admin(&self, server_id: ServerId, session: SessionId) -> bool {
        use mumble_plugin_api::Permissions;
        let ctx = &self.inner.ctx;
        ctx.is_session_active(server_id, session)
            && ctx.has_permission(server_id, session, 0, Permissions::WRITE)
    }

    /// Returns `true` if the session may *connect* to the document's WS:
    /// the session is active and its identity is the owner or a recorded
    /// share recipient.  Re-checked live at every connect so a revoked
    /// grant cannot ride an unexpired token.
    pub async fn session_can_connect(
        &self,
        server_id: ServerId,
        session: SessionId,
        key: &DocKey,
    ) -> bool {
        if !self.inner.ctx.is_session_active(server_id, session) {
            return false;
        }
        let Some(identity) = self.identity(server_id, session).await else {
            return false;
        };
        let room = {
            let rooms = self.inner.rooms.lock().await;
            rooms.get(key).map(|e| e.room.clone())
        };
        match room {
            Some(room) => {
                let meta = room.meta().await;
                // Same ownership resolution as the open path (and the
                // file-server): stable user id, cert hash, recorded share, or
                // server admin - so a uid-owner whose cert rotated can still
                // connect to their own document's WS.
                mumble_plugin_api::identity_owns(
                    identity.user_id,
                    &identity.cert_hash,
                    meta.owner_user_id,
                    &meta.owner_cert_hash,
                ) || room.is_member(&identity.cert_hash).await
                    || self.is_server_admin(server_id, session)
            }
            None => false,
        }
    }

    /// Record a share recipient for a document (persists to the
    /// file-server ACL and updates the room's in-memory set).
    pub async fn record_shared_with(&self, room: &DocRoom, identity: &Identity) {
        // The room's own set first, so access works this session whatever the
        // stores do; then the durable copy.
        room.add_member(identity.cert_hash.clone()).await;
        let members: Vec<String> = room.members().await.into_iter().collect();
        let filename = room.key().as_filename();
        if let Err(error) =
            host_store::set_shared_with(&self.inner.ctx, self.storage_scope(), &filename, &members)
                .await
        {
            tracing::debug!(%error, ?filename, "live-doc host storage unavailable; recording the share on the file-server");
            record_shared_with(
                &self.inner.cfg,
                &self.inner.http_client,
                room,
                &identity.cert_hash,
                identity.user_id,
                &identity.name,
            )
            .await;
        }
    }

    /// Persist a single room immediately (used after a metadata change).
    pub async fn persist_room_now(&self, room: &DocRoom) {
        self.save_room(room).await;
    }

    /// Fetch the document's shared-with member list (with display names)
    /// for surfacing to clients.
    pub async fn shared_with_members(&self, room: &DocRoom) -> Vec<SharedMember> {
        fetch_shared_with_members(&self.inner.cfg, &self.inner.http_client, room).await
    }

    /// Persist every room that has changed since its last flush.  Driven
    /// by the autosave loop.
    pub async fn persist_dirty_rooms(&self) {
        let rooms: Vec<Arc<DocRoom>> = {
            let guard = self.inner.rooms.lock().await;
            guard.values().map(|e| e.room.clone()).collect()
        };
        for room in rooms {
            if room.needs_persist().await {
                self.save_room(&room).await;
            }
        }
    }

    /// Persist every active room and forget them.  Called on plugin
    /// unload.
    pub async fn shutdown(&self) {
        let mut rooms = self.inner.rooms.lock().await;
        let to_persist: Vec<Arc<DocRoom>> = rooms.values().map(|e| e.room.clone()).collect();
        rooms.clear();
        drop(rooms);
        for room in to_persist {
            self.save_room(&room).await;
        }
    }

    fn spawn_teardown(&self, key: DocKey) -> JoinHandle<()> {
        let state = self.clone();
        let grace = Duration::from_secs(state.inner.cfg.teardown_grace_secs);
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            state.teardown_room(&key).await;
        })
    }

    async fn teardown_room(&self, key: &DocKey) {
        let room = {
            let mut rooms = self.inner.rooms.lock().await;
            let Some(entry) = rooms.get(key) else {
                return;
            };
            if !entry.sessions.is_empty() {
                return;
            }
            rooms.remove(key).map(|e| e.room)
        };
        if let Some(room) = room {
            // Preserve the access grant before the room (and its ACL) is
            // dropped, so the owner / share recipients can reconnect and
            // recreate the room without relying on the file-server.
            self.remember_acl(key, &room).await;
            self.save_room(&room).await;
            tracing::info!(?key, "live-doc room torn down");
        }
    }
}

fn generate_secret() -> Vec<u8> {
    use rand::Rng;
    let mut buf = vec![0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;
    use crate::doc::{DocMeta, Visibility};
    use crate::host_facade::{FacadeResult, HostFacade, PluginMessageArgs};
    use mumble_plugin_api::Permissions;
    use std::net::SocketAddr;

    /// Host stub that treats every session as active and authorised; the
    /// ACL itself is what these tests exercise.
    #[derive(Debug)]
    struct AllowCtx;

    impl HostFacade for AllowCtx {
        fn send_plugin_data(&self, _: u32, _: u32, _: &str, _: &[u8]) -> FacadeResult<()> {
            Ok(())
        }
        fn is_session_active(&self, _: u32, _: u32) -> bool {
            true
        }
        fn user_has_channel_access(&self, _: u32, _: u32, _: u32) -> bool {
            true
        }
        fn has_permission(&self, _: u32, _: u32, _: u32, perm: Permissions) -> bool {
            // Grant ordinary channel permissions, but not admin (root Write),
            // so the ACL under test isn't masked by the admin-override path.
            !perm.intersects(Permissions::WRITE)
        }
        fn get_config(&self, _: &str) -> Option<String> {
            None
        }
        fn send_plugin_message(&self, _: PluginMessageArgs<'_>) -> FacadeResult<()> {
            Ok(())
        }
    }

    /// Build state with the file-server intentionally *unconfigured*, so
    /// the tests prove access survives a teardown without it.
    fn test_state() -> AppState {
        let cfg = LiveDocConfig {
            bind: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            public_url: None,
            jwt_secret: Some("test-secret-0123456789abcdef0123456789".to_owned()),
            state_path: std::env::temp_dir(),
            max_update_bytes: 4 * 1024 * 1024,
            snapshot_idle_secs: 60,
            teardown_grace_secs: 30,
            file_server_url: None,
            file_server_admin_token: None,
            port: 0,
        };
        AppState::new(Arc::new(cfg), Arc::new(AllowCtx))
    }

    fn ident(cert: &str, session: i64) -> Identity {
        Identity {
            cert_hash: cert.to_owned(),
            user_id: session,
            name: format!("user-{session}"),
        }
    }

    /// The reported bug: an owner edits a doc, the room is torn down after
    /// the WS drops, and every reconnect is rejected as "not owner or
    /// share recipient" because the in-memory ACL died with the room and
    /// no file-server was available to rehydrate it.  The cached ACL must
    /// keep the owner and recorded share recipients connectable after a
    /// teardown.
    #[tokio::test]
    async fn owner_and_member_reconnect_after_teardown_without_file_server() {
        let state = test_state();
        let server_id = 1u32;
        state
            .set_identity(server_id, 2, ident("owner-cert", 2))
            .await;
        state
            .set_identity(server_id, 3, ident("friend-cert", 3))
            .await;
        state
            .set_identity(server_id, 4, ident("stranger-cert", 4))
            .await;

        let key = DocKey {
            server_id,
            slug: "my-document".into(),
        };

        // Owner opens the doc; a friend is recorded as a share recipient.
        let room = state.ensure_room(key.clone()).await;
        room.set_meta(DocMeta {
            owner_cert_hash: "owner-cert".into(),
            owner_user_id: None,
            title: "My Document".into(),
            bound_channel: None,
            visibility: Visibility::Private,
        })
        .await;
        room.add_member("friend-cert".into()).await;
        drop(room);

        assert!(
            state.session_can_connect(server_id, 2, &key).await,
            "owner before teardown"
        );
        assert!(
            state.session_can_connect(server_id, 3, &key).await,
            "friend before teardown"
        );

        // The viewer leaves and the grace teardown fires (invoked directly
        // here instead of waiting out the grace timer).
        state.register_session(&key, 2).await;
        state.unregister_session(&key, 2).await;
        state.teardown_room(&key).await;

        // A reconnect recreates the room from scratch (no file-server) and
        // must still admit the owner and the recorded share recipient,
        // while continuing to reject a stranger.
        let _ = state.ensure_room(key.clone()).await;
        assert!(
            state.session_can_connect(server_id, 2, &key).await,
            "owner must reconnect after teardown"
        );
        assert!(
            state.session_can_connect(server_id, 3, &key).await,
            "share recipient must reconnect after teardown"
        );
        assert!(
            !state.session_can_connect(server_id, 4, &key).await,
            "stranger must still be rejected after teardown"
        );
    }

    /// A document that has chosen a store keeps it.
    ///
    /// The failure this prevents: a server with both stores configured, a
    /// transient host error at open, a seed from the plugin's older copy, and
    /// then a save that puts that older state into the host - where it is now
    /// the newest thing there and the real edit is gone.
    #[tokio::test]
    async fn a_document_is_saved_to_the_store_it_was_seeded_from() {
        let state = test_state();
        let key = DocKey {
            server_id: 1,
            slug: "notes".to_owned(),
        };

        state.remember_store(&key, DocStore::Plugin).await;

        assert_eq!(state.store_of(&key).await, Some(DocStore::Plugin));
    }

    #[tokio::test]
    async fn a_documents_store_is_decided_once_and_not_again() {
        // Re-deciding is exactly how the older copy gets promoted, so the
        // second answer is ignored rather than allowed to win.
        let state = test_state();
        let key = DocKey {
            server_id: 1,
            slug: "notes".to_owned(),
        };

        state.remember_store(&key, DocStore::Host).await;
        state.remember_store(&key, DocStore::Plugin).await;

        assert_eq!(state.store_of(&key).await, Some(DocStore::Host));
    }

    #[tokio::test]
    async fn a_document_nothing_has_answered_for_has_no_store_yet() {
        let state = test_state();
        assert_eq!(
            state
                .store_of(&DocKey {
                    server_id: 1,
                    slug: "unseen".to_owned(),
                })
                .await,
            None
        );
    }

    #[tokio::test]
    async fn one_documents_store_is_not_anothers() {
        let state = test_state();
        state
            .remember_store(
                &DocKey {
                    server_id: 1,
                    slug: "a".to_owned(),
                },
                DocStore::Plugin,
            )
            .await;

        assert_eq!(
            state
                .store_of(&DocKey {
                    server_id: 1,
                    slug: "b".to_owned(),
                })
                .await,
            None
        );
    }
}
