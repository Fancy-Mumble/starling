//! Storing a ban list a client wrote, and saying who did it.
//!
//! What the list may hold is [`crate::written`]'s; this is the write itself:
//! the stored list is replaced in one transaction, as murmur's `saveBans`
//! replaces it, and the change goes to the audit trail under the session that
//! made it.

use starling_proto::proto::tcp::BanList;
use starling_proto_fancy::moderation::Ban;
use starling_runtime::ids::now_ms;
use starling_runtime::log::{Category, LogEvent};
use starling_runtime::plane::{Actions, Inbound, to_conn};
use starling_runtime::trail::{self, Record};

use crate::written::{added, bans_from};
use crate::{ModerationService, PERMISSION_DENIED, session_actor};

impl ModerationService {
    /// Replace the stored list with the one a client wrote.
    ///
    /// The caller has checked `Ban` at the root. A list that cannot be stored
    /// as written is refused whole, with the reason, and nothing of it is
    /// applied: half a list is a list nobody wrote.
    pub(crate) async fn on_ban_write(&self, inbound: &Inbound, list: &BanList) -> Actions {
        // In the form a client was shown, so an old four-octet row the editor
        // sends back unchanged is the same ban, keeping its id and start.
        let held: Vec<Ban> = self
            .bans(inbound.scope)
            .await
            .iter()
            .map(crate::covering::sixteen_bytes)
            .collect();
        let bans = match bans_from(&list.bans, &held, &self.ids, now_ms()) {
            Ok(bans) => bans,
            Err(reason) => {
                tracing::info!(session = inbound.session, %reason, "ban list refused");
                return vec![refused(inbound, &reason)];
            }
        };
        if let Err(error) = self.replace_bans(inbound.scope, &bans).await {
            tracing::error!(%error, "could not store a written ban list");
            return vec![refused(inbound, "The ban list could not be stored.")];
        }

        let new = added(&bans, &held);
        let lifted = added(&held, &bans);
        self.logger.log(
            LogEvent::notice(Category::Admin, "ban list updated")
                .with("actor", inbound.session)
                .with("added", new.len())
                .with("lifted", lifted.len())
                .with("scope", inbound.scope),
        );
        self.trail.record(
            inbound.scope,
            Record::new(trail::category::BAN, "list updated")
                .actor(session_actor(inbound.session), String::new())
                .detail(format!(
                    "added: {}; lifted: {}",
                    names(&new),
                    names(&lifted)
                )),
        );
        // Whoever a new ban covers goes now, not at their next login. Only the
        // new ones: a ban the list already held turned its subjects away when
        // it was made.
        self.turn_away(inbound.scope, &new).await;
        Actions::new()
    }

    /// The stored list becomes `bans`, all or nothing.
    async fn replace_bans(&self, scope: u32, bans: &[Ban]) -> Result<(), sqlx::Error> {
        let mut tx = self.store.pool().begin().await?;
        let _ = sqlx::query("DELETE FROM ban WHERE server_id = ?")
            .bind(i64::from(scope))
            .execute(&mut *tx)
            .await?;
        for ban in bans {
            let _ = sqlx::query(
                "INSERT INTO ban (server_id, id, address, prefix_len, name, cert_hash, reason, \
                     start_ms, duration_s) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(i64::from(scope))
            .bind(ban.id as i64)
            .bind(ban.address.as_slice())
            .bind(i64::from(ban.prefix_len))
            .bind(&ban.name)
            .bind(ban.cert_hash.as_slice())
            .bind(&ban.reason)
            .bind(ban.start_ms as i64)
            .bind(i64::from(ban.duration_s))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await
    }
}

/// A refusal the client shows as it is worded.
fn refused(inbound: &Inbound, reason: &str) -> starling_proto_fancy::control::ServerAction {
    use prost::Message as _;
    let denied = starling_proto::proto::tcp::PermissionDenied {
        r#type: Some(starling_proto::proto::tcp::permission_denied::DenyType::Text as i32),
        session: Some(inbound.session),
        reason: Some(reason.to_owned()),
        ..starling_proto::proto::tcp::PermissionDenied::default()
    };
    to_conn(inbound.conn, PERMISSION_DENIED, denied.encode_to_vec())
}

/// The names on `bans`, for the trail.
fn names(bans: &[Ban]) -> String {
    if bans.is_empty() {
        return "none".to_owned();
    }
    bans.iter()
        .map(|ban| {
            if ban.name.is_empty() {
                "(unnamed)"
            } else {
                ban.name.as_str()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
