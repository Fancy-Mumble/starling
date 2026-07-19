//! `UserList`(18), the registered-users dialog, read and edited.
//!
//! The message is one type doing two jobs, and murmur decides which by whether
//! it arrived carrying any users (`Messages.cpp:3155`):
//!
//! * **empty**, "tell me who is registered", answered with the whole directory;
//! * **non-empty**, "rename these, and unregister the ones I sent no name for".
//!
//! Both halves live here rather than in `lib.rs` because they are one feature
//! and because the read half has to be careful about two things that have
//! nothing to do with accounts: how much it is about to send, and how much of it
//! the asker is entitled to see.

use prost::Message as _;
use starling_proto::proto::tcp;
use starling_proto_fancy::identity;
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::userdata::Account;
use starling_runtime::log::timestamp::rfc3339;
use starling_runtime::log::{Category, LogEvent};
use starling_runtime::permit::permission_denied;
use starling_runtime::plane::{Actions, Inbound, to_conn, to_sessions};
use starling_runtime::trail::{self, Record};

use crate::{ROOT_CHANNEL, USER_LIST, UserdataService, actor_of};

/// Upstream `UserState`, which is how a rename reaches the connected clients.
const USER_STATE: u16 = 9;

/// How many accounts one page of [`UserdataService::every_account`] asks for.
///
/// `Accounts::list` clamps its own limit to 500, so asking for more would
/// silently page in 500s anyway and make the loop's arithmetic a lie.
const PAGE: u32 = 500;

/// The most accounts one directory answer will describe.
///
/// The frame codec refuses anything past `MAX_PAYLOAD_SIZE` (8 MiB,
/// `proto/src/codec.rs:30`), and a refused frame is *this exact bug wearing a
/// different face*: the operator opens the dialog and it is empty. murmur has
/// the same hazard and no limit, which works because nobody has ever opened this
/// dialog on a server with fifty thousand accounts and enjoyed it.
///
/// Ten thousand name-and-id rows are roughly two megabytes, which leaves the
/// texture budget below room to spare.
const MAX_ENTRIES: usize = 10_000;

/// How many bytes of avatar one directory answer will carry.
///
/// Avatars are the only unbounded part of an entry, `image_message_length`
/// defaults to 128 KiB each, so this is what actually decides whether the
/// answer fits. Past it the remaining entries are sent **without** their
/// texture: a row with a name and no picture is a usable directory, and an
/// oversized frame is no directory at all.
const TEXTURE_BUDGET: usize = 4 * 1024 * 1024;

/// The length at which a comment travels as a hash instead of inline.
///
/// The protocol's own rule (`Mumble.proto`, `UserList.User.comment_hash`): under
/// it the text is sent with the entry, at or over it the client is given the
/// hash and fetches the body with `RequestBlob.user_id_comment`.
const INLINE_COMMENT_LEN: usize = 128;

impl UserdataService {
    /// `UserList`: the registered-user directory, read or edited.
    pub(crate) async fn on_user_list(&self, inbound: &Inbound) -> Actions {
        let Ok(list) = tcp::UserList::decode(inbound.payload.as_slice()) else {
            tracing::debug!(conn = inbound.conn, "undecodable UserList");
            return Actions::new();
        };

        // Asked once and passed down, because both halves need it and it is a
        // round trip to `permissions`. `Register` is the read/write power over
        // the directory; it also grants the read, which is why the query half
        // below only falls back to `ReadRegister`.
        let manage = self
            .permit
            .allows(inbound, ROOT_CHANNEL, Perm::REGISTER.bits())
            .await;

        if list.users.is_empty() {
            self.read_directory(inbound, manage).await
        } else {
            self.edit_directory(inbound, manage, &list.users).await
        }
    }

    /// Answer the dialog with every registered account.
    ///
    /// Two permissions, deliberately (`Messages.cpp:3153`). `Register` is an
    /// administrator's power over the directory and comes with the whole record.
    /// `ReadRegister` is held by every registered user by default
    /// (`permissions/src/evaluate.rs:182`) and gets the reduced view, a name and
    /// an avatar, enough to find somebody who is offline and invite them, and
    /// not enough to tell when they were last here.
    async fn read_directory(&self, inbound: &Inbound, manage: bool) -> Actions {
        if !manage
            && !self
                .permit
                .allows(inbound, ROOT_CHANNEL, Perm::READ_REGISTER.bits())
                .await
        {
            tracing::info!(
                session = inbound.session,
                "refusing the registered-user directory"
            );
            return vec![permission_denied(
                inbound,
                Perm::READ_REGISTER,
                ROOT_CHANNEL,
            )];
        }

        let accounts = self.every_account(inbound.scope);
        let listed = accounts.len();
        let mut budget = TEXTURE_BUDGET;
        let mut users = Vec::with_capacity(listed);
        for account in accounts {
            users.push(
                self.entry(inbound.scope, account, manage, &mut budget)
                    .await,
            );
        }

        tracing::debug!(
            conn = inbound.conn,
            session = inbound.session,
            listed,
            manage,
            textures_left = budget,
            "answering UserList"
        );
        let reply = tcp::UserList { users };
        vec![to_conn(inbound.conn, USER_LIST, reply.encode_to_vec())]
    }

    /// Every account in `scope` that belongs in the dialog, ordered by id.
    ///
    /// The `List` RPC pages and this message does not, so the pages are walked
    /// back into one list. The SuperUser is dropped as murmur drops it
    /// (`Messages.cpp:3167`): it is not a person anybody registers, renames or
    /// unregisters, and offering it in a dialog whose other buttons are "rename"
    /// and "remove" invites exactly one accident.
    fn every_account(&self, scope: u32) -> Vec<Account> {
        let mut all: Vec<Account> = Vec::new();
        let mut after = 0;
        loop {
            let page = self.accounts.list(scope, "", PAGE, after);
            let Some(last) = page.accounts.last() else {
                break;
            };
            after = last.id;
            all.extend(
                page.accounts
                    .into_iter()
                    .filter(|account| account.id != identity::SUPERUSER),
            );
            if !page.more {
                break;
            }
            if all.len() >= MAX_ENTRIES {
                tracing::warn!(
                    scope,
                    listed = all.len(),
                    "the registered-user directory is longer than one message can carry; \
                     answering with the first accounts by id"
                );
                all.truncate(MAX_ENTRIES);
                break;
            }
        }
        all
    }

    /// One directory row.
    ///
    /// `budget` is decremented by whatever texture this row takes and is what
    /// stops the answer growing past a frame; a row past the budget keeps its
    /// name and loses its picture.
    async fn entry(
        &self,
        scope: u32,
        account: Account,
        manage: bool,
        budget: &mut usize,
    ) -> tcp::user_list::User {
        let texture = self.affordable_texture(scope, &account, budget).await;
        // Presence and comments are the sensitive half of a directory row: they
        // say when somebody was last on the server and what they wrote about
        // themselves. `ReadRegister` is a lookup permission, not a supervision
        // one, so it stops at the name and the avatar.
        let (comment, comment_hash) = if manage {
            self.comment_of(scope, &account).await
        } else {
            (None, None)
        };
        tcp::user_list::User {
            user_id: account.id as u32,
            name: Some(account.name),
            last_seen: manage.then(|| {
                rfc3339(
                    std::time::UNIX_EPOCH
                        + std::time::Duration::from_millis(account.last_active_ms),
                )
            }),
            // Absent because nothing records it: Starling has no last-channel
            // memory at all (`docs/GAP-ANALYSIS.md` A4), and a zero here is not
            // "unknown" to a client; it is the root channel.
            last_channel: None,
            texture,
            comment_hash,
            comment,
        }
    }

    /// This account's avatar, if the answer still has room for it.
    async fn affordable_texture(
        &self,
        scope: u32,
        account: &Account,
        budget: &mut usize,
    ) -> Option<Vec<u8>> {
        let texture = self.accounts.blob(scope, &account.texture_hash).await?;
        let afforded = afford(budget, texture);
        if afforded.is_none() {
            tracing::debug!(
                account = account.id,
                "omitting an avatar from the directory; the answer is already full"
            );
        }
        afforded
    }

    /// This account's comment as `(inline, hash)`, never both.
    async fn comment_of(&self, scope: u32, account: &Account) -> (Option<String>, Option<Vec<u8>>) {
        if account.comment_hash.is_empty() {
            return (None, None);
        }
        let body = self
            .accounts
            .blob(scope, &account.comment_hash)
            .await
            .and_then(|bytes| String::from_utf8(bytes).ok());
        split_comment(&account.comment_hash, body)
    }

    /// Rename and unregister accounts the dialog's editor sent back.
    ///
    /// Writing takes `Register` and nothing else will do (`Messages.cpp:3199`):
    /// `ReadRegister` is what lets an ordinary user *find* an account, and
    /// letting it delete one would make every registered user an administrator
    /// of everybody else's account.
    async fn edit_directory(
        &self,
        inbound: &Inbound,
        manage: bool,
        users: &[tcp::user_list::User],
    ) -> Actions {
        if !manage {
            tracing::info!(
                session = inbound.session,
                edits = users.len(),
                "refusing an edit to the registered-user directory"
            );
            return vec![permission_denied(inbound, Perm::REGISTER, ROOT_CHANNEL)];
        }

        let mut actions = Actions::new();
        for user in users {
            // The SuperUser, skipped exactly as murmur skips it
            // (`Messages.cpp:3207`). Renaming it makes the administrator login
            // unfindable and unregistering it removes the account that repairs
            // a broken ACL table.
            if u64::from(user.user_id) == identity::SUPERUSER {
                continue;
            }
            match &user.name {
                Some(name) => actions.extend(self.rename(inbound, user.user_id, name).await),
                None => self.unregister(inbound, user.user_id).await,
            }
        }
        actions
    }

    /// Rename a registered account, and tell everyone if its owner is here.
    async fn rename(&self, inbound: &Inbound, id: u32, name: &str) -> Actions {
        let name = name.trim();
        if name.is_empty() {
            // murmur runs the name past `validateUserName` and answers a bad one
            // with `DenyType::UserName` (`Messages.cpp:3245`). Starling has no
            // name regex at all (`docs/GAP-ANALYSIS.md` C5), so the one rule it
            // can honestly enforce is that a name has to be something.
            return vec![invalid_name(inbound, name)];
        }
        let id = u64::from(id);
        // `rename` rather than `update`, and the difference is which authority
        // the change rests on. `update` demands the account's *current password*
        // for a name change, because there it is a user editing their own
        // profile and a hijacked session must not be able to lock the owner out.
        // Here the authority is `Register`, checked above against the caller,
        // and an administrator renaming somebody else does not know, and must
        // not need, that person's password.
        let renamed = match self.accounts.rename(inbound.scope, id, name).await {
            Ok(account) => account,
            Err(refused) => {
                tracing::info!(account = id, %refused, "the rename was refused");
                return vec![invalid_name(inbound, name)];
            }
        };

        self.logger.log(
            LogEvent::notice(Category::Admin, "account renamed")
                .with("actor", inbound.session)
                .with("account", id)
                .with("name", renamed.name.clone()),
        );
        self.trail.record(
            inbound.scope,
            Record::new(trail::category::REGISTER, "renamed")
                .actor(actor_of(inbound.session), String::new())
                .target_account(id)
                .detail(renamed.name.clone()),
        );

        // A connected session carries the *old* name in every client's tree, and
        // nothing else will correct it: the account row changed, and a client
        // builds its user list from `UserState`. murmur broadcasts one for
        // exactly this reason (`Messages.cpp:3231`).
        let Some(session) = self.session_of(inbound.scope, id).await else {
            return Actions::new();
        };
        let announce = tcp::UserState {
            session: Some(session),
            actor: Some(inbound.session),
            name: Some(renamed.name),
            ..tcp::UserState::default()
        };
        vec![to_sessions(
            Vec::new(),
            USER_STATE,
            announce.encode_to_vec(),
        )]
    }

    /// Unregister an account: an entry the dialog sent back with no name.
    ///
    /// The connected session is deliberately **not** disturbed. Unregistering
    /// takes the account away, not the connection, murmur leaves the user on
    /// the server and lets the next login decide what they are.
    async fn unregister(&self, inbound: &Inbound, id: u32) {
        let id = u64::from(id);
        let name = self
            .accounts
            .by_id(inbound.scope, id)
            .map(|account| account.name)
            .unwrap_or_default();
        self.accounts.delete(inbound.scope, id).await;

        self.logger.log(
            LogEvent::notice(Category::Admin, "account unregistered")
                .with("actor", inbound.session)
                .with("account", id)
                .with("name", name.clone()),
        );
        self.trail.record(
            inbound.scope,
            Record::new(trail::category::REGISTER, "unregistered")
                .actor(actor_of(inbound.session), String::new())
                .target_account(id)
                .detail(name),
        );
    }

    /// The live session holding `account`, if its owner is connected.
    async fn session_of(&self, scope: u32, account: u64) -> Option<u32> {
        self.sessions(scope).await.into_iter().find_map(|session| {
            (identity::account(session.registered, session.account) == Some(account))
                .then_some(session.session)
        })
    }
}

/// Spend `budget` on `texture`, or leave both alone.
///
/// A row that cannot afford its picture must not spend what the next row could
/// still have used, and the check has to be a comparison rather than a
/// subtraction, which on `usize` would wrap into an enormous budget and let
/// every remaining avatar through.
fn afford(budget: &mut usize, texture: Vec<u8>) -> Option<Vec<u8>> {
    if texture.len() > *budget {
        return None;
    }
    *budget -= texture.len();
    Some(texture)
}

/// A stored comment as `(inline, hash)`, never both, and never neither.
///
/// The protocol's own split: short comments travel with the entry, long ones
/// travel as a hash the client redeems through `RequestBlob.user_id_comment`.
/// Sending both would be a client rendering the text and then fetching it
/// again; sending neither leaves the dialog's comment column permanently blank.
///
/// `body` is `None` when the hash is on the account and the blob is gone or is
/// not text. The hash alone is still the honest answer there, the client asks
/// for it and is told there is nothing, where an inlined empty string renders
/// as somebody having deliberately cleared theirs.
fn split_comment(hash: &[u8], body: Option<String>) -> (Option<String>, Option<Vec<u8>>) {
    match body {
        Some(comment) if comment.len() < INLINE_COMMENT_LEN => (Some(comment), None),
        _ => (None, Some(hash.to_vec())),
    }
}

/// Refuse a name the directory will not accept.
///
/// `DenyType::UserName` carrying the name, which is what a Mumble client renders
/// as "X is not a valid username" (`Messages.cpp:3245`). A permission refusal
/// would send the operator looking for a grant that would not help.
fn invalid_name(inbound: &Inbound, name: &str) -> starling_proto_fancy::control::ServerAction {
    /// Upstream `PermissionDenied`.
    const PERMISSION_DENIED: u16 = 12;
    let denied = tcp::PermissionDenied {
        r#type: Some(tcp::permission_denied::DenyType::UserName as i32),
        session: Some(inbound.session),
        name: Some(name.to_owned()),
        ..tcp::PermissionDenied::default()
    };
    to_conn(inbound.conn, PERMISSION_DENIED, denied.encode_to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &[u8] = &[1, 2, 3, 4];

    #[test]
    fn a_short_comment_travels_inline() {
        let (comment, hash) = split_comment(HASH, Some("hello".to_owned()));
        assert_eq!(comment.as_deref(), Some("hello"));
        assert_eq!(hash, None, "sending both makes the client fetch it twice");
    }

    #[test]
    fn a_long_comment_travels_as_a_hash() {
        let long = "a".repeat(INLINE_COMMENT_LEN);
        let (comment, hash) = split_comment(HASH, Some(long));
        assert_eq!(comment, None);
        assert_eq!(hash.as_deref(), Some(HASH));
    }

    #[test]
    fn the_boundary_is_the_protocols_own() {
        // Under the limit inline, at it by hash. Off by one here means every
        // comment of exactly 128 characters renders as a hash a client shows
        // raw, or as text it then refetches.
        assert!(
            split_comment(HASH, Some("a".repeat(INLINE_COMMENT_LEN - 1)))
                .0
                .is_some()
        );
        assert!(
            split_comment(HASH, Some("a".repeat(INLINE_COMMENT_LEN)))
                .0
                .is_none()
        );
    }

    #[test]
    fn a_comment_whose_blob_has_gone_is_still_offered_as_a_hash() {
        // Not as an empty string: the account says there is a comment, and
        // inlining "" would render as somebody having deliberately cleared
        // theirs rather than as content the client can go and ask for.
        let (comment, hash) = split_comment(HASH, None);
        assert_eq!(comment, None);
        assert_eq!(hash.as_deref(), Some(HASH));
    }

    #[test]
    fn a_texture_that_does_not_fit_leaves_the_budget_for_the_next_row() {
        let mut budget = 10;
        assert_eq!(afford(&mut budget, vec![0; 11]), None);
        assert_eq!(budget, 10, "a refused row must not spend anything");
        assert_eq!(afford(&mut budget, vec![0; 4]), Some(vec![0; 4]));
        assert_eq!(budget, 6);
    }

    #[test]
    fn an_exhausted_budget_does_not_wrap_into_an_enormous_one() {
        // `usize` subtraction is the trap: one texture past zero would wrap to
        // near `usize::MAX` and let every remaining avatar through, which is
        // precisely the oversized frame the budget exists to prevent.
        let mut budget = 0;
        assert_eq!(afford(&mut budget, vec![0; 1]), None);
        assert_eq!(budget, 0);
        assert_eq!(afford(&mut budget, Vec::new()), Some(Vec::new()));
    }

    #[test]
    fn the_answer_cannot_outgrow_the_frame_that_carries_it() {
        // The budget plus the worst case of the entry cap has to stay under the
        // codec's limit, or the dialog is empty for the largest servers, which
        // is the bug this whole file exists to fix, arriving by another route.
        const NAME_AND_ID: usize = 200;
        assert!(
            TEXTURE_BUDGET + MAX_ENTRIES * NAME_AND_ID
                < starling_proto::codec::MAX_PAYLOAD_SIZE as usize
        );
    }
}
