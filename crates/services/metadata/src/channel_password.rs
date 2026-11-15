//! A channel password, and the grant that keeps a channel's maker in it.
//!
//! In Mumble a channel password is not a property of the channel: it is two
//! ACL entries, which is how the stock client's ACL editor writes one
//! (`vendor/server/src/mumble/ACLEditor.cpp:719`, `updatePasswordACL`) and
//! how murmur recognises one (`ChanACL::isPassword`, `src/ACL.cpp:426`):
//! `all` is denied entering, speaking, whispering, writing and linking there,
//! and `#<password>` is granted them back. Whoever presents the password as an
//! access token is in `#<password>`.
//!
//! The Fancy channel form sends the password beside the channel instead
//! (`ChannelState.channel_info_password`), and this turns it into those two
//! entries.

use starling_proto::proto::tcp::ChannelState;
use starling_proto::proto::tcp::permission_denied::DenyType;
use starling_proto_fancy::control::ServerAction;
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::permissions::AclEntry;
use starling_proto_fancy::sessionview::Session;
use starling_runtime::permit::refused;
use starling_runtime::plane::Inbound;

/// What a password shuts and its token opens.
const SHUT: Perm = Perm::ENTER
    .union(Perm::SPEAK)
    .union(Perm::WHISPER)
    .union(Perm::TEXT_MESSAGE)
    .union(Perm::LINK_CHANNEL)
    .union(Perm::TRAVERSE);
/// The same set without `Traverse`, which murmur's editor wrote before it
/// denied traversal, and still recognises.
const SHUT_BEFORE_TRAVERSE: Perm = SHUT.difference(Perm::TRAVERSE);

/// The longest password a channel may have, in characters.
///
/// It becomes an ACL group name, stored and compared on every permission
/// check in the channel, and nothing bounded it: anybody who may make a
/// channel could give it one of megabytes. murmur has no limit; this one is
/// far past any password a person types.
pub(crate) const MAX_CHARS: usize = 128;

/// Whether `password` may be a channel's.
pub(crate) fn fits(password: &str) -> bool {
    password.chars().count() <= MAX_CHARS
}

/// The refusal for a `ChannelState` whose password does not fit.
pub(crate) fn too_long(
    inbound: &Inbound,
    state: &ChannelState,
    channel: u32,
) -> Option<ServerAction> {
    let password = state.channel_info_password.as_deref()?;
    (!fits(password)).then(|| {
        refused(
            inbound,
            DenyType::TextTooLong,
            channel,
            "a channel password may be at most 128 characters",
        )
    })
}

/// `acls` with its password replaced by `password`, or removed by an empty one.
///
/// Inherited entries are left out: they belong to the parent, and writing
/// them back here would copy them into this channel's own table.
pub(crate) fn with_password(acls: Vec<AclEntry>, password: &str) -> Vec<AclEntry> {
    let mut acls: Vec<AclEntry> = acls
        .into_iter()
        .filter(|entry| !entry.inherited && !is_password(entry) && !is_shut_to_all(entry))
        .collect();
    if !password.is_empty() {
        acls.push(own(Some("all"), None, Perm::empty(), SHUT));
        acls.push(own(
            Some(&format!("#{password}")),
            None,
            SHUT,
            Perm::empty(),
        ));
    }
    acls
}

/// The grant murmur gives whoever made a channel and may not otherwise write
/// it, so they can still edit, enter and remove it (`Messages.cpp:1889`).
///
/// By account where there is one, otherwise by certificate (`$<hash>`); a
/// guest with neither has nothing it could be granted to.
pub(crate) fn maker(session: &Session) -> Option<AclEntry> {
    let grant = Perm::WRITE.union(Perm::TRAVERSE);
    if session.registered {
        return Some(own(None, Some(session.account), grant, Perm::empty()));
    }
    if session.cert_hash.is_empty() {
        return None;
    }
    let hash: String = session
        .cert_hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Some(own(Some(&format!("${hash}")), None, grant, Perm::empty()))
}

/// An entry of this channel's own, applying here and not below.
fn own(group: Option<&str>, account: Option<u64>, grant: Perm, deny: Perm) -> AclEntry {
    AclEntry {
        apply_here: true,
        apply_subs: false,
        inherited: false,
        account,
        group: group.map(str::to_owned),
        grant: grant.bits(),
        deny: deny.bits(),
    }
}

/// murmur's `ChanACL::isPassword`.
fn is_password(entry: &AclEntry) -> bool {
    entry
        .group
        .as_deref()
        .is_some_and(|group| group.starts_with('#'))
        && entry.apply_here
        && entry.deny == 0
        && (entry.grant == SHUT.bits() || entry.grant == SHUT_BEFORE_TRAVERSE.bits())
}

/// The `all` deny that goes with a password, as murmur's editor finds it.
fn is_shut_to_all(entry: &AclEntry) -> bool {
    entry.group.as_deref() == Some("all")
        && entry.apply_here
        && entry.grant == 0
        && (entry.deny == SHUT.bits() || entry.deny == SHUT_BEFORE_TRAVERSE.bits())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invitee() -> AclEntry {
        own(None, Some(7), Perm::ENTER, Perm::empty())
    }

    #[test]
    fn a_password_past_the_limit_does_not_fit_and_one_at_it_does() {
        assert!(fits(&"é".repeat(MAX_CHARS)), "counted in characters");
        assert!(!fits(&"a".repeat(MAX_CHARS + 1)), "one past is refused");
        assert!(fits(""), "none at all is no password");
    }

    #[test]
    fn a_password_is_a_deny_to_all_and_a_grant_to_its_token() {
        let acls = with_password(Vec::new(), "hunter2");
        assert_eq!(acls.len(), 2);
        assert_eq!(acls[0].group.as_deref(), Some("all"));
        assert_eq!(acls[0].deny, SHUT.bits());
        assert_eq!(acls[1].group.as_deref(), Some("#hunter2"));
        assert_eq!(acls[1].grant, SHUT.bits());
        assert!(
            acls.iter()
                .all(|entry| entry.apply_here && !entry.apply_subs)
        );
    }

    #[test]
    fn a_new_password_replaces_the_old_and_an_empty_one_removes_it() {
        let first = with_password(vec![invitee()], "hunter2");
        let changed = with_password(first, "swordfish");
        let groups: Vec<_> = changed
            .iter()
            .filter_map(|entry| entry.group.clone())
            .collect();
        assert_eq!(groups, vec!["all".to_owned(), "#swordfish".to_owned()]);
        assert_eq!(changed[0], invitee(), "everything else is kept");
        let removed = with_password(changed, "");
        assert_eq!(removed, vec![invitee()]);
    }

    #[test]
    fn an_older_password_without_traverse_is_recognised_too() {
        let old = vec![
            own(Some("all"), None, Perm::empty(), SHUT_BEFORE_TRAVERSE),
            own(Some("#old"), None, SHUT_BEFORE_TRAVERSE, Perm::empty()),
        ];
        assert!(with_password(old, "").is_empty());
    }

    #[test]
    fn inherited_entries_are_not_copied_into_the_channel() {
        let inherited = AclEntry {
            inherited: true,
            ..invitee()
        };
        assert!(with_password(vec![inherited], "").is_empty());
    }

    #[test]
    fn a_maker_is_granted_by_account_or_by_certificate_and_a_bare_guest_not_at_all() {
        let registered = Session {
            registered: true,
            account: 4,
            ..Session::default()
        };
        assert_eq!(maker(&registered).and_then(|entry| entry.account), Some(4));
        let guest = Session {
            cert_hash: vec![0xab, 0x01],
            ..Session::default()
        };
        assert_eq!(
            maker(&guest).and_then(|entry| entry.group).as_deref(),
            Some("$ab01")
        );
        assert!(maker(&Session::default()).is_none());
    }
}
