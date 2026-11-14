//! One user, several devices: which id other users know an account by.
//!
//! An account online from a laptop and a phone is two connections and two
//! session ids, but one person, and other users see it as one user. Every
//! device of it presents as the id of the device that arrived first, and that
//! id stays reserved until the last device leaves, so a peer never sees the
//! user leave and rejoin because the first device dropped
//! (`docs/SERVICES.md`, "One user, several devices").
//!
//! Guests have no account to group by, so each is its own user.

use std::collections::HashMap;

/// The devices of one account and the id they present as.
#[derive(Debug)]
struct Presence {
    shown: u32,
    devices: Vec<u32>,
}

/// What an arriving device became.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arrival {
    /// The id other users know this device by.
    pub shown: u32,
    /// Whether it is the account's only device, so other users have to be
    /// told a user arrived. A later device joins a user they already see.
    pub first: bool,
}

/// What a departing device left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Departure {
    /// The id other users knew the device by.
    pub shown: u32,
    /// Whether it was the account's last device, so other users have to be
    /// told the user left.
    pub last: bool,
    /// The ids the session pool may hand out again: the device's own unless
    /// it is the one still being shown, and the shown one once nobody is.
    pub released: Vec<u32>,
}

/// Every account online from at least one device, by account.
#[derive(Debug, Default)]
pub struct Presences {
    by_account: HashMap<u64, Presence>,
    /// Device session to its account, so a departure needs only the session.
    accounts: HashMap<u32, u64>,
}

impl Presences {
    /// Record `session` arriving, as `account` or as a guest.
    pub fn arrive(&mut self, account: Option<u64>, session: u32) -> Arrival {
        let Some(account) = account else {
            return Arrival {
                shown: session,
                first: true,
            };
        };
        let _ = self.accounts.insert(session, account);
        let presence = self.by_account.entry(account).or_insert(Presence {
            shown: session,
            devices: Vec::new(),
        });
        presence.devices.push(session);
        Arrival {
            shown: presence.shown,
            first: presence.devices.len() == 1,
        }
    }

    /// Record `session` leaving.
    pub fn leave(&mut self, session: u32) -> Departure {
        let Some(account) = self.accounts.remove(&session) else {
            return Departure {
                shown: session,
                last: true,
                released: vec![session],
            };
        };
        let Some(presence) = self.by_account.get_mut(&account) else {
            return Departure {
                shown: session,
                last: true,
                released: vec![session],
            };
        };
        presence.devices.retain(|device| *device != session);
        let shown = presence.shown;
        let last = presence.devices.is_empty();
        let mut released = Vec::new();
        if session != shown {
            released.push(session);
        }
        if last {
            released.push(shown);
            let _ = self.by_account.remove(&account);
        }
        Departure {
            shown,
            last,
            released,
        }
    }

    /// The id other users know `session` by.
    #[must_use]
    pub fn shown(&self, session: u32) -> u32 {
        self.accounts
            .get(&session)
            .and_then(|account| self.by_account.get(account))
            .map_or(session, |presence| presence.shown)
    }

    /// Every device presenting as `shown`, in arrival order.
    ///
    /// `shown` alone for an id no account presents as, so a single-device
    /// user is addressed exactly as before.
    #[must_use]
    pub fn devices(&self, shown: u32) -> Vec<u32> {
        self.by_account
            .values()
            .find(|presence| presence.shown == shown)
            .map_or_else(|| vec![shown], |presence| presence.devices.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_guest_is_always_its_own_user() {
        let mut presences = Presences::default();
        let arrival = presences.arrive(None, 5);
        assert_eq!(
            arrival,
            Arrival {
                shown: 5,
                first: true
            }
        );
        assert_eq!(presences.leave(5).released, vec![5]);
    }

    #[test]
    fn a_second_device_joins_the_user_others_already_see() {
        let mut presences = Presences::default();
        assert!(presences.arrive(Some(7), 1).first);
        let phone = presences.arrive(Some(7), 2);
        assert_eq!(
            phone,
            Arrival {
                shown: 1,
                first: false
            }
        );
        assert_eq!(presences.shown(2), 1);
        assert_eq!(presences.devices(1), vec![1, 2]);
    }

    #[test]
    fn two_accounts_are_two_users() {
        let mut presences = Presences::default();
        let _ = presences.arrive(Some(7), 1);
        assert!(presences.arrive(Some(8), 2).first);
        assert_eq!(presences.shown(2), 2);
    }

    #[test]
    fn the_first_device_leaving_keeps_its_id_shown_and_reserved() {
        let mut presences = Presences::default();
        let _ = presences.arrive(Some(7), 1);
        let _ = presences.arrive(Some(7), 2);

        let gone = presences.leave(1);
        assert_eq!(
            gone,
            Departure {
                shown: 1,
                last: false,
                released: Vec::new()
            }
        );
        assert_eq!(presences.shown(2), 1, "nobody sees the user change id");
        assert_eq!(presences.devices(1), vec![2]);
    }

    #[test]
    fn the_last_device_leaving_frees_both_ids() {
        let mut presences = Presences::default();
        let _ = presences.arrive(Some(7), 1);
        let _ = presences.arrive(Some(7), 2);
        let _ = presences.leave(1);

        let gone = presences.leave(2);
        assert!(gone.last);
        assert_eq!(gone.released, vec![2, 1]);
        assert_eq!(presences.devices(1), vec![1], "nothing presents as it now");
    }

    #[test]
    fn a_later_device_leaving_frees_only_its_own_id() {
        let mut presences = Presences::default();
        let _ = presences.arrive(Some(7), 1);
        let _ = presences.arrive(Some(7), 2);

        let gone = presences.leave(2);
        assert!(!gone.last);
        assert_eq!(gone.released, vec![2]);
    }

    #[test]
    fn a_device_returning_after_the_first_left_rejoins_the_same_user() {
        let mut presences = Presences::default();
        let _ = presences.arrive(Some(7), 1);
        let _ = presences.arrive(Some(7), 2);
        let _ = presences.leave(1);

        let back = presences.arrive(Some(7), 3);
        assert_eq!(
            back,
            Arrival {
                shown: 1,
                first: false
            }
        );
    }
}
