//! The devices an account is used from.
//!
//! # Why an account has devices at all
//!
//! A Mumble account is a certificate, and a certificate is a file. Copying it to
//! a second machine is how one person uses one account from a laptop and a
//! phone, and nothing on the wire tells those two apart: both present the same
//! hash. That made two things impossible. Being online from both at once, since
//! the second login looked exactly like the first reconnecting and evicted it
//! as a ghost. And taking one of them away again, since there was nothing to
//! take away except the certificate both of them hold.
//!
//! So a Fancy client names its install: a random id, a secret it registered
//! with, and a name its owner can recognise. Two sessions of one account from
//! two ids are two devices and may coexist; one id reconnecting is a reconnect.
//!
//! # Trusted on first use, until a device is signed out
//!
//! Every account starts *unlocked*: a device it has never seen is registered
//! the first time it logs in, which is how a certificate has always worked and
//! so changes nothing for anyone who never opens their device list.
//!
//! Signing a device out leaves a tombstone, and the first tombstone locks the
//! account. From then on a login proved by the certificate alone must come from
//! a device the account knows. A login that also proved the password still
//! registers whatever device it comes from: the password is a second secret
//! the signed-out device does not have unless its owner typed it there, and
//! then changing it is what signs that device out for good.
//!
//! A signed-out device is refused by id whatever it proves, so it cannot come
//! straight back by presenting the id it was refused under.
//!
//! # What this does not do
//!
//! A signed-out device still holds the certificate it was given, and a
//! certificate is valid on every server it was registered on. What is withdrawn
//! here is this server's willingness to admit that device, which is as far as a
//! server's authority goes.

use sha2::{Digest as _, Sha256};
use starling_proto_fancy::userdata::AuthRequest;
use subtle::ConstantTimeEq as _;

/// How many devices an account may have registered at once.
///
/// A ceiling rather than none, because registration is automatic and a script
/// holding the password could otherwise mint rows until the table is the
/// problem. Past it the least recently seen device is forgotten, which costs its
/// owner at most a re-link: on a locked account a forgotten device is simply an
/// unknown one again.
pub const MAX_DEVICES: usize = 32;

/// How many tombstones are kept.
///
/// One would do to keep the account locked; more are kept so that a device
/// signed out recently stays refused by id rather than falling back to "unknown",
/// which a password would let straight back in.
pub const MAX_SIGNED_OUT: usize = 32;

/// The longest device id accepted.
pub const MAX_ID_LEN: usize = 64;

/// The shortest secret accepted: 128 bits as hex.
const MIN_SECRET_LEN: usize = 32;

/// The longest secret accepted.
const MAX_SECRET_LEN: usize = 256;

/// The longest name kept. A longer one is cut, not refused: it is a label.
pub const MAX_NAME_LEN: usize = 64;

/// One device of one account, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The id the client generated for its install.
    pub id: String,
    /// What its owner calls it.
    pub name: String,
    /// SHA-256 of the secret it registered with.
    ///
    /// A plain hash, not the password KDF: the secret is 128 random bits or
    /// more, so there is nothing to slow a guesser down *from*, and this is
    /// checked on every login.
    pub secret_hash: Vec<u8>,
    /// When it was registered.
    pub added_at_ms: u64,
    /// When it last logged in.
    pub last_seen_ms: u64,
    /// Signed out: refused by id, and the reason the account is locked.
    pub signed_out: bool,
}

impl Device {
    /// Whether `secret` is the one this device registered with.
    #[must_use]
    pub fn proves(&self, secret: &str) -> bool {
        hash(secret).ct_eq(&self.secret_hash).into()
    }
}

/// The hash a device secret is stored as.
#[must_use]
pub fn hash(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

/// A device as a login presents it, once it has been checked for shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Presented<'a> {
    /// The install's id.
    pub id: &'a str,
    /// The secret it registered with, in the clear as the login carried it.
    pub secret: &'a str,
    /// What it calls itself, used only when it is new.
    pub name: &'a str,
}

/// The device a login names, or `None` when it names none usable.
///
/// A malformed one is treated as absent rather than refused: a client with a
/// bug in how it stores its id should still be able to log in the way every
/// stock client does, and it gains nothing by being malformed - an absent
/// device is exactly what a locked account refuses to a certificate alone.
#[must_use]
pub fn presented(request: &AuthRequest) -> Option<Presented<'_>> {
    valid(&request.device_id, &request.device_secret).then_some(Presented {
        id: &request.device_id,
        secret: &request.device_secret,
        name: &request.device_name,
    })
}

/// Whether an id and a secret have the shape this module stores.
#[must_use]
pub fn valid(id: &str, secret: &str) -> bool {
    valid_id(id) && (MIN_SECRET_LEN..=MAX_SECRET_LEN).contains(&secret.len())
}

/// Whether `id` is one this module would have stored.
///
/// Printable ASCII without spaces, because it is a key in a table and a string
/// in a log line, and neither should have to wonder what else it might be.
#[must_use]
pub fn valid_id(id: &str) -> bool {
    (1..=MAX_ID_LEN).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// `name` cut to what is kept, on a character boundary.
#[must_use]
pub fn clean_name(name: &str) -> String {
    name.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_LEN)
        .collect()
}

/// Whether the account admits only the devices it knows.
#[must_use]
pub fn locked(devices: &[Device]) -> bool {
    devices.iter().any(|device| device.signed_out)
}

/// What a successful login does about its device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// It named none, and may in without one.
    None,
    /// Admitted as this device: a known one with its `last_seen_ms` moved on,
    /// or a new one to register.
    Admit(Device),
    /// Refused.
    Refuse,
}

/// Decide the device half of a login that has already proved its account.
///
/// `password_proved` is whether the login proved a stored password, which is
/// the one thing that registers a new device on a locked account. It is a
/// fact about the account, not the request: `Accounts::finish` refuses a wrong
/// password before this is asked, so an account with a password was proved by
/// it whichever path reached here.
#[must_use]
pub fn judge(
    devices: &[Device],
    presented: Option<Presented<'_>>,
    password_proved: bool,
    now_ms: u64,
) -> Verdict {
    let locked = locked(devices);
    let Some(presented) = presented else {
        // A stock client, or one that sends nothing usable. On a locked account
        // a certificate alone is exactly what a signed-out device still has,
        // so it is not enough; the password is.
        return if locked && !password_proved {
            Verdict::Refuse
        } else {
            Verdict::None
        };
    };
    let name = clean_name(presented.name);
    match devices.iter().find(|device| device.id == presented.id) {
        // Refused by id whatever else was proved: a signed-out device that
        // could come back by presenting the id it was refused under was never
        // signed out.
        Some(device) if device.signed_out => Verdict::Refuse,
        // Known id, wrong secret: somebody else's id. Refused, or a session
        // could evict another device's by claiming to be it.
        Some(device) if !device.proves(presented.secret) => Verdict::Refuse,
        Some(device) => Verdict::Admit(Device {
            // The owner may have renamed it from another device since, and
            // that rename wins over whatever this install still calls itself.
            name: if device.name.is_empty() {
                name
            } else {
                device.name.clone()
            },
            last_seen_ms: now_ms,
            ..device.clone()
        }),
        None if locked && !password_proved => Verdict::Refuse,
        None => Verdict::Admit(Device {
            id: presented.id.to_owned(),
            name,
            secret_hash: hash(presented.secret),
            added_at_ms: now_ms,
            last_seen_ms: now_ms,
            signed_out: false,
        }),
    }
}

/// `devices` with `device` put in, and the ceilings applied.
///
/// Returns the new set and the ids that fell out of it, which the caller has
/// to delete from the table as well.
#[must_use]
pub fn upsert(devices: &[Device], device: Device) -> (Vec<Device>, Vec<String>) {
    let mut kept: Vec<Device> = devices
        .iter()
        .filter(|other| other.id != device.id)
        .cloned()
        .collect();
    kept.push(device);
    let mut dropped = Vec::new();
    for signed_out in [false, true] {
        let ceiling = if signed_out {
            MAX_SIGNED_OUT
        } else {
            MAX_DEVICES
        };
        while kept.iter().filter(|d| d.signed_out == signed_out).count() > ceiling {
            // The least recently seen of that kind. Ties go to the oldest id so
            // that which one goes never depends on the order rows loaded in.
            let Some(oldest) = kept
                .iter()
                .enumerate()
                .filter(|(_, d)| d.signed_out == signed_out)
                .min_by(|(_, a), (_, b)| {
                    a.last_seen_ms
                        .cmp(&b.last_seen_ms)
                        .then_with(|| a.id.cmp(&b.id))
                })
                .map(|(at, _)| at)
            else {
                break;
            };
            dropped.push(kept.remove(oldest).id);
        }
    }
    (kept, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn device(id: &str, signed_out: bool) -> Device {
        Device {
            id: id.to_owned(),
            name: format!("{id}'s name"),
            secret_hash: hash(SECRET),
            added_at_ms: 1,
            last_seen_ms: 1,
            signed_out,
        }
    }

    fn laptop() -> Presented<'static> {
        Presented {
            id: "laptop",
            secret: SECRET,
            name: "Laptop",
        }
    }

    #[test]
    fn a_new_device_is_trusted_on_first_use_until_one_is_signed_out() {
        // Unlocked: exactly what a certificate always allowed.
        assert!(matches!(
            judge(&[device("phone", false)], Some(laptop()), false, 5),
            Verdict::Admit(Device { ref id, .. }) if id == "laptop"
        ));
        // Locked, certificate alone: refused, because that is all a signed-out
        // device still has.
        assert_eq!(
            judge(&[device("phone", true)], Some(laptop()), false, 5),
            Verdict::Refuse
        );
        // Locked, password proved: registered.
        assert!(matches!(
            judge(&[device("phone", true)], Some(laptop()), true, 5),
            Verdict::Admit(_)
        ));
    }

    #[test]
    fn a_signed_out_device_is_refused_by_id_even_with_the_password() {
        assert_eq!(
            judge(&[device("laptop", true)], Some(laptop()), true, 5),
            Verdict::Refuse
        );
    }

    #[test]
    fn a_known_id_with_the_wrong_secret_is_somebody_else() {
        let stolen_id = Presented {
            secret: "ffffffffffffffffffffffffffffffff",
            ..laptop()
        };
        assert_eq!(
            judge(&[device("laptop", false)], Some(stolen_id), true, 5),
            Verdict::Refuse
        );
    }

    #[test]
    fn a_known_device_keeps_the_name_its_owner_gave_it() {
        let Verdict::Admit(admitted) = judge(&[device("laptop", false)], Some(laptop()), false, 9)
        else {
            panic!("a known device is admitted");
        };
        assert_eq!(admitted.name, "laptop's name");
        assert_eq!(admitted.last_seen_ms, 9);
        assert_eq!(admitted.added_at_ms, 1);
    }

    #[test]
    fn a_login_naming_no_device_needs_the_password_only_once_locked() {
        assert_eq!(judge(&[], None, false, 5), Verdict::None);
        assert_eq!(judge(&[device("x", true)], None, false, 5), Verdict::Refuse);
        assert_eq!(judge(&[device("x", true)], None, true, 5), Verdict::None);
    }

    #[test]
    fn a_malformed_device_is_no_device_at_all() {
        let request = |id: &str, secret: &str| AuthRequest {
            device_id: id.to_owned(),
            device_secret: secret.to_owned(),
            ..AuthRequest::default()
        };
        assert!(presented(&request("laptop", SECRET)).is_some());
        assert!(presented(&request("", SECRET)).is_none());
        assert!(presented(&request("has space", SECRET)).is_none());
        assert!(presented(&request(&"x".repeat(MAX_ID_LEN + 1), SECRET)).is_none());
        assert!(presented(&request("laptop", "short")).is_none());
    }

    #[test]
    fn a_name_is_trimmed_cut_and_stripped_of_control_characters() {
        assert_eq!(clean_name("  Laptop\n "), "Laptop");
        assert_eq!(clean_name(&"é".repeat(100)).chars().count(), MAX_NAME_LEN);
    }

    #[test]
    fn past_the_ceiling_the_least_recently_seen_device_is_forgotten() {
        let mut devices: Vec<Device> = (0..MAX_DEVICES as u64)
            .map(|n| Device {
                last_seen_ms: n + 10,
                ..device(&format!("d{n:02}"), false)
            })
            .collect();
        devices.push(device("gone", true));
        let (kept, dropped) = upsert(
            &devices,
            Device {
                last_seen_ms: 999,
                ..device("new", false)
            },
        );
        assert_eq!(dropped, vec!["d00".to_owned()]);
        assert_eq!(kept.iter().filter(|d| !d.signed_out).count(), MAX_DEVICES);
        assert!(
            kept.iter().any(|d| d.signed_out),
            "a tombstone is not a device and does not count against the ceiling"
        );
    }
}
