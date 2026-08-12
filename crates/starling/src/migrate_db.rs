//! `starling migrate-db`: move a murmur database into this server's.
//!
//! ```text
//! starling migrate-db --from sqlite:/data/mumble-server.sqlite --dry-run
//! starling migrate-db --from sqlite:/data/mumble-server.sqlite --verify
//! starling migrate-db --from mysql://murmur:pw@db/mumble --server-id 3 --instance 1
//! ```
//!
//! `migrate-config` carries the `.ini`; this carries everything that was in the
//! database, which is the part an operator cannot recreate by hand: the channel
//! tree, the registered accounts and their passwords, the ACL entries and
//! groups, the ban list, the stored listeners, and the settings that were
//! changed while the server was running.
//!
//! # The five requirements, and where each of them lives
//!
//! `docs/STORAGE.md` §4 states them in priority order.
//!
//! 1. **Non-destructive.** `starling_migrate::Murmur` opens the source read-only
//!    and issues nothing but `SELECT`s. The old server keeps working, which is
//!    what makes this safe to try.
//! 2. **Verifying.** `--verify` re-reads *both* sides afterwards and compares
//!    counts per entity. A migration nobody can check is a migration nobody can
//!    trust.
//! 3. **Resumable and idempotent.** Every write is an upsert keyed the way the
//!    owning service keys its table, so a second run converges rather than
//!    doubling. Murmur has no ban id, so one is derived from the ban's own
//!    contents ([`ban_id`]) precisely so that a re-run reproduces it.
//! 4. **Loud about what it could not map.** Everything the reader could not
//!    carry, and everything this mapping approximates, is a line in the report,
//!    and the report is printed whether or not anything went wrong.
//! 5. **Per-tenant.** `--server-id` migrates one virtual server; omitted, it
//!    migrates all of them.
//!
//! # Why the writes go through the services
//!
//! Every table this touches belongs to a service, and each service owns its own
//! schema (`docs/STORAGE.md` §1). So this module maps murmur's shapes onto the
//! services' own types and hands them over; it contains no SQL. What it *does*
//! contain is the mapping, and that is the interesting part: murmur's
//! permission bits, its group specification grammar, its two password hashes and
//! its `config` keys all have to arrive meaning what they meant.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

use starling_migrate::{Murmur, Password, Report, Server};
use starling_proto_fancy::channel::{FLAG_DETACHED, FLAG_HIDDEN, FLAG_STRUCTURAL};
use starling_proto_fancy::metadata::Channel;
use starling_proto_fancy::moderation::Ban;
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::permissions::{AclEntry, AclSet, Group};
use starling_runtime::Config;
use starling_runtime::inproc::Broker;
use starling_runtime::log::LogRuntime;
use starling_runtime::serve::context;
use starling_runtime::shutdown::Shutdown;
use starling_runtime::storage::Store;
use starling_userdata::{Accounts, Import as AccountImport, Secret};

/// What the command was asked to do.
#[derive(Debug, Default)]
struct Options {
    /// The murmur database.
    from: String,
    /// murmur's `dbPrefix`, which only the pre-1.5 schema ever had.
    prefix: String,
    /// Which virtual server to move, or all of them.
    server: Option<u32>,
    /// Which Starling instance to move it into. Only meaningful with `server`.
    instance: Option<u32>,
    /// Read and report, write nothing.
    dry_run: bool,
    /// Re-read both sides afterwards and compare.
    verify: bool,
}

/// Run the migration.
///
/// # Errors
///
/// A message when the arguments are unusable, when the murmur database cannot
/// be opened or is not a murmur database, or when a target store cannot be
/// written. Individual rows that will not go in are reported rather than fatal;
/// see the owning services' `import` functions.
pub(crate) fn migrate_db(arguments: &[String]) -> Result<(), String> {
    let options = parse(arguments)?;
    let config = crate::compose::load(arguments).map_err(|error| error.to_string())?;

    // The configured logger, as `set-superuser-password` does: this rewrites
    // every account and every permission on the server, and an operator reading
    // the log afterwards should be able to see that it happened.
    let log = LogRuntime::start_from(&config.logging);
    let logger = log.logger().clone();

    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    let report = runtime.block_on(run(&options, Arc::new(config), logger))?;

    // Drained before returning, or the process exits with the record still in
    // the writer's queue.
    log.finish();
    crate::out(&report)
}

/// Everything, from opening the source to the printed report.
async fn run(
    options: &Options,
    config: Arc<Config>,
    logger: starling_runtime::log::Logger,
) -> Result<String, String> {
    let source = Murmur::open(&options.from, &options.prefix)
        .await
        .map_err(|error| error.to_string())?;

    let servers = source.servers().await.map_err(|error| error.to_string())?;
    let wanted: Vec<u32> = match options.server {
        Some(id) => {
            if !servers.contains(&id) {
                return Err(format!(
                    "{} has no virtual server {id}; it has {}",
                    options.from,
                    list(&servers)
                ));
            }
            vec![id]
        }
        None => servers.clone(),
    };

    let mut text = String::new();
    let _ = writeln!(
        text,
        "source     {} ({})",
        options.from,
        source.layout().name()
    );
    let _ = writeln!(text, "servers    {}", list(&wanted));
    if options.dry_run {
        let _ = writeln!(text, "mode       dry run, nothing is written");
    }
    let _ = writeln!(text);

    // Opened once for every server rather than once per server: they are the
    // same five databases either way, and opening them per tenant would mean a
    // pool per tenant for no benefit.
    let stores = if options.dry_run {
        None
    } else {
        Some(Stores::open(&config, logger).await?)
    };

    for server in wanted {
        let mut report = Report::new();
        let read = source
            .read(server, &mut report)
            .await
            .map_err(|error| error.to_string())?;
        let instance = options.instance.unwrap_or(server);
        known_instance(&config, instance, server)?;

        let counts = Counts::of(&read);
        let _ = writeln!(text, "server {server} -> instance {instance}");
        let _ = write!(text, "{}", counts.describe("  read     "));

        if let Some(stores) = stores.as_ref() {
            let written = write_server(stores, instance, &read, &mut report).await?;
            let _ = write!(text, "{}", written.describe("  written  "));
            if options.verify {
                let _ = write!(text, "{}", verify(stores, instance, &counts).await?);
            }
        }

        if report.is_empty() {
            let _ = writeln!(text, "  nothing was dropped");
        } else {
            let _ = writeln!(
                text,
                "  {} things could not be carried across:",
                report.notes().len()
            );
            for note in report.notes() {
                let _ = writeln!(text, "    {note}");
            }
        }
        let _ = writeln!(text);
    }

    if options.dry_run {
        text.push_str("nothing was written; run again without --dry-run\n");
    }
    Ok(text)
}

/// Refuse to write into a server instance this deployment does not have.
///
/// murmur numbers its virtual servers from **zero** and Starling's shipped
/// deployment has one instance with id **1**, so the commonest single-server
/// migration in the world -- one murmur, one Starling -- lands on an instance
/// nothing serves unless it is redirected. Everything would appear to succeed:
/// the rows go in, the counts add up, `--verify` agrees with itself, and the
/// server starts empty, because nothing ever looks at instance 0.
///
/// Every row this writes is keyed by instance, so this is not a detail that
/// surfaces later; it is the whole migration going to the wrong address.
fn known_instance(config: &Config, instance: u32, server: u32) -> Result<(), String> {
    if config.instances.iter().any(|known| known.id == instance) {
        return Ok(());
    }
    let known: Vec<u32> = config.instances.iter().map(|known| known.id).collect();
    Err(format!(
        "this deployment has no server instance {instance}; it has {}.\n\
         murmur's virtual server {server} would be written there and nothing would read it.\n\
         Use `--server-id {server} --instance <id>` to say where it should go, \
         or add an `[[instances]]` block with id {instance}.",
        list(&known)
    ))
}

/// The five databases a migration writes into.
///
/// Five, because each service owns its own (`docs/STORAGE.md` §1), and they are
/// resolved through the same [`starling_runtime::serve::ServiceContext::storage`]
/// a start would use. Deriving a path a second way here is how a tool ends up
/// quietly writing a database nobody loads.
#[derive(Debug)]
struct Stores {
    userdata: Accounts,
    metadata: Store,
    permissions: Store,
    moderation: Store,
    server_config: Store,
}

impl Stores {
    async fn open(
        config: &Arc<Config>,
        logger: starling_runtime::log::Logger,
    ) -> Result<Self, String> {
        let store = async |name: &str| -> Result<Store, String> {
            context(
                name,
                Arc::clone(config),
                Broker::new(),
                Shutdown::new(),
                logger.clone(),
            )
            .storage()
            .await
            .map_err(|error| format!("{name}: {error}"))
        };

        Ok(Self {
            userdata: Accounts::open(store("userdata").await?)
                .await
                .map_err(|error| format!("userdata: {error}"))?,
            metadata: store("metadata").await?,
            permissions: store("permissions").await?,
            moderation: store("moderation").await?,
            server_config: store("server-config").await?,
        })
    }
}

/// How much of each thing there is.
///
/// The same shape on both sides of the migration, which is what makes
/// `--verify` a comparison rather than a description.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Counts {
    channels: usize,
    links: usize,
    accounts: usize,
    acl_sets: usize,
    bans: usize,
    listeners: usize,
}

impl Counts {
    /// What murmur had.
    fn of(server: &Server) -> Self {
        let mut channels: Vec<u32> = server.acls.iter().map(|acl| acl.channel).collect();
        channels.extend(server.groups.iter().map(|group| group.channel));
        channels.sort_unstable();
        channels.dedup();
        Self {
            channels: server.channels.len(),
            // Both directions, because a link is symmetric and murmur stores
            // each pair once.
            links: server.links.len() * 2,
            accounts: server.users.len(),
            acl_sets: channels.len(),
            bans: server.bans.len(),
            listeners: server.listeners.len(),
        }
    }

    fn describe(&self, prefix: &str) -> String {
        format!(
            "{prefix}{} channels, {} links, {} accounts, {} ACL sets, {} bans, {} listeners\n",
            self.channels, self.links, self.accounts, self.acl_sets, self.bans, self.listeners
        )
    }
}

/// Map one murmur server onto the services and write it.
async fn write_server(
    stores: &Stores,
    instance: u32,
    read: &Server,
    report: &mut Report,
) -> Result<Counts, String> {
    let tree = channel_tree(read);
    let written_tree = starling_metadata::import(&stores.metadata, instance, &tree)
        .await
        .map_err(|error| format!("metadata: {error}"))?;

    let sets = acl_sets(read, report);
    let written_acls = starling_permissions::import(&stores.permissions, instance, &sets)
        .await
        .map_err(|error| format!("permissions: {error}"))?;

    let accounts = accounts(read, report);
    let refused = stores.userdata.import(instance, &accounts).await;
    for note in &refused {
        report.note(note.clone());
    }

    let bans = bans(read, report);
    let written_bans = starling_moderation::import::import(&stores.moderation, instance, &bans)
        .await
        .map_err(|error| format!("moderation: {error}"))?;

    let settings = starling_migrate::Ini::from_pairs(read.config.clone()).to_settings();
    let claimed = starling_server_config::import(&stores.server_config, instance, &settings)
        .await
        .map_err(|error| format!("server-config: {error}"))?;
    unmapped_settings(&read.config, &claimed, report);

    Ok(Counts {
        channels: written_tree.channels,
        links: written_tree.links,
        accounts: accounts.len() - refused.len(),
        acl_sets: written_acls,
        bans: written_bans,
        listeners: written_tree.listeners,
    })
}

/// Re-read both sides and say whether they agree.
///
/// Deliberately reads through the services' own count queries rather than
/// reporting what the writes returned: what an operator wants to know is what is
/// in the database, and a number produced by the code that did the writing
/// cannot answer that.
async fn verify(stores: &Stores, instance: u32, expected: &Counts) -> Result<String, String> {
    let (channels, links) = starling_metadata::import::count(&stores.metadata, instance)
        .await
        .map_err(|error| format!("metadata: {error}"))?;
    let acl_sets = starling_permissions::import::count(&stores.permissions, instance)
        .await
        .map_err(|error| format!("permissions: {error}"))?;
    let bans = starling_moderation::import::count(&stores.moderation, instance)
        .await
        .map_err(|error| format!("moderation: {error}"))?;
    let accounts = stores.userdata.count(instance).await;

    let mut text = String::new();
    let mut disagreed = false;
    let mut compare = |what: &str, want: usize, got: usize| {
        if want != got {
            disagreed = true;
            let _ = writeln!(text, "  verify   {what}: expected {want}, found {got}");
        }
    };
    compare("channels", expected.channels, channels);
    compare("links", expected.links, links);
    compare("ACL sets", expected.acl_sets, acl_sets);
    compare("bans", expected.bans, bans);
    // Accounts are compared as "at least": the target may already have had a
    // SuperUser, and every server has one whether or not murmur wrote a row for
    // it. Fewer than expected is the direction that means something was lost.
    if accounts < expected.accounts {
        disagreed = true;
        let _ = writeln!(
            text,
            "  verify   accounts: expected at least {}, found {accounts}",
            expected.accounts
        );
    }
    if !disagreed {
        text.push_str("  verify   both sides agree\n");
    }
    Ok(text)
}

// -- the mapping ------------------------------------------------------------

/// murmur's channels, links, listeners and remembered channels.
fn channel_tree(read: &Server) -> starling_metadata::ImportedTree {
    use starling_metadata::import::{LastChannel, Listener};

    let channels = read
        .channels
        .iter()
        .map(|channel| Channel {
            id: channel.id,
            parent: channel.parent,
            name: channel.name.clone(),
            description: channel.description.clone(),
            position: channel.position,
            max_users: channel.max_users,
            // Temporary is deliberately absent: murmur never persists a
            // temporary channel, so a stored one cannot be temporary, and
            // setting the flag would make every imported channel vanish the
            // moment its last occupant left.
            flags: if channel.hidden { FLAG_HIDDEN } else { 0 }
                | if channel.structural { FLAG_STRUCTURAL } else { 0 }
                // Without this every detached channel arrives as a second
                // root: the flag is the only thing distinguishing "parentless
                // because it is out of the tree" from "parentless because it
                // *is* the tree", and clients walk by parent id.
                | if channel.detached { FLAG_DETACHED } else { 0 },
            expiry_mode: channel.expiry_mode,
            expiry_duration_s: channel.expiry_duration_s,
            created_at_ms: channel.created_at_ms,
            ..Channel::default()
        })
        .collect();

    // Both directions. murmur stores a link once, as an unordered pair, and
    // Starling's table is keyed by `(channel, linked)`; writing one direction
    // would make the link visible from one end only.
    let links = read
        .links
        .iter()
        .flat_map(|link| [(link.channel, link.linked), (link.linked, link.channel)])
        .collect();

    let listeners = read
        .listeners
        .iter()
        .map(|listener| Listener {
            account: u64::from(listener.user),
            channel: listener.channel,
            volume: listener.volume,
            enabled: listener.enabled,
        })
        .collect();

    // Only for accounts murmur recorded a disconnection for. `left_at_ms` is
    // what `remember_channel_duration` is measured from, so a zero here would
    // read as "long ago" and expire the memory of every returning user at once.
    let last_channels = read
        .users
        .iter()
        .filter(|user| user.last_disconnect_s > 0)
        .map(|user| LastChannel {
            account: u64::from(user.id),
            channel: user.last_channel,
            left_at_ms: user.last_disconnect_s.saturating_mul(1_000),
        })
        .collect();

    starling_metadata::ImportedTree {
        channels,
        links,
        listeners,
        last_channels,
    }
}

/// One [`AclSet`] per channel that has entries or groups.
///
/// murmur stores entries and groups in two flat tables keyed by channel;
/// Starling stores one set per channel, whole, because the order within a set is
/// what makes deny beat allow. The `inherit` flag comes from the **channel**
/// row, where murmur keeps it, rather than from the entries.
fn acl_sets(read: &Server, report: &mut Report) -> Vec<AclSet> {
    let mut sets: BTreeMap<u32, AclSet> = BTreeMap::new();

    let set_for = |channel: u32, sets: &mut BTreeMap<u32, AclSet>| {
        let inherit = read
            .channels
            .iter()
            .find(|c| c.id == channel)
            .is_none_or(|c| c.inherit_acl);
        let _ = sets.entry(channel).or_insert_with(|| AclSet {
            channel,
            inherit,
            ..AclSet::default()
        });
    };

    for acl in &read.acls {
        set_for(acl.channel, &mut sets);
        let (grant, deny) = (
            permissions(acl.grant, report),
            permissions(acl.deny, report),
        );
        if let Some(set) = sets.get_mut(&acl.channel) {
            set.acls.push(AclEntry {
                apply_here: acl.apply_here,
                apply_subs: acl.apply_subs,
                // Never inherited: this is what is *written on* the channel.
                // The flag means "shown to a client as coming from above", and
                // an entry marked so would be one an operator could not edit.
                inherited: false,
                account: acl.user.map(u64::from),
                group: acl.group.clone(),
                grant,
                deny,
            });
        }
    }

    for group in &read.groups {
        set_for(group.channel, &mut sets);
        let (add, remove): (Vec<u64>, Vec<u64>) = read
            .members
            .iter()
            .filter(|member| member.group == group.id)
            .fold((Vec::new(), Vec::new()), |(mut add, mut remove), member| {
                if member.add {
                    add.push(u64::from(member.user));
                } else {
                    remove.push(u64::from(member.user));
                }
                (add, remove)
            });
        if let Some(set) = sets.get_mut(&group.channel) {
            set.groups.push(Group {
                name: group.name.clone(),
                inherited: false,
                inherit: group.inherit,
                inheritable: group.inheritable,
                add,
                remove,
                // Computed by the evaluator from the tree, never stored: a
                // recorded list would be a snapshot of an inheritance that
                // changes whenever a parent's group does.
                inherited_members: Vec::new(),
            });
        }
    }

    sets.into_values().collect()
}

/// murmur's permission bits, which are Starling's.
///
/// Transcribed rather than translated: `starling_proto_fancy::perm` states that
/// its values come from `vendor/server/src/ACL.h` and are wire-visible, so a
/// mapping table here would be a second copy of that claim. What this *does* do
/// is drop anything outside the declared set, `ACL.h`'s internal `Cached` marker
/// above all, and say so.
fn permissions(bits: u32, report: &mut Report) -> u32 {
    let kept = Perm::from_bits_truncate(bits);
    let dropped = bits & !kept.bits();
    if dropped != 0 {
        report.note(format!(
            "an ACL entry carries permission bits {dropped:#x}, \
             which this build has no name for; they are dropped"
        ));
    }
    kept.bits()
}

/// murmur's registered users.
fn accounts(read: &Server, report: &mut Report) -> Vec<AccountImport> {
    read.users
        .iter()
        .map(|user| {
            let cert_hash = if user.cert_hash.is_empty() {
                Vec::new()
            } else {
                from_hex(&user.cert_hash).unwrap_or_else(|| {
                    report.note(format!(
                        "account {} has a certificate hash that is not hex; \
                         it is imported without one and must log in by password",
                        user.id
                    ));
                    Vec::new()
                })
            };

            let totp_secret = if user.totp_secret.is_empty() {
                None
            } else {
                match from_base32(&user.totp_secret) {
                    Some(secret) => Some(secret),
                    None => {
                        // Loud, because the account still logs in afterwards
                        // and has quietly lost its second factor.
                        report.note(format!(
                            "account {} has a two-factor secret that is not base32; \
                             it is imported with two-factor authentication off",
                            user.id
                        ));
                        None
                    }
                }
            };

            AccountImport {
                id: u64::from(user.id),
                name: user.name.clone(),
                email: user.email.clone(),
                comment: user.comment.clone(),
                cert_hash,
                password: secret(&user.password),
                totp_secret,
                texture: user.texture.clone(),
                // murmur records no creation time, so the earliest moment it
                // can vouch for is used instead of inventing one. Zero would
                // date every migrated account to 1970 on every client that
                // shows it.
                created_at_ms: user.last_active_s.saturating_mul(1_000),
                last_active_ms: user.last_active_s.saturating_mul(1_000),
            }
        })
        .collect()
}

/// murmur's stored password, as something that can verify a login.
fn secret(password: &Password) -> Option<Secret> {
    match password {
        Password::None => None,
        Password::Pbkdf2 {
            salt,
            key,
            iterations,
        } => Some(Secret::Murmur {
            salt: salt.clone(),
            key: key.clone(),
            iterations: *iterations,
        }),
        Password::Sha1 { digest } => Some(Secret::MurmurLegacy {
            digest: digest.clone(),
        }),
    }
}

/// murmur's ban list.
fn bans(read: &Server, report: &mut Report) -> Vec<Ban> {
    read.bans
        .iter()
        .map(|ban| {
            let cert_hash = if ban.cert_hash.is_empty() {
                Vec::new()
            } else {
                from_hex(&ban.cert_hash).unwrap_or_else(|| {
                    report.note(format!(
                        "the ban on {:?} has a certificate hash that is not hex; \
                         it is imported as an address ban only",
                        ban.name
                    ));
                    Vec::new()
                })
            };
            Ban {
                id: ban_id(&ban.address, ban.prefix_len, &cert_hash),
                address: ban.address.clone(),
                prefix_len: ban.prefix_len,
                name: ban.name.clone(),
                cert_hash,
                reason: ban.reason.clone(),
                start_ms: ban.start_s.saturating_mul(1_000),
                duration_s: ban.duration_s,
            }
        })
        .collect()
}

/// A ban id derived from the ban itself.
///
/// murmur has no ban id: its primary key is exactly the address, the prefix and
/// the certificate hash, so those three are what identifies a ban and what a
/// second run must reproduce. A counter or a timestamp here would make
/// `migrate-db` double an operator's ban list every time it was run.
///
/// FNV-1a, and it does not need to be anything stronger: a collision means two
/// bans in one server share a row, which requires an adversary who can already
/// choose the contents of two of that server's bans.
fn ban_id(address: &[u8], prefix_len: u32, cert_hash: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in address
        .iter()
        .chain(prefix_len.to_be_bytes().iter())
        .chain(cert_hash.iter())
    {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Report the `config` keys that were read and not stored.
///
/// The `.ini` reader already warns about keys with no home; this is the same
/// promise applied to the table, and it matters more here: the table is where
/// the settings somebody *changed* live, so a key dropped from it is a change
/// somebody made being undone.
fn unmapped_settings(config: &BTreeMap<String, String>, claimed: &[String], report: &mut Report) {
    if config.is_empty() {
        return;
    }
    let moved = claimed.len();
    let total = config.len();
    if moved < total {
        report.note(format!(
            "murmur's config table holds {total} settings and {moved} of them have a home here; \
             the rest are either deployment settings, which `migrate-config` carries, \
             or not implemented yet"
        ));
    }
}

// -- odds and ends ----------------------------------------------------------

/// Bytes from hex.
///
/// The reader keeps murmur's digests as text so that a value which is not hex
/// can be reported against the account or ban it came from, which is here.
fn from_hex(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        out.push(nibble(*pair.first()?)? << 4 | nibble(*pair.get(1)?)?);
    }
    Some(out)
}

/// Bytes from RFC 4648 base32, which is how the fork stores a TOTP secret.
///
/// Padding is accepted and ignored, and so is the lower-case spelling, because
/// what is in the column is whatever an authenticator app showed the user and
/// whatever they pasted back.
fn from_base32(value: &str) -> Option<Vec<u8>> {
    let mut buffer: u16 = 0;
    let mut bits = 0_u8;
    let mut out = Vec::with_capacity(value.len() * 5 / 8);
    for character in value.trim().chars().filter(|c| *c != '=') {
        let index = match character.to_ascii_uppercase() {
            letter @ 'A'..='Z' => u16::from(letter as u8 - b'A'),
            digit @ '2'..='7' => u16::from(digit as u8 - b'2') + 26,
            _ => return None,
        };
        buffer = buffer << 5 | index;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    // The trailing bits are padding and must be zero; anything else is a
    // truncated secret, which would produce codes that never match.
    if buffer & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// `1, 2 and 3`, for a message an operator reads.
fn list(ids: &[u32]) -> String {
    match ids {
        [] => "none".to_owned(),
        [only] => only.to_string(),
        [rest @ .., last] => format!(
            "{} and {last}",
            rest.iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Read the arguments.
fn parse(arguments: &[String]) -> Result<Options, String> {
    let from =
        flag(arguments, "--from").ok_or("migrate-db needs --from <url>\n\n".to_owned() + USAGE)?;
    let number = |name: &str| -> Result<Option<u32>, String> {
        flag(arguments, name)
            .map(|value| {
                value
                    .parse::<u32>()
                    .map_err(|_| format!("{name} needs a server instance id, not {value:?}"))
            })
            .transpose()
    };
    let options = Options {
        from,
        prefix: flag(arguments, "--table-prefix").unwrap_or_default(),
        server: number("--server-id")?,
        instance: number("--instance")?,
        dry_run: arguments.iter().any(|argument| argument == "--dry-run"),
        verify: arguments.iter().any(|argument| argument == "--verify"),
    };
    if options.instance.is_some() && options.server.is_none() {
        // Otherwise every virtual server in the source would be written on top
        // of the same instance, and the last one would win silently.
        return Err("--instance needs --server-id: it says where one server goes".to_owned());
    }
    Ok(options)
}

/// The value of `name`, if it was given.
fn flag(arguments: &[String], name: &str) -> Option<String> {
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        if argument == name {
            return rest.next().cloned();
        }
    }
    None
}

/// What this command accepts.
const USAGE: &str = "usage: starling migrate-db --from <murmur database url> \
     [--server-id <id>] [--instance <id>]\n\
     \x20                          [--table-prefix <prefix>] [--dry-run] [--verify] \
     [--config <file>]";

#[cfg(test)]
mod tests {
    use super::*;
    use starling_migrate::{Acl, Ban as MurmurBan, Channel as MurmurChannel, Group as MurmurGroup};

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn the_source_is_required_rather_than_guessed_at() {
        // Defaulting to murmur's own `murmur.sqlite` would read whatever file
        // happened to be beside the binary and report a migration of it.
        assert!(parse(&args(&["migrate-db"])).is_err());
    }

    #[test]
    fn an_instance_without_a_server_is_refused() {
        // Otherwise every virtual server lands on one instance and the last one
        // silently wins.
        let error = parse(&args(&["migrate-db", "--from", "x", "--instance", "1"]))
            .expect_err("--instance alone is ambiguous");
        assert!(error.contains("--server-id"), "{error}");
    }

    #[test]
    fn a_non_numeric_server_id_is_reported_rather_than_defaulted() {
        let error = parse(&args(&["migrate-db", "--from", "x", "--server-id", "main"]))
            .expect_err("a non-numeric id must be refused");
        assert!(error.contains("--server-id"), "{error}");
    }

    #[test]
    fn the_flags_are_read() {
        let options = parse(&args(&[
            "migrate-db",
            "--from",
            "sqlite:/tmp/m.sqlite",
            "--server-id",
            "3",
            "--instance",
            "1",
            "--table-prefix",
            "mb_",
            "--dry-run",
            "--verify",
        ]))
        .expect("parsed");
        assert_eq!(options.from, "sqlite:/tmp/m.sqlite");
        assert_eq!(options.server, Some(3));
        assert_eq!(options.instance, Some(1));
        assert_eq!(options.prefix, "mb_");
        assert!(options.dry_run);
        assert!(options.verify);
    }

    /// A server with one room, one group, one entry and one ban.
    fn server() -> Server {
        Server {
            id: 1,
            channels: vec![
                MurmurChannel {
                    id: 0,
                    name: "Root".to_owned(),
                    inherit_acl: true,
                    ..MurmurChannel::default()
                },
                MurmurChannel {
                    id: 1,
                    parent: Some(0),
                    name: "Lobby".to_owned(),
                    hidden: true,
                    inherit_acl: false,
                    ..MurmurChannel::default()
                },
            ],
            acls: vec![Acl {
                channel: 1,
                priority: 0,
                group: Some("admin".to_owned()),
                apply_here: true,
                apply_subs: true,
                grant: Perm::KICK.bits(),
                ..Acl::default()
            }],
            groups: vec![MurmurGroup {
                id: 7,
                channel: 1,
                name: "admin".to_owned(),
                inherit: true,
                inheritable: true,
            }],
            members: vec![starling_migrate::GroupMember {
                group: 7,
                user: 3,
                add: true,
            }],
            bans: vec![MurmurBan {
                address: vec![0; 16],
                prefix_len: 128,
                name: "mallory".to_owned(),
                cert_hash: "abcd".to_owned(),
                reason: "spam".to_owned(),
                start_s: 1_700_000_000,
                duration_s: 0,
            }],
            ..Server::default()
        }
    }

    #[test]
    fn a_channels_acl_inheritance_comes_from_the_channel_row() {
        // murmur keeps `inherit_acl` on the channel and Starling keeps it on the
        // set. Reading it from the wrong place turns inheritance on for a
        // channel an operator deliberately detached, which hands out every
        // permission its parents grant.
        let mut report = Report::new();
        let sets = acl_sets(&server(), &mut report);
        let lobby = sets.iter().find(|set| set.channel == 1).expect("the lobby");
        assert!(!lobby.inherit);
    }

    #[test]
    fn a_groups_members_are_split_into_added_and_removed() {
        let mut report = Report::new();
        let sets = acl_sets(&server(), &mut report);
        let lobby = sets.iter().find(|set| set.channel == 1).expect("the lobby");
        let group = lobby.groups.first().expect("the admin group");
        assert_eq!(group.name, "admin");
        assert_eq!(group.add, vec![3]);
        assert!(group.remove.is_empty());
    }

    #[test]
    fn a_permission_bit_this_build_has_no_name_for_is_dropped_and_reported() {
        // `ACL.h`'s `Cached` marker is internal bookkeeping; carrying it would
        // put a bit on the wire that no client has a meaning for.
        let mut report = Report::new();
        let kept = permissions(Perm::KICK.bits() | 0x0800_0000, &mut report);
        assert_eq!(kept, Perm::KICK.bits());
        assert_eq!(report.notes().len(), 1, "{:?}", report.notes());
    }

    #[test]
    fn a_hidden_channel_stays_hidden_and_is_never_temporary() {
        // A temporary flag here would make every imported channel disappear the
        // moment its last occupant left.
        let tree = channel_tree(&server());
        let lobby = tree
            .channels
            .iter()
            .find(|channel| channel.id == 1)
            .expect("the lobby");
        assert_eq!(lobby.flags, FLAG_HIDDEN);
    }

    #[test]
    fn a_detached_channel_is_flagged_rather_than_becoming_a_second_root() {
        // Both are parentless, and the flag is the only thing that says which
        // is which. Without it, every meeting room and friend chat on a Fancy
        // server arrives as another root and clients draw them at the top of
        // the tree.
        // Added to the ordinary server rather than replacing its channels: the
        // point of the test is that the root and this one end up *different*,
        // so both have to be in the same tree.
        let mut read = server();
        read.channels.push(MurmurChannel {
            id: 9,
            parent: None,
            detached: true,
            name: "Friends".to_owned(),
            inherit_acl: true,
            ..MurmurChannel::default()
        });
        let tree = channel_tree(&read);
        let friends = tree
            .channels
            .iter()
            .find(|channel| channel.id == 9)
            .expect("the detached channel");
        assert_eq!(friends.parent, None);
        assert_eq!(friends.flags & FLAG_DETACHED, FLAG_DETACHED);

        let root = tree
            .channels
            .iter()
            .find(|channel| channel.id == 0)
            .expect("the root");
        assert_eq!(root.flags & FLAG_DETACHED, 0, "the root is not detached");
    }

    #[test]
    fn a_link_is_written_in_both_directions() {
        // murmur stores an unordered pair once; Starling's table is keyed by
        // `(channel, linked)`, so one row would make the link visible from one
        // end only.
        let read = Server {
            links: vec![starling_migrate::Link {
                channel: 0,
                linked: 1,
            }],
            ..server()
        };
        let tree = channel_tree(&read);
        assert_eq!(tree.links, vec![(0, 1), (1, 0)]);
    }

    #[test]
    fn a_ban_id_is_derived_from_the_ban_so_a_second_run_reproduces_it() {
        // murmur has no ban id. A counter here would double an operator's ban
        // list on every run.
        let mut report = Report::new();
        let first = bans(&server(), &mut report);
        let second = bans(&server(), &mut report);
        assert_eq!(
            first.first().map(|ban| ban.id),
            second.first().map(|ban| ban.id)
        );
        assert_ne!(
            ban_id(&[0; 16], 128, b"one"),
            ban_id(&[0; 16], 128, b"two"),
            "two different bans must not share a row"
        );
    }

    #[test]
    fn both_of_murmurs_password_forms_arrive_as_something_that_can_verify() {
        assert!(matches!(
            secret(&Password::Pbkdf2 {
                salt: vec![1, 2],
                key: vec![3, 4],
                iterations: 1_000,
            }),
            Some(Secret::Murmur { .. })
        ));
        assert!(matches!(
            secret(&Password::Sha1 {
                digest: vec![0; 20]
            }),
            Some(Secret::MurmurLegacy { .. })
        ));
        assert!(secret(&Password::None).is_none());
    }

    #[test]
    fn a_two_factor_secret_survives_the_base32_it_was_stored_as() {
        // Losing it silently turns two-factor authentication off for an account
        // whose owner believes it is on.
        assert_eq!(from_base32("JBSWY3DP"), Some(b"Hello".to_vec()));
        assert_eq!(from_base32("JBSWY3DP===="), Some(b"Hello".to_vec()));
        assert_eq!(from_base32("jbswy3dp"), Some(b"Hello".to_vec()));
        assert_eq!(from_base32("not base32!"), None);
    }

    #[test]
    fn a_certificate_hash_decodes_from_the_hex_murmur_wrote() {
        assert_eq!(from_hex("00ff"), Some(vec![0x00, 0xff]));
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("abc"), None);
    }

    #[test]
    fn a_server_instance_this_deployment_does_not_have_is_refused() {
        // murmur numbers from zero and the shipped deployment has instance 1,
        // so the commonest migration there is lands on an instance nothing
        // serves. Everything succeeds and the server starts empty.
        let config = Config::with_defaults(std::path::Path::new("/run/starling"));
        let error = known_instance(&config, 0, 0).expect_err("instance 0 is not configured");
        assert!(error.contains("--instance"), "{error}");
        assert!(known_instance(&config, 1, 0).is_ok());
    }

    #[test]
    fn the_server_list_reads_as_a_sentence() {
        assert_eq!(list(&[]), "none");
        assert_eq!(list(&[1]), "1");
        assert_eq!(list(&[1, 2]), "1 and 2");
        assert_eq!(list(&[1, 2, 3]), "1, 2 and 3");
    }
}
