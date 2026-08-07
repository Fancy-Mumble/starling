//! What the public list is told, and the conditions that must hold first.
//!
//! Deliberately free of I/O: the payload and the rules about whether to send it
//! at all are the part worth testing exhaustively, and a test that needs a
//! socket is a test nobody writes enough of.
//!
//! Every field and every rule below is murmur's `src/murmur/Register.cpp`. The
//! rules in particular are not ours to relax; they are what the list expects,
//! and a server that ignores them is a server whose registration is refused for
//! reasons nobody can see from here.

use starling_proto_fancy::serverconfig::Snapshot;

/// Where murmur registers, and so where Starling does.
///
/// Not configurable. A "public list" that can be pointed elsewhere is a
/// credential-exfiltration setting with a friendly name: the payload carries
/// `registry_password`, and the client certificate authenticates it.
pub const PUBLIC_LIST: &str = "https://publist-registration.mumble.info/v1/register";

/// Everything the public list is told about this server.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    /// The name shown in the server browser. murmur's `registerName`.
    pub name: String,
    /// The DNS name the list should reach this server at.
    pub host: String,
    /// The shared secret that proves a later update is the same server.
    pub password: String,
    /// The control port.
    pub port: u16,
    /// The web page the listing links to.
    pub url: String,
    /// SHA-1 of the server certificate, lowercase hex.
    ///
    /// The same fingerprint a client pins on first connection, which is how the
    /// list ties an entry to an identity rather than to an address.
    pub digest: String,
    /// Users connected right now.
    pub users: u32,
    /// Channels that exist.
    pub channels: u32,
    /// Free-text country or region. Omitted entirely when empty.
    pub location: String,
}

impl Listing {
    /// The document murmur posts, field for field.
    ///
    /// Hand-rolled rather than pulled from an XML crate: this is nine text
    /// elements with no attributes, no namespaces and no nesting, and the whole
    /// of the correctness lives in `escape`.
    #[must_use]
    pub fn to_xml(&self) -> String {
        let mut xml = String::from("<server>");
        // The identity of the software, which the list uses for statistics.
        // murmur's `OSInfo::fillXml` also sends a hash of the host's MAC
        // addresses and a CPU fingerprint; neither is reproduced here. Starling
        // does not need a stable hardware identifier to be listed, and
        // inventing one to match murmur would be a privacy regression adopted
        // for symmetry alone.
        push_element(&mut xml, "version", env!("CARGO_PKG_VERSION"));
        push_element(
            &mut xml,
            "release",
            &format!("Starling {}", env!("CARGO_PKG_VERSION")),
        );
        push_element(&mut xml, "os", std::env::consts::OS);
        push_element(&mut xml, "osarch", std::env::consts::ARCH);

        push_element(&mut xml, "name", &self.name);
        push_element(&mut xml, "host", &self.host);
        push_element(&mut xml, "password", &self.password);
        push_element(&mut xml, "port", &self.port.to_string());
        push_element(&mut xml, "url", &self.url);
        push_element(&mut xml, "digest", &self.digest);
        push_element(&mut xml, "users", &self.users.to_string());
        push_element(&mut xml, "channels", &self.channels.to_string());
        // Omitted rather than sent empty, as murmur does.
        if !self.location.is_empty() {
            push_element(&mut xml, "location", &self.location);
        }
        xml.push_str("</server>");
        xml
    }

    /// The same document with the secret replaced, for a log line.
    ///
    /// Exists because the useful thing to log when a registration is refused is
    /// the body that was refused, and the body contains a password.
    #[must_use]
    pub fn to_xml_redacted(&self) -> String {
        Self {
            password: String::from("[redacted]"),
            ..self.clone()
        }
        .to_xml()
    }
}

/// Append `<tag>text</tag>`, escaped.
fn push_element(xml: &mut String, tag: &str, text: &str) {
    xml.push('<');
    xml.push_str(tag);
    xml.push('>');
    xml.push_str(&escape(text));
    xml.push_str("</");
    xml.push_str(tag);
    xml.push('>');
}

/// The three characters that cannot appear literally in XML text.
///
/// A server called `Bob & Friends` produces a document the list rejects as
/// malformed, and the operator sees only that they are not listed. `&` must be
/// replaced first or the replacement's own ampersand is escaped again.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Why a server is not being announced.
///
/// Each variant is a condition murmur checks before its first registration
/// (`Register.cpp:21`). They are reported rather than counted, because "we are
/// not on the list" is a question an operator asks once and needs a whole answer
/// to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unlisted {
    /// No name to be listed under.
    #[error("registry_name is not set, so there is nothing to be listed as")]
    NoName,
    /// No shared secret, so no later update could prove it is the same server.
    #[error("registry_password is not set, so no later update could be authenticated")]
    NoPassword,
    /// No web page.
    #[error("registry_url is not set, and the list requires one")]
    NoUrl,
    /// The server is private.
    ///
    /// murmur refuses outright, and this is a rule rather than a preference: a
    /// public list is a directory of servers people can join.
    #[error("the server has a password set; a private server is not listed publicly")]
    PasswordProtected,
    /// Pings are off, so the listing could never be measured.
    #[error("allow_ping is off, so the list could not measure this server")]
    PingDisabled,
    /// The certificate has not been written yet.
    ///
    /// Not a misconfiguration: on a first boot the gateway generates the pair,
    /// and until it has, there is no fingerprint to be listed under.
    #[error("the server certificate does not exist yet")]
    NoCertificate,
}

/// Whether this configuration may be announced, and why not if it may not.
///
/// # Errors
///
/// The first condition that fails, in murmur's own order.
pub fn eligible(config: &Snapshot) -> Result<(), Unlisted> {
    if config.registry_name.is_empty() {
        return Err(Unlisted::NoName);
    }
    if config.registry_password.is_empty() {
        return Err(Unlisted::NoPassword);
    }
    if config.registry_url.is_empty() {
        return Err(Unlisted::NoUrl);
    }
    if !config.password.is_empty() {
        return Err(Unlisted::PasswordProtected);
    }
    if !config.allow_ping {
        return Err(Unlisted::PingDisabled);
    }
    Ok(())
}

/// Build the document's fields from the settings that decide them.
///
/// Pure, and the counts and digest are arguments rather than fetched here: they
/// come from three different services, and which service owns which fact is not
/// a decision this function should be able to get wrong.
#[must_use]
pub fn compose(config: &Snapshot, port: u16, digest: String, users: u32, channels: u32) -> Listing {
    Listing {
        name: config.registry_name.clone(),
        // Empty is meaningful rather than missing: it tells the list to use
        // whatever address the announcement arrived from, which is what a server
        // behind one NAT and no DNS name of its own wants.
        host: config.registry_hostname.clone(),
        password: config.registry_password.clone(),
        port,
        url: config.registry_url.clone(),
        digest,
        users,
        channels,
        location: config.registry_location.clone(),
    }
}

/// SHA-1 of a DER certificate, lowercase hex.
///
/// murmur's `Server::getDigest()`. SHA-1 is not a choice: it is the identifier
/// the list and every Mumble client already key a server by, and changing it
/// here would mean not being recognised rather than being more secure.
#[must_use]
pub fn digest(der: &[u8]) -> String {
    use sha1::Digest as _;
    let hash = sha1::Sha1::digest(der);
    let mut hex = String::with_capacity(hash.len() * 2);
    for byte in hash {
        // Two lowercase hex digits, which is what `toHex()` produces on the
        // other side of this comparison.
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listable() -> Snapshot {
        Snapshot {
            registry_name: "Starling".to_owned(),
            registry_password: "shared-secret".to_owned(),
            registry_url: "https://example.org".to_owned(),
            password: String::new(),
            allow_ping: true,
            ..Snapshot::default()
        }
    }

    fn listing() -> Listing {
        Listing {
            name: "Starling".to_owned(),
            host: "mumble.example.org".to_owned(),
            password: "shared-secret".to_owned(),
            port: 64738,
            url: "https://example.org".to_owned(),
            digest: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_owned(),
            users: 7,
            channels: 3,
            location: String::new(),
        }
    }

    #[test]
    fn a_fully_configured_public_server_is_eligible() {
        assert_eq!(eligible(&listable()), Ok(()));
    }

    #[test]
    fn a_password_protected_server_is_never_listed() {
        // murmur's rule, and the one most likely to surprise: everything else is
        // set correctly and the server still does not appear.
        let mut config = listable();
        config.password = "hunter2".to_owned();
        assert_eq!(eligible(&config), Err(Unlisted::PasswordProtected));
    }

    #[test]
    fn a_server_that_answers_no_pings_is_not_listed() {
        // A listing the list cannot measure is a dead entry in a browser.
        let mut config = listable();
        config.allow_ping = false;
        assert_eq!(eligible(&config), Err(Unlisted::PingDisabled));
    }

    #[test]
    fn each_missing_registry_field_is_named_on_its_own() {
        // "Not registering: missing required fields" costs an operator an
        // afternoon. Which field costs them a grep.
        let mut config = listable();
        config.registry_name = String::new();
        assert_eq!(eligible(&config), Err(Unlisted::NoName));

        let mut config = listable();
        config.registry_password = String::new();
        assert_eq!(eligible(&config), Err(Unlisted::NoPassword));

        let mut config = listable();
        config.registry_url = String::new();
        assert_eq!(eligible(&config), Err(Unlisted::NoUrl));
    }

    #[test]
    fn the_document_carries_every_field_murmur_sends() {
        let xml = listing().to_xml();
        for expected in [
            "<name>Starling</name>",
            "<host>mumble.example.org</host>",
            "<password>shared-secret</password>",
            "<port>64738</port>",
            "<url>https://example.org</url>",
            "<digest>da39a3ee5e6b4b0d3255bfef95601890afd80709</digest>",
            "<users>7</users>",
            "<channels>3</channels>",
        ] {
            assert!(xml.contains(expected), "{expected} is missing from {xml}");
        }
        assert!(xml.starts_with("<server>") && xml.ends_with("</server>"));
    }

    #[test]
    fn an_empty_location_is_omitted_rather_than_sent_blank() {
        assert!(!listing().to_xml().contains("location"));
        let listed = Listing {
            location: "Frankfurt".to_owned(),
            ..listing()
        };
        assert!(listed.to_xml().contains("<location>Frankfurt</location>"));
    }

    #[test]
    fn a_name_with_xml_in_it_produces_a_well_formed_document() {
        // The failure this prevents: a server called `Bob & Friends` is silently
        // absent from the list forever, because the document it posts is
        // malformed and nothing on this side ever sees the parse error.
        let listed = Listing {
            name: "Bob & Friends <the sequel>".to_owned(),
            ..listing()
        };
        let xml = listed.to_xml();
        assert!(xml.contains("<name>Bob &amp; Friends &lt;the sequel&gt;</name>"));
        // The escaped ampersand must not itself be escaped again.
        assert!(!xml.contains("&amp;amp;"));
    }

    #[test]
    fn the_redacted_document_is_the_same_document_without_the_secret() {
        // What gets logged when a registration is refused.
        let xml = listing().to_xml_redacted();
        assert!(!xml.contains("shared-secret"));
        assert!(xml.contains("<password>[redacted]</password>"));
        assert!(xml.contains("<name>Starling</name>"));
    }

    #[test]
    fn the_document_is_composed_from_the_operators_settings() {
        let mut config = listable();
        config.registry_hostname = "mumble.example.org".to_owned();
        config.registry_location = "Frankfurt".to_owned();

        let composed = compose(&config, 64738, "abc".to_owned(), 7, 3);

        assert_eq!(composed.name, "Starling");
        assert_eq!(composed.host, "mumble.example.org");
        assert_eq!(composed.password, "shared-secret");
        assert_eq!(composed.url, "https://example.org");
        assert_eq!(composed.location, "Frankfurt");
        assert_eq!(composed.port, 64738);
        assert_eq!(composed.users, 7);
        assert_eq!(composed.channels, 3);
    }

    #[test]
    fn an_unset_hostname_stays_empty_rather_than_becoming_a_guess() {
        // Empty tells the list to use the address the announcement came from.
        // Substituting a local hostname here would publish an address nobody
        // outside the host can reach.
        let composed = compose(&listable(), 64738, String::new(), 0, 0);
        assert!(composed.host.is_empty());
    }

    #[test]
    fn the_digest_is_the_sha1_every_mumble_client_already_keys_a_server_by() {
        // The well-known SHA-1 of the empty input, so this asserts the encoding
        // rather than agreeing with whatever the implementation produced.
        assert_eq!(digest(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(digest(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }
}
