//! The livery document: its field-wise merge, its canonical form, and what a
//! server is not allowed to say.
//!
//! Livery is presentation an operator supplies and a client renders before it
//! has authenticated anything. That makes every field here a message from a
//! party that has proven nothing, so the rules below are about what is
//! *inexpressible* rather than what is filtered: a colour is three integers or
//! it is dropped, and there is no field anywhere that becomes CSS, markup or a
//! URL a viewer's machine fetches.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};
use starling_proto_fancy::serverconfig::Livery;
use starling_proto_fancy::serverconfig::livery::{Palette, Tag, tag::Tone};

/// How many bytes of the SHA-256 travel in the UDP ping.
///
/// The reply's size is this responder's amplification factor, and it answers a
/// ~16-byte request unauthenticated. Sixty-four bits separates one operator's
/// livery from the next by a margin nothing here needs to beat; the document
/// itself arrives over TLS, where the whole thing is checked.
pub const DIGEST_BYTES: usize = 8;

/// Characters in a name that stands in for the host in headings.
pub const MAX_DISPLAY_NAME: usize = 64;
/// Characters in the single line under the name.
pub const MAX_TAGLINE: usize = 120;
/// Characters in the motto card. A paragraph, not a page.
pub const MAX_MOTD: usize = 400;
/// Characters in one chip.
pub const MAX_TAG_LABEL: usize = 24;
/// Chips, past which the row wraps into the layout below it.
pub const MAX_TAGS: usize = 4;

/// Every settable field name, which is also the order `canonical` emits them.
pub const FIELDS: &[&str] = &[
    "banner_focus_x",
    "banner_focus_y",
    "banner_key",
    "dark",
    "display_name",
    "icon_key",
    "light",
    "motd",
    "rules_url",
    "tagline",
    "tags",
];

/// A refused livery write, and which field caused it.
///
/// Field and reason are separate because an operator acts on both: the name
/// tells them where to look, the reason tells them what to type instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid {
    /// The field, in the form an operator names it: `motd`, `dark.accent`,
    /// `tags[].href`.
    pub field: String,
    /// The rule it broke.
    pub reason: Reason,
}

/// What was wrong with a field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// No livery document has a field by this name.
    Unknown,
    /// Past the cap carried here, counted in characters.
    TooLong(usize),
    /// More entries than the cap carried here. Separate from `TooLong` because
    /// the two produce different sentences, and an operator reading "tags is
    /// longer than 4 characters" has been told the wrong thing about the wrong
    /// unit.
    TooMany(usize),
    /// Not `#rrggbb`. Carries what was sent, so the message can quote it.
    NotAColour(String),
    /// Not an `https://` URL.
    NotHttps,
    /// A focus point outside 0..=100.
    OffImage,
    /// The JSON value was not the shape this field takes, named here.
    WrongType(&'static str),
    /// Not one of the `Tag.Tone` names.
    NotATone(String),
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let field = &self.field;
        match &self.reason {
            Reason::Unknown => write!(f, "no livery field is called {field}"),
            Reason::TooLong(limit) => write!(f, "{field} is longer than {limit} characters"),
            Reason::TooMany(limit) => write!(f, "{field} may hold at most {limit}"),
            Reason::NotAColour(value) => write!(f, "{field} is {value}, which is not #rrggbb"),
            Reason::NotHttps => write!(f, "{field} must be an https:// URL"),
            Reason::OffImage => write!(f, "{field} must be between 0 and 100"),
            Reason::WrongType(shape) => write!(f, "{field} must be {shape}"),
            Reason::NotATone(name) => write!(f, "{field} is {name}, which is not a tone"),
        }
    }
}

impl Invalid {
    fn at(field: &str, reason: Reason) -> Self {
        Self {
            field: field.to_owned(),
            reason,
        }
    }
}

/// Copy only `fields` from `values` into `current`.
///
/// The same reasoning as the settings merge next door: a whole-document write
/// would let two operators editing different halves of the branding silently
/// overwrite each other.
///
/// # Errors
///
/// Names a field no document has. Unlike `Snapshot`, an unrecognised key is
/// refused rather than carried: `Snapshot.extra` exists so another service can
/// add a knob without a proto release, and livery has no second author, so a
/// misspelling here can only be a mistake, and one whose symptom is a screen
/// that did not change.
pub fn apply_fields(
    current: &mut Livery,
    values: &Livery,
    fields: &[String],
) -> Result<(), Invalid> {
    for field in fields {
        match field.as_str() {
            "display_name" => current.display_name = values.display_name.clone(),
            "tagline" => current.tagline = values.tagline.clone(),
            "motd" => current.motd = values.motd.clone(),
            "tags" => current.tags = values.tags.clone(),
            "rules_url" => current.rules_url = values.rules_url.clone(),
            "banner_key" => current.banner_key = values.banner_key.clone(),
            "icon_key" => current.icon_key = values.icon_key.clone(),
            "banner_focus_x" => current.banner_focus_x = values.banner_focus_x,
            "banner_focus_y" => current.banner_focus_y = values.banner_focus_y,
            "dark" => current.dark = values.dark.clone(),
            "light" => current.light = values.light.clone(),
            other => return Err(Invalid::at(other, Reason::Unknown)),
        }
    }
    Ok(())
}

/// Whether `livery` may be stored, and the first reason it may not.
///
/// # Errors
///
/// The first violated rule, in field order, so a caller reporting one gets a
/// stable answer rather than whichever the iteration happened to reach.
pub fn validate(livery: &Livery) -> Result<(), Invalid> {
    cap("display_name", &livery.display_name, MAX_DISPLAY_NAME)?;
    cap("tagline", &livery.tagline, MAX_TAGLINE)?;
    cap("motd", &livery.motd, MAX_MOTD)?;

    if livery.tags.len() > MAX_TAGS {
        return Err(Invalid::at("tags", Reason::TooMany(MAX_TAGS)));
    }
    for tag in &livery.tags {
        cap("tags[].label", &tag.label, MAX_TAG_LABEL)?;
        https("tags[].href", &tag.href)?;
    }
    https("rules_url", &livery.rules_url)?;

    focus("banner_focus_x", livery.banner_focus_x)?;
    focus("banner_focus_y", livery.banner_focus_y)?;

    palette("dark", livery.dark.as_ref())?;
    palette("light", livery.light.as_ref())?;
    Ok(())
}

fn cap(field: &str, value: &str, limit: usize) -> Result<(), Invalid> {
    // Counted in characters, not bytes: the limit exists so a line fits on a
    // screen, and a cap that let an operator write a third as much because
    // their language is not Latin would be a different rule for each of them.
    if value.chars().count() > limit {
        return Err(Invalid::at(field, Reason::TooLong(limit)));
    }
    Ok(())
}

/// Empty, or an `https://` URL. Never `http`, `javascript:`, `data:` or `file:`.
fn https(field: &str, value: &str) -> Result<(), Invalid> {
    if value.is_empty() || value.starts_with("https://") {
        return Ok(());
    }
    Err(Invalid::at(field, Reason::NotHttps))
}

fn focus(field: &str, value: u32) -> Result<(), Invalid> {
    if value > 100 {
        return Err(Invalid::at(field, Reason::OffImage));
    }
    Ok(())
}

fn palette(mode: &str, palette: Option<&Palette>) -> Result<(), Invalid> {
    let Some(palette) = palette else {
        return Ok(());
    };
    for (name, value) in [
        ("accent", &palette.accent),
        ("surface", &palette.surface),
        ("aura_from", &palette.aura_from),
        ("aura_to", &palette.aura_to),
    ] {
        if value.is_empty() {
            continue;
        }
        if parse_hex(value).is_none() {
            return Err(Invalid::at(
                &format!("{mode}.{name}"),
                Reason::NotAColour(value.clone()),
            ));
        }
    }
    Ok(())
}

/// `#rrggbb` to its three channels, or `None`.
///
/// Deliberately strict, and deliberately not a sanitiser: a value that is not
/// exactly this shape is dropped rather than repaired, because the whole safety
/// property is that a colour never reaches a stylesheet as text. There is no
/// input here that can carry a second declaration, because there is no input
/// here that survives as a string.
#[must_use]
pub fn parse_hex(value: &str) -> Option<[u8; 3]> {
    let digits = value.strip_prefix('#')?;
    if digits.len() != 6 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = digits.as_bytes();
    // Indexed as bytes rather than sliced as a string: every byte here is an
    // ASCII hex digit, checked above, but a string slice would still be a panic
    // waiting for the day that check is loosened.
    let channel = |at: usize| {
        let pair = [bytes[at], bytes[at + 1]];
        let text = std::str::from_utf8(&pair).ok()?;
        u8::from_str_radix(text, 16).ok()
    };
    Some([channel(0)?, channel(2)?, channel(4)?])
}

/// The form the digest is taken over: sorted keys, empty fields omitted.
///
/// **Not the encoded protobuf, and this is the whole point of the function.**
/// Serialisation is not canonical, so adding a field to `Livery` in a later
/// release would re-encode identical content to different bytes, every client
/// would see a changed digest and refetch artwork that had not changed. It
/// would still work, which is why it would go unnoticed.
///
/// This form is the operator-facing document instead: it does not move when the
/// proto gains a field, and an operator can reproduce it from a `curl` when a
/// cache misbehaves. `version` and `digest` are excluded — one is a counter
/// over this value and the other is derived from it.
///
/// The artwork needs no hashing: `banner_key` and `icon_key` are files-plane
/// keys, which are content hashes already, so naming them here carries the
/// images' identity in for free.
#[must_use]
pub fn canonical(livery: &Livery) -> String {
    let mut fields: BTreeMap<&str, String> = BTreeMap::new();

    let mut text = |key: &'static str, value: &str| {
        if !value.is_empty() {
            let _ = fields.insert(key, quote(value));
        }
    };
    text("display_name", &livery.display_name);
    text("tagline", &livery.tagline);
    text("motd", &livery.motd);
    text("rules_url", &livery.rules_url);
    text("banner_key", &livery.banner_key);
    text("icon_key", &livery.icon_key);

    if livery.banner_focus_x != 0 {
        let _ = fields.insert("banner_focus_x", livery.banner_focus_x.to_string());
    }
    if livery.banner_focus_y != 0 {
        let _ = fields.insert("banner_focus_y", livery.banner_focus_y.to_string());
    }
    if !livery.tags.is_empty() {
        let rendered: Vec<String> = livery.tags.iter().map(canonical_tag).collect();
        let _ = fields.insert("tags", format!("[{}]", rendered.join(",")));
    }
    if let Some(dark) = &livery.dark
        && let Some(rendered) = canonical_palette(dark)
    {
        let _ = fields.insert("dark", rendered);
    }
    if let Some(light) = &livery.light
        && let Some(rendered) = canonical_palette(light)
    {
        let _ = fields.insert("light", rendered);
    }

    let body: Vec<String> = fields
        .iter()
        .map(|(key, value)| format!("{}:{value}", quote(key)))
        .collect();
    format!("{{{}}}", body.join(","))
}

fn canonical_tag(tag: &Tag) -> String {
    let tone = Tone::try_from(tag.tone).unwrap_or(Tone::Neutral);
    let mut parts = vec![
        format!("\"label\":{}", quote(&tag.label)),
        format!("\"tone\":{}", quote(tone.as_str_name())),
    ];
    if !tag.href.is_empty() {
        parts.push(format!("\"href\":{}", quote(&tag.href)));
    }
    // Ordered as written rather than sorted: the keys are fixed here, so the
    // order is already deterministic and naming it once is clearer than
    // routing three constants through a map.
    format!("{{{}}}", parts.join(","))
}

/// A palette's non-empty entries, or `None` when it names nothing.
///
/// An all-empty palette is the same document as no palette, and the digest has
/// to agree, or clearing the last colour would leave a `{}` that reads as a
/// change on every client forever.
fn canonical_palette(palette: &Palette) -> Option<String> {
    let mut parts = Vec::new();
    for (name, value) in [
        ("accent", &palette.accent),
        ("aura_from", &palette.aura_from),
        ("aura_to", &palette.aura_to),
        ("surface", &palette.surface),
    ] {
        if !value.is_empty() {
            parts.push(format!("\"{name}\":{}", quote(value)));
        }
    }
    (!parts.is_empty()).then(|| format!("{{{}}}", parts.join(",")))
}

/// JSON string escaping, to RFC 8259.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The digest a client compares against its cache.
///
/// Empty for a livery that says nothing, which is how "this server has no
/// livery" is told apart from "this server's livery hashes to zero" — the
/// client clears its cache entry on the former and would have to guess
/// otherwise.
#[must_use]
pub fn digest(livery: &Livery) -> Vec<u8> {
    let canonical = canonical(livery);
    if canonical == "{}" {
        return Vec::new();
    }
    Sha256::digest(canonical.as_bytes())[..DIGEST_BYTES].to_vec()
}

/// Everything an operator may read back, as JSON.
///
/// This is also the form [`canonical`] hashes, which is why it is the operator
/// document rather than a projection of it: a digest an operator cannot
/// reproduce from a `curl` is one they cannot debug.
#[must_use]
pub fn to_json(livery: &Livery) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    let _ = map.insert("version".to_owned(), livery.version.into());
    let _ = map.insert("digest".to_owned(), hex(&livery.digest).into());

    let mut text = |key: &str, value: &str| {
        if !value.is_empty() {
            let _ = map.insert(key.to_owned(), value.into());
        }
    };
    text("display_name", &livery.display_name);
    text("tagline", &livery.tagline);
    text("motd", &livery.motd);
    text("rules_url", &livery.rules_url);
    text("banner_key", &livery.banner_key);
    text("icon_key", &livery.icon_key);

    if livery.banner_focus_x != 0 {
        let _ = map.insert("banner_focus_x".to_owned(), livery.banner_focus_x.into());
    }
    if livery.banner_focus_y != 0 {
        let _ = map.insert("banner_focus_y".to_owned(), livery.banner_focus_y.into());
    }
    if !livery.tags.is_empty() {
        let tags: Vec<serde_json::Value> = livery
            .tags
            .iter()
            .map(|tag| {
                let tone = Tone::try_from(tag.tone).unwrap_or(Tone::Neutral);
                let mut entry = serde_json::Map::new();
                let _ = entry.insert("label".to_owned(), tag.label.clone().into());
                let _ = entry.insert("tone".to_owned(), tone.as_str_name().into());
                if !tag.href.is_empty() {
                    let _ = entry.insert("href".to_owned(), tag.href.clone().into());
                }
                serde_json::Value::Object(entry)
            })
            .collect();
        let _ = map.insert("tags".to_owned(), tags.into());
    }
    for (key, palette) in [("dark", &livery.dark), ("light", &livery.light)] {
        if let Some(palette) = palette
            && let Some(rendered) = palette_json(palette)
        {
            let _ = map.insert(key.to_owned(), rendered);
        }
    }
    serde_json::Value::Object(map)
}

fn palette_json(palette: &Palette) -> Option<serde_json::Value> {
    let mut map = serde_json::Map::new();
    for (name, value) in [
        ("accent", &palette.accent),
        ("aura_from", &palette.aura_from),
        ("aura_to", &palette.aura_to),
        ("surface", &palette.surface),
    ] {
        if !value.is_empty() {
            let _ = map.insert(name.to_owned(), value.clone().into());
        }
    }
    (!map.is_empty()).then_some(serde_json::Value::Object(map))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Read an operator's JSON into a document, and say which fields it named.
///
/// # Errors
///
/// The first key that is not a livery field, or whose value is the wrong shape.
/// Both are refused rather than skipped: `Snapshot`'s `extra` map exists so a
/// service can add a knob without a proto release, and livery has no second
/// author, so an unrecognised key here can only be a typo — one whose symptom
/// would otherwise be a request that succeeds and changes nothing.
pub fn from_json(values: &serde_json::Value) -> Result<(Livery, Vec<String>), Invalid> {
    let mut livery = Livery::default();
    let mut fields = Vec::new();
    let Some(object) = values.as_object() else {
        return Ok((livery, fields));
    };

    for (key, value) in object {
        match key.as_str() {
            "display_name" => livery.display_name = string(key, value)?,
            "tagline" => livery.tagline = string(key, value)?,
            "motd" => livery.motd = string(key, value)?,
            "rules_url" => livery.rules_url = string(key, value)?,
            "banner_key" => livery.banner_key = string(key, value)?,
            "icon_key" => livery.icon_key = string(key, value)?,
            "banner_focus_x" => livery.banner_focus_x = count(key, value)?,
            "banner_focus_y" => livery.banner_focus_y = count(key, value)?,
            "tags" => livery.tags = tags_from(value)?,
            "dark" => livery.dark = Some(palette_from("dark", value)?),
            "light" => livery.light = Some(palette_from("light", value)?),
            // `version` and `digest` are the server's. Named rather than
            // ignored, so an operator who round-trips a GET into a POST is told
            // instead of silently having them dropped.
            "version" | "digest" => {
                return Err(Invalid::at(key, Reason::Unknown));
            }
            other => return Err(Invalid::at(other, Reason::Unknown)),
        }
        fields.push(key.clone());
    }
    Ok((livery, fields))
}

fn string(field: &str, value: &serde_json::Value) -> Result<String, Invalid> {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| Invalid::at(field, Reason::WrongType("a string")))
}

fn count(field: &str, value: &serde_json::Value) -> Result<u32, Invalid> {
    value
        .as_u64()
        .and_then(|number| u32::try_from(number).ok())
        .ok_or_else(|| Invalid::at(field, Reason::WrongType("a whole number")))
}

fn tags_from(value: &serde_json::Value) -> Result<Vec<Tag>, Invalid> {
    let entries = value
        .as_array()
        .ok_or_else(|| Invalid::at("tags", Reason::WrongType("an array")))?;
    entries
        .iter()
        .map(|entry| {
            let object = entry
                .as_object()
                .ok_or_else(|| Invalid::at("tags[]", Reason::WrongType("an object")))?;
            for key in object.keys() {
                if !matches!(key.as_str(), "label" | "tone" | "href") {
                    return Err(Invalid::at(&format!("tags[].{key}"), Reason::Unknown));
                }
            }
            let label = object
                .get("label")
                .map(|value| string("tags[].label", value))
                .transpose()?
                .unwrap_or_default();
            let href = object
                .get("href")
                .map(|value| string("tags[].href", value))
                .transpose()?
                .unwrap_or_default();
            let tone = match object.get("tone") {
                None => Tone::Neutral,
                Some(value) => {
                    let name = string("tags[].tone", value)?;
                    Tone::from_str_name(&name)
                        .ok_or_else(|| Invalid::at("tags[].tone", Reason::NotATone(name)))?
                }
            };
            Ok(Tag {
                label,
                tone: tone as i32,
                href,
            })
        })
        .collect()
}

fn palette_from(mode: &str, value: &serde_json::Value) -> Result<Palette, Invalid> {
    let object = value
        .as_object()
        .ok_or_else(|| Invalid::at(mode, Reason::WrongType("an object")))?;
    let mut palette = Palette::default();
    for (key, entry) in object {
        let field = format!("{mode}.{key}");
        let colour = string(&field, entry)?;
        match key.as_str() {
            "accent" => palette.accent = colour,
            "surface" => palette.surface = colour,
            "aura_from" => palette.aura_from = colour,
            "aura_to" => palette.aura_to = colour,
            _ => return Err(Invalid::at(&field, Reason::Unknown)),
        }
    }
    Ok(palette)
}

// -- The contrast floor ----------------------------------------------------

/// Contrast a colour bearing text must reach against what is behind it.
pub const CONTRAST_TEXT: f64 = 4.5;
/// Contrast a colour that only has to be *seen* must reach: WCAG's rule for
/// interface components and graphical objects.
pub const CONTRAST_ACCENT: f64 = 3.0;

/// Move `colour` until it reaches `target` against `behind`, keeping its hue.
///
/// An operator can choose a mood; they cannot make their own Connect button
/// invisible, and they cannot do it on only some viewers' themes. Hue and
/// saturation are preserved and only lightness moves, so the result is
/// recognisably the colour that was asked for rather than a substitute.
///
/// Returns the colour and whether it had to move, because an operator who
/// cannot see that their `#0b0b0b` came back as something else finds out from a
/// support thread instead.
#[must_use]
pub fn clamp(colour: [u8; 3], behind: [u8; 3], target: f64) -> ([u8; 3], bool) {
    if contrast(colour, behind) >= target {
        return (colour, false);
    }
    let (hue, saturation, lightness) = to_hsl(colour);

    // Both directions, nearest first, rather than a rule for which way to go.
    // Every such rule is wrong somewhere: "away from the ground's luminance"
    // sends a near-white accent on a near-white surface further towards white,
    // and a midpoint test has to pick a midpoint. Walking outwards takes the
    // smallest move that works, whichever side it is on, so the result stays as
    // close to the colour the operator chose as the floor allows.
    let mut best = colour;
    let mut best_contrast = contrast(colour, behind);
    for step in 1..=100 {
        let offset = f64::from(step) / 100.0;
        for candidate in [lightness + offset, lightness - offset] {
            if !(0.0..=1.0).contains(&candidate) {
                continue;
            }
            let moved = from_hsl(hue, saturation, candidate);
            let reached = contrast(moved, behind);
            if reached >= target {
                return (moved, true);
            }
            if reached > best_contrast {
                best = moved;
                best_contrast = reached;
            }
        }
    }
    // Nothing on this hue reaches the floor, which a fully desaturated surface
    // can do. The most legible answer available still beats handing back the
    // one that cannot be seen at all.
    (best, true)
}

/// WCAG 2.1 contrast ratio, 1.0 to 21.0.
#[must_use]
pub fn contrast(one: [u8; 3], other: [u8; 3]) -> f64 {
    let (a, b) = (luminance(one), luminance(other));
    let (lighter, darker) = if a > b { (a, b) } else { (b, a) };
    (lighter + 0.05) / (darker + 0.05)
}

/// Relative luminance, with the sRGB transfer function undone first.
fn luminance(colour: [u8; 3]) -> f64 {
    let channel = |value: u8| {
        let value = f64::from(value) / 255.0;
        if value <= 0.040_45 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(colour[0]) + 0.7152 * channel(colour[1]) + 0.0722 * channel(colour[2])
}

fn to_hsl(colour: [u8; 3]) -> (f64, f64, f64) {
    let [red, green, blue] = colour.map(|value| f64::from(value) / 255.0);
    let max = red.max(green).max(blue);
    let min = red.min(green).min(blue);
    let lightness = f64::midpoint(max, min);
    let delta = max - min;
    if delta.abs() < f64::EPSILON {
        return (0.0, 0.0, lightness);
    }
    let saturation = delta / (1.0 - (2.0f64.mul_add(lightness, -1.0)).abs());
    let hue = if (max - red).abs() < f64::EPSILON {
        ((green - blue) / delta).rem_euclid(6.0)
    } else if (max - green).abs() < f64::EPSILON {
        (blue - red) / delta + 2.0
    } else {
        (red - green) / delta + 4.0
    };
    (hue * 60.0, saturation, lightness)
}

fn from_hsl(hue: f64, saturation: f64, lightness: f64) -> [u8; 3] {
    let chroma = (1.0 - (2.0f64.mul_add(lightness, -1.0)).abs()) * saturation;
    let sector = hue.rem_euclid(360.0) / 60.0;
    let second = chroma * (1.0 - (sector.rem_euclid(2.0) - 1.0).abs());
    let (red, green, blue) = match sector as u8 {
        0 => (chroma, second, 0.0),
        1 => (second, chroma, 0.0),
        2 => (0.0, chroma, second),
        3 => (0.0, second, chroma),
        4 => (second, 0.0, chroma),
        _ => (chroma, 0.0, second),
    };
    let base = chroma.mul_add(-0.5, lightness);
    [red, green, blue].map(|value| ((value + base) * 255.0).round().clamp(0.0, 255.0) as u8)
}

/// `[r, g, b]` back to `#rrggbb`.
#[must_use]
pub fn to_hex(colour: [u8; 3]) -> String {
    format!("#{:02x}{:02x}{:02x}", colour[0], colour[1], colour[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tagged(label: &str) -> Tag {
        Tag {
            label: label.to_owned(),
            tone: Tone::Ok as i32,
            href: String::new(),
        }
    }

    #[test]
    fn an_empty_livery_has_no_digest() {
        assert!(digest(&Livery::default()).is_empty());
        assert_eq!(canonical(&Livery::default()), "{}");
    }

    #[test]
    fn the_digest_is_eight_bytes() {
        let livery = Livery {
            tagline: "hello".to_owned(),
            ..Default::default()
        };
        assert_eq!(digest(&livery).len(), DIGEST_BYTES);
    }

    #[test]
    fn the_version_and_digest_are_not_hashed() {
        // Otherwise every client refetches on a write that changed nothing they
        // can see, and the counter would hash into the value it counts.
        let base = Livery {
            tagline: "hello".to_owned(),
            ..Default::default()
        };
        let bumped = Livery {
            version: 41,
            digest: vec![1, 2, 3],
            ..base.clone()
        };
        assert_eq!(digest(&base), digest(&bumped));
    }

    #[test]
    fn an_all_empty_palette_hashes_as_no_palette() {
        let named = Livery {
            tagline: "hello".to_owned(),
            dark: Some(Palette::default()),
            ..Default::default()
        };
        let absent = Livery {
            tagline: "hello".to_owned(),
            ..Default::default()
        };
        assert_eq!(digest(&named), digest(&absent));
    }

    #[test]
    fn changing_the_banner_key_changes_the_digest() {
        // The keys are content hashes, so this is how a new image reaches the
        // digest without the bytes ever being hashed here.
        let before = Livery {
            banner_key: "blob-a".to_owned(),
            ..Default::default()
        };
        let after = Livery {
            banner_key: "blob-b".to_owned(),
            ..Default::default()
        };
        assert_ne!(digest(&before), digest(&after));
    }

    #[test]
    fn canonical_sorts_its_keys() {
        let livery = Livery {
            tagline: "b".to_owned(),
            display_name: "a".to_owned(),
            motd: "c".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            canonical(&livery),
            r#"{"display_name":"a","motd":"c","tagline":"b"}"#
        );
    }

    #[test]
    fn canonical_escapes_text() {
        let livery = Livery {
            motd: "say \"hi\"\nthen leave".to_owned(),
            ..Default::default()
        };
        assert_eq!(canonical(&livery), r#"{"motd":"say \"hi\"\nthen leave"}"#);
    }

    #[test]
    fn apply_fields_writes_only_what_is_named() {
        let mut current = Livery {
            tagline: "kept".to_owned(),
            motd: "old".to_owned(),
            ..Default::default()
        };
        let values = Livery {
            tagline: "ignored".to_owned(),
            motd: "new".to_owned(),
            ..Default::default()
        };
        apply_fields(&mut current, &values, &["motd".to_owned()]).unwrap();
        assert_eq!(current.tagline, "kept");
        assert_eq!(current.motd, "new");
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_carried() {
        let mut current = Livery::default();
        let error = apply_fields(&mut current, &Livery::default(), &["taglin".to_owned()]);
        assert_eq!(error, Err(Invalid::at("taglin", Reason::Unknown)));
    }

    #[test]
    fn colours_must_be_six_hex_digits() {
        assert_eq!(parse_hex("#8a90ff"), Some([0x8a, 0x90, 0xff]));
        assert_eq!(parse_hex("#8A90FF"), Some([0x8a, 0x90, 0xff]));
        for bad in [
            "8a90ff",
            "#8a90f",
            "#8a90fff",
            "#zzzzzz",
            "red",
            "#fff",
            "red;background:url(x)",
        ] {
            assert_eq!(parse_hex(bad), None, "{bad} should not parse");
        }
    }

    #[test]
    fn a_palette_carrying_a_non_colour_is_refused() {
        let livery = Livery {
            dark: Some(Palette {
                accent: "red;background:url(http://x)".to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(matches!(
            validate(&livery),
            Err(Invalid {
                reason: Reason::NotAColour(_),
                ..
            })
        ));
    }

    #[test]
    fn links_must_be_https() {
        for bad in [
            "http://x",
            "javascript:alert(1)",
            "data:text/html,x",
            "file:///etc/passwd",
        ] {
            let livery = Livery {
                rules_url: bad.to_owned(),
                ..Default::default()
            };
            assert!(
                matches!(
                    validate(&livery),
                    Err(Invalid {
                        reason: Reason::NotHttps,
                        ..
                    })
                ),
                "{bad} should be refused"
            );
        }
        let ok = Livery {
            rules_url: "https://example.org/rules".to_owned(),
            ..Default::default()
        };
        assert!(validate(&ok).is_ok());
    }

    #[test]
    fn text_is_capped_in_characters() {
        let livery = Livery {
            tagline: "é".repeat(MAX_TAGLINE),
            ..Default::default()
        };
        assert!(
            validate(&livery).is_ok(),
            "a cap in bytes would refuse this"
        );

        let over = Livery {
            tagline: "a".repeat(MAX_TAGLINE + 1),
            ..Default::default()
        };
        assert!(matches!(
            validate(&over),
            Err(Invalid {
                reason: Reason::TooLong(_),
                ..
            })
        ));
    }

    #[test]
    fn there_is_a_ceiling_on_tags() {
        let livery = Livery {
            tags: (0..=MAX_TAGS).map(|n| tagged(&n.to_string())).collect(),
            ..Default::default()
        };
        let refused = validate(&livery).expect_err("five tags is too many");
        assert!(matches!(refused.reason, Reason::TooMany(_)));
        // Counted in entries, not characters: the message an operator reads has
        // to name the unit the number is in.
        assert_eq!(refused.to_string(), "tags may hold at most 4");
    }

    #[test]
    fn a_focus_point_stays_on_the_image() {
        let livery = Livery {
            banner_focus_x: 101,
            ..Default::default()
        };
        assert!(matches!(
            validate(&livery),
            Err(Invalid {
                reason: Reason::OffImage,
                ..
            })
        ));
    }

    /// `to_json` minus the two fields the server owns, which is what an
    /// operator would POST back after a GET.
    fn without_server_fields(livery: &Livery) -> serde_json::Value {
        let mut value = to_json(livery);
        let object = value.as_object_mut().unwrap();
        let _ = object.remove("version");
        let _ = object.remove("digest");
        value
    }

    #[test]
    fn json_round_trips_through_the_operator_form() {
        let livery = Livery {
            display_name: "magical.rocks".to_owned(),
            tagline: "cozy corner".to_owned(),
            banner_focus_y: 30,
            tags: vec![Tag {
                label: "Server rules".to_owned(),
                tone: Tone::Accent as i32,
                href: "https://magical.rocks/rules".to_owned(),
            }],
            dark: Some(Palette {
                accent: "#8a90ff".to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let (parsed, fields) = from_json(&without_server_fields(&livery)).unwrap();
        assert_eq!(parsed.display_name, livery.display_name);
        assert_eq!(parsed.tags, livery.tags);
        assert_eq!(parsed.dark, livery.dark);
        assert_eq!(parsed.banner_focus_y, 30);
        assert!(fields.contains(&"tagline".to_owned()));
    }

    #[test]
    fn the_servers_own_fields_are_refused_as_input() {
        // A GET round-tripped into a POST otherwise drops them in silence, and
        // an operator has no way to tell that from them being accepted.
        for key in ["version", "digest"] {
            let body = serde_json::json!({ key: 1 });
            assert_eq!(
                from_json(&body).unwrap_err(),
                Invalid::at(key, Reason::Unknown)
            );
        }
    }

    #[test]
    fn a_value_of_the_wrong_shape_is_refused() {
        let body = serde_json::json!({ "tagline": 7 });
        assert!(matches!(
            from_json(&body),
            Err(Invalid {
                reason: Reason::WrongType(_),
                ..
            })
        ));
    }

    #[test]
    fn an_unknown_tone_is_refused() {
        let body = serde_json::json!({ "tags": [{ "label": "x", "tone": "PUCE" }] });
        assert!(matches!(
            from_json(&body),
            Err(Invalid {
                reason: Reason::NotATone(_),
                ..
            })
        ));
    }

    #[test]
    fn the_canonical_form_is_what_to_json_hashes() {
        // The digest an operator can reproduce from a curl is the whole reason
        // this form and not the encoded protobuf is what gets hashed.
        let livery = Livery {
            tagline: "hello".to_owned(),
            motd: "there".to_owned(),
            ..Default::default()
        };
        let mut from_operator_view = to_json(&livery);
        let object = from_operator_view.as_object_mut().unwrap();
        let _ = object.remove("version");
        let _ = object.remove("digest");
        assert_eq!(
            serde_json::to_string(&object).unwrap(),
            canonical(&livery),
            "canonical() and to_json() have drifted"
        );
    }

    #[test]
    fn a_colour_that_already_reads_is_left_alone() {
        let surface = parse_hex("#141d33").unwrap();
        let accent = parse_hex("#41b4f9").unwrap();
        let (result, moved) = clamp(accent, surface, CONTRAST_ACCENT);
        assert_eq!(result, accent);
        assert!(!moved);
    }

    #[test]
    fn a_server_cannot_hide_its_own_button() {
        // Near-black accent on the dark surface: 1.1:1, which is a button you
        // cannot see. It has to come back legible and still blue.
        let surface = parse_hex("#141d33").unwrap();
        let accent = parse_hex("#0b0f1a").unwrap();
        let (result, moved) = clamp(accent, surface, CONTRAST_ACCENT);
        assert!(moved);
        assert!(
            contrast(result, surface) >= CONTRAST_ACCENT,
            "{} is still {:.2}:1",
            to_hex(result),
            contrast(result, surface)
        );
    }

    #[test]
    fn the_clamp_holds_on_a_light_surface_too() {
        // The same accent must not be legible on one theme and invisible on the
        // other, which is what a single-mode clamp would allow.
        let surface = parse_hex("#fdfbf6").unwrap();
        for accent in ["#fffef8", "#f5f3ee", "#ffffff"] {
            let (result, _) = clamp(parse_hex(accent).unwrap(), surface, CONTRAST_ACCENT);
            assert!(
                contrast(result, surface) >= CONTRAST_ACCENT,
                "{accent} clamped to {} is still {:.2}:1",
                to_hex(result),
                contrast(result, surface)
            );
        }
    }

    #[test]
    fn the_clamp_keeps_the_hue_it_was_given() {
        let surface = parse_hex("#141d33").unwrap();
        let (result, _) = clamp(parse_hex("#0d0033").unwrap(), surface, CONTRAST_ACCENT);
        let (hue, _, _) = to_hsl(result);
        // Still violet, not a substitute colour the operator never chose.
        assert!((240.0..=290.0).contains(&hue), "hue drifted to {hue}");
    }

    #[test]
    fn contrast_is_symmetric_and_bounded() {
        let black = [0, 0, 0];
        let white = [255, 255, 255];
        assert!((contrast(black, white) - 21.0).abs() < 0.01);
        assert!((contrast(white, black) - 21.0).abs() < 0.01);
        assert!((contrast(black, black) - 1.0).abs() < 0.01);
    }

    #[test]
    fn hsl_survives_the_round_trip() {
        for colour in [[0x41, 0xb4, 0xf9], [0x8a, 0x90, 0xff], [0x14, 0x1d, 0x33]] {
            let (hue, saturation, lightness) = to_hsl(colour);
            let back = from_hsl(hue, saturation, lightness);
            for channel in 0..3 {
                assert!(
                    back[channel].abs_diff(colour[channel]) <= 1,
                    "{colour:?} came back as {back:?}"
                );
            }
        }
    }

    #[test]
    fn every_settable_field_is_in_fields() {
        // FIELDS is what the operator API advertises and what `apply_fields`
        // accepts; the two drifting apart is a setting nobody can set.
        let mut current = Livery::default();
        for field in FIELDS {
            apply_fields(&mut current, &Livery::default(), &[(*field).to_owned()])
                .unwrap_or_else(|_| panic!("{field} is advertised but not settable"));
        }
    }
}
