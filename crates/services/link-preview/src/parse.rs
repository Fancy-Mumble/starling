//! Pulling a title, a description and a site name out of a page.
//!
//! # Why this is not an HTML parser
//!
//! It reads `<meta>` and `<title>` and stops at `</head>`. A conforming parser
//! would build a document we would then throw away, on input chosen by a
//! stranger, every parser bug in it becomes reachable from a chat message.
//! The job is four strings out of the head of a document, and the smaller thing
//! that does only that has less to get wrong.
//!
//! It follows that this is *lenient*: unknown tags, broken nesting and
//! attributes it does not recognise are skipped rather than refused. There is
//! no such thing as a malformed page here, only a page that yields nothing.
//!
//! # What it prefers
//!
//! `OpenGraph` first, because it is what a page author wrote *for* this, then
//! Twitter's equivalents, then the ordinary `<title>` and
//! `<meta name="description">`. A page that offers none of them gets a preview
//! with its host as the title, which is still better than a bare URL.

/// What a page says about itself.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Card {
    /// What the page calls itself.
    pub title: String,
    /// Its own one-line summary.
    pub description: String,
    /// The publication, where it names one.
    pub site: String,
    /// The `og:image` URL, as the page gave it.
    ///
    /// **Not** what goes on the wire: sending it would have every viewer load
    /// the origin's picture, which is precisely the network probe that having
    /// the server fetch previews exists to prevent. It is where the *server's*
    /// image fetch starts, and only the bytes it brings back travel.
    ///
    /// Relative as often as not (`/static/card.png`), so a caller resolves it
    /// against the page's own URL before it means anything.
    pub image: String,
    /// What the page says the image measures, or `0` where it did not say.
    ///
    /// A hint, and used as one: the bytes that travel are downscaled and carry
    /// their own size. This is what lets a fetch decline a picture the page
    /// itself describes as enormous without spending a request to find out.
    pub image_width: u32,
    /// The height the page claims, paired with [`Card::image_width`].
    pub image_height: u32,
    /// `og:type`, lowercased: "article", "video.other", "product".
    ///
    /// Kept as the page wrote it rather than resolved to a kind here, because
    /// what a page *says* it is and what the crawler decides it is are two
    /// different judgements and only one of them belongs in a parser. See
    /// [`crate::classify`].
    pub page_type: String,
    /// `twitter:card`: "summary", "`summary_large_image`", "player".
    pub twitter_card: String,
    /// Who made it, where the page has a byline.
    pub author: String,
    /// Playing time in seconds, from whichever of the half-dozen ways a page
    /// states one it used. Zero where it stated none.
    pub duration: u32,
    /// What the page says the thing costs.
    pub price: Price,
    /// The `<meta name="generator">` line, lowercased.
    ///
    /// Read for one reason: forum software announces itself there, and a
    /// thread on a Discourse instance nobody has heard of is still a thread.
    pub generator: String,
    /// The labelled facts the page published about itself, in page order.
    pub facts: Vec<Fact>,
    /// When the page says it was published, as it wrote it.
    ///
    /// Not parsed into a time here: half the vocabularies carry ISO-8601 and
    /// the other half carry whatever an editor typed, a date the server
    /// cannot read is still worth showing, and which of the two it is does
    /// not change what this crate does with it.
    pub published: String,
    /// What the page says its content is: "safe", "mature", "explicit".
    ///
    /// Lowercased and otherwise as written. The vocabularies disagree and no
    /// scale maps onto another, so this is a label to print rather than a
    /// number to compare.
    pub rating: String,
    /// The site's own icon, as the page's `<link rel="icon">` gave it.
    ///
    /// Relative as often as not, like [`Card::image`], and fetched by the
    /// server for the same reason: a client that went and got it would tell
    /// the origin who is reading the conversation.
    pub icon: String,
}

/// What a page says its subject costs.
///
/// All strings, and empty means "the page did not say". A price is a decimal
/// amount in a currency, neither of which is a number this ever does
/// arithmetic on: it is read, carried, and printed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Price {
    /// The amount, normalised to a `.` decimal point and no thousands marks.
    pub amount: String,
    /// ISO 4217, where the page named a currency.
    pub currency: String,
    /// What it cost before, for a page advertising a reduction.
    pub was: String,
    /// "instock", "oos", "preorder" - as the page wrote it, lowercased.
    pub availability: String,
}

impl Price {
    /// Whether the page named a price at all.
    #[must_use]
    pub fn is_named(&self) -> bool {
        !self.amount.is_empty()
    }
}

/// One labelled fact, as a `twitter:labelN`/`twitter:dataN` pair gave it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Fact {
    /// The crawler's reading of [`Fact::label`], lowercased and canonical, or
    /// empty where the label was not one it knows. See [`fact_key`].
    pub key: String,
    /// The label the page wrote.
    pub label: String,
    /// The value the page wrote.
    pub value: String,
}

/// Read `html` for what it says about itself.
#[must_use]
pub fn card(html: &str) -> Card {
    let head = head_of(html);
    let mut card = Card::default();

    // First value wins for each field, so a page that repeats a tag does not
    // have its own preferred answer overwritten by an afterthought further
    // down.
    let take = |slot: &mut String, value: String| {
        if slot.is_empty() && !value.is_empty() {
            *slot = value;
        }
    };
    // Same rule for the dimensions, and unparseable means absent: a page that
    // writes `og:image:width` as "large" has said nothing about the size, which
    // is exactly the state a `0` already means.
    let take_number = |slot: &mut u32, value: &str| {
        if *slot == 0 {
            *slot = value.trim().parse().unwrap_or(0);
        }
    };

    // The labelled facts arrive as two halves - `twitter:label2` here,
    // `twitter:data2` three tags further down - so they are collected by index
    // and paired once the head has been read. Four, because that is as many as
    // the vocabulary defines and a page that invents a fifth is inventing.
    let mut labels: [Option<String>; 4] = Default::default();
    let mut values: [Option<String>; 4] = Default::default();

    for tag in tags(head, "meta") {
        let key = attribute(tag, "property")
            .or_else(|| attribute(tag, "name"))
            // `itemprop` last, and read at all because it is where a video
            // page states its playing time: YouTube writes no `og:video:
            // duration` and one `<meta itemprop="duration" content="PT1H14M">`.
            .or_else(|| attribute(tag, "itemprop"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        let Some(content) = attribute(tag, "content") else {
            continue;
        };
        let content = decode(&content);
        match key.as_str() {
            "og:title" | "twitter:title" => take(&mut card.title, content),
            "og:description" | "twitter:description" | "description" => {
                take(&mut card.description, content);
            }
            // `twitter:site` is deliberately not here: by Twitter's own
            // definition it is an @handle for an account, not the name of a
            // publication, so reading it as one labelled cards "@rustlang" and
            // "@github". A page that names no site gets its host, which the
            // caller fills in because it is the only one that knows the URL.
            "og:site_name" => take(&mut card.site, content),
            // `og:image:secure_url` before `og:image`, and both before
            // Twitter's: a page that offers https for the same picture is
            // offering the one a fetch can actually use.
            "og:image:secure_url"
            | "og:image"
            | "og:image:url"
            | "twitter:image"
            | "twitter:image:src" => take(&mut card.image, content),
            "og:image:width" | "twitter:image:width" => {
                take_number(&mut card.image_width, &content);
            }
            "og:image:height" | "twitter:image:height" => {
                take_number(&mut card.image_height, &content);
            }
            // What the page says it is. Lowercased here rather than at every
            // reader: `og:type` is a vocabulary, not prose, and pages write
            // "Article" as readily as "article".
            "og:type" => take(&mut card.page_type, content.to_ascii_lowercase()),
            "twitter:card" => take(&mut card.twitter_card, content.to_ascii_lowercase()),
            "generator" => take(&mut card.generator, content.to_ascii_lowercase()),
            // When it went out. Several spellings, because the vocabularies
            // for this never converged: `OpenGraph`'s article namespace,
            // Dublin Core, Google Scholar's citation set, and the plain
            // `date` a news CMS writes.
            "article:published_time"
            | "og:article:published_time"
            | "datepublished"
            | "date"
            | "dc.date"
            | "dcterms.date"
            | "citation_publication_date"
            | "pubdate" => take(&mut card.published, content),
            // What it is rated. `rating` is the old convention and still what
            // image boards and adult sites write; `og:restrictions:age` is
            // `OpenGraph`'s, and carries "18+" rather than a word.
            "rating" | "og:rating" | "content-rating" | "og:restrictions:age" => {
                take(&mut card.rating, content.to_ascii_lowercase());
            }
            // A byline, in the several places pages put one. `article:author`
            // is as often a profile URL as a name, and a URL printed where a
            // name goes reads as a bug, so [`byline`] drops those.
            "author" | "article:author" | "og:article:author" | "og:video:director"
            | "og:music:musician" | "book:author"
            // Dublin Core and the citation set, which is what an academic
            // publisher and a good half of the CMSs in the world write.
            | "dc.creator" | "dcterms.creator" | "citation_author" => {
                take(&mut card.author, byline(&content));
            }
            "og:video:duration" | "video:duration" | "og:music:duration" | "music:duration"
            | "duration"
                if card.duration == 0 =>
            {
                card.duration = seconds(&content);
            }
            "og:price:amount" | "product:price:amount" | "og:product:price:amount" => {
                take(&mut card.price.amount, decimal(&content));
            }
            "og:price:currency" | "product:price:currency" => {
                take(&mut card.price.currency, content.to_ascii_uppercase());
            }
            // The "was" price, which every vocabulary spells differently and
            // no two shops agree on.
            "og:price:standard_amount"
            | "product:original_price:amount"
            | "product:price:original"
            | "og:price:original_amount" => take(&mut card.price.was, decimal(&content)),
            "og:availability" | "product:availability" => {
                take(&mut card.price.availability, content.to_ascii_lowercase());
            }
            "twitter:label1" => labels[0] = labels[0].take().or(Some(content)),
            "twitter:label2" => labels[1] = labels[1].take().or(Some(content)),
            "twitter:label3" => labels[2] = labels[2].take().or(Some(content)),
            "twitter:label4" => labels[3] = labels[3].take().or(Some(content)),
            "twitter:data1" => values[0] = values[0].take().or(Some(content)),
            "twitter:data2" => values[1] = values[1].take().or(Some(content)),
            "twitter:data3" => values[2] = values[2].take().or(Some(content)),
            "twitter:data4" => values[3] = values[3].take().or(Some(content)),
            _ => {}
        }
    }

    labelled(&mut card, labels, values);
    structured(&mut card, head);
    card.icon = icon_of(head);

    if card.title.is_empty()
        && let Some(title) = between(head, "<title", "</title")
    {
        // `<title` and not `<title>`: the tag may carry attributes, and a page
        // that writes `<title lang="en">` would otherwise have no title at all.
        let text = title.split_once('>').map_or(title, |(_, rest)| rest);
        card.title = decode(text.trim());
    }
    card
}

/// Pair the `twitter:labelN`/`twitter:dataN` halves and read what they say.
///
/// Its own step because the two halves arrive tags apart and can only be
/// paired once the head has been read, and because three of the facts have a
/// typed home as well: a page states its price, its byline and its playing
/// time in whichever of the two places suits it, and which one it chose is not
/// a distinction that should reach a reader. The typed tags are read first and
/// keep precedence - a tag that exists for no other purpose beats a label
/// somebody typed.
fn labelled(card: &mut Card, labels: [Option<String>; 4], values: [Option<String>; 4]) {
    for (label, value) in labels.into_iter().zip(values) {
        // Both halves or neither: a label with nothing under it is a heading
        // for a fact the page did not state, and a value with no label is a
        // number nobody can read.
        let (Some(label), Some(value)) = (label, value) else {
            continue;
        };
        if label.is_empty() || value.is_empty() {
            continue;
        }
        card.facts.push(Fact {
            key: fact_key(&label).to_owned(),
            label,
            value,
        });
    }

    let stated = |key: &str| {
        card.facts
            .iter()
            .find(|fact| fact.key == key)
            .map(|fact| fact.value.clone())
    };
    if !card.price.is_named()
        && let Some(value) = stated("price")
    {
        card.price.amount = decimal(&value);
        // The currency travels inside the value there ("89,99 EUR"), so it is
        // read out of the same string rather than left blank.
        card.price.currency = currency_in(&value).to_owned();
    }
    if card.author.is_empty()
        && let Some(value) = stated("author")
    {
        card.author = byline(&value);
    }
    if card.duration == 0
        && let Some(value) = stated("duration")
    {
        card.duration = seconds(&value);
    }
}

/// Fill what the meta tags left empty from the page's `JSON-LD`.
///
/// Second, deliberately. `OpenGraph` is what a page author wrote *for* a card
/// like this one, so where the two disagree the tag written for sharing wins;
/// `schema.org` is where the facts a sharing vocabulary has no room for live -
/// who made it, when, how it was rated, how many people watched it - and on
/// most pages it is the only place they exist at all.
fn structured(card: &mut Card, head: &str) {
    let found = crate::structured::read(head);
    if found.is_empty() {
        return;
    }
    if card.author.is_empty() {
        card.author = byline(&found.author);
    }
    if card.published.is_empty() {
        card.published = found.published;
    }
    if card.rating.is_empty() {
        card.rating = found.rating;
    }
    if card.duration == 0 {
        card.duration = seconds(&found.duration);
    }
    // The counts join the page's own labelled facts rather than becoming
    // fields of their own: they are the same kind of thing a `twitter:label`
    // carries, and a client that can draw one can draw all of them.
    let mut add = |key: &str, label: &str, value: String| {
        if value.is_empty() || card.facts.iter().any(|fact| fact.key == key) {
            return;
        }
        card.facts.push(Fact {
            key: key.to_owned(),
            label: label.to_owned(),
            value,
        });
    };
    add("views", "Views", found.views);
    add("likes", "Likes", found.likes);
    add("comments", "Comments", found.comments);
    // The average and how many it is of, as one fact: "4.6/5 (128)" is what a
    // reader wants off a rating, and two facts would take two of the three
    // places a card has.
    let stars = match (found.stars.is_empty(), found.rating_count.is_empty()) {
        (true, _) => String::new(),
        (false, true) => found.stars,
        (false, false) => format!("{} ({})", found.stars, found.rating_count),
    };
    add("rating", "Rating", stars);
}

/// The site icon a page declares, or `""`.
///
/// `apple-touch-icon` first where there is one: it is a PNG of at least 120
/// pixels by convention, where `rel="icon"` is as often a 16-pixel `.ico`
/// drawn for a browser tab in 1999. Both are read; a page that declares
/// neither gets none, and the client draws a monogram instead.
///
/// SVG is skipped rather than preferred: the fetcher refuses it (a document
/// with scripts and external references in it is not a picture), so choosing
/// one would mean choosing the icon that cannot arrive.
fn icon_of(head: &str) -> String {
    let mut fallback = String::new();
    for tag in tags(head, "link") {
        let rel = attribute(tag, "rel")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let Some(href) = attribute(tag, "href").map(|href| decode(&href)) else {
            continue;
        };
        if href.is_empty() || href.to_ascii_lowercase().ends_with(".svg") {
            continue;
        }
        if rel.contains("apple-touch-icon") {
            return href;
        }
        if rel.split_whitespace().any(|word| word == "icon") && fallback.is_empty() {
            fallback = href;
        }
    }
    fallback
}

/// The document head, or the whole input if it has no head.
///
/// Bounded scanning: a page's metadata is at the top, and reading past
/// `</head>` is reading the entire body for tags that are not there.
fn head_of(html: &str) -> &str {
    let lower = html.to_ascii_lowercase();
    lower
        .find("</head")
        .map_or(html, |end| html.get(..end).unwrap_or(html))
}

/// Every `<name ...>` tag in `html`, as raw text.
fn tags<'a>(html: &'a str, name: &str) -> Vec<&'a str> {
    let lower = html.to_ascii_lowercase();
    let opener = format!("<{name}");
    let mut out = Vec::new();
    let mut at = 0;
    // Every slice is a `get`. The input is a page a stranger chose, so a byte
    // index that lands inside a multi-byte character is a panic reachable from
    // a chat message, and `at` walks the string, so it is exactly the index
    // most likely to land in the middle of one.
    while let Some(start) = lower.get(at..).and_then(|rest| rest.find(&opener)) {
        let start = at + start;
        // The character after the name has to be a delimiter, or `<metadata>`
        // would be read as a `<meta>` tag with strange attributes.
        let after = lower.as_bytes().get(start + opener.len()).copied();
        let end = lower
            .get(start..)
            .and_then(|rest| rest.find('>'))
            .map_or(lower.len(), |e| start + e);
        if matches!(after, Some(b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'>')) {
            out.push(html.get(start..end).unwrap_or_default());
        }
        at = end.max(start + 1);
    }
    out
}

/// The value of `name` in a tag, quoted or bare.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut at = 0;
    while let Some(found) = lower.get(at..).and_then(|rest| rest.find(name)) {
        let start = at + found;
        at = start + name.len();
        // Preceded by whitespace, or `name` would match inside `og:sitename`
        // and `property` inside `data-property`.
        let before = start.checked_sub(1).and_then(|i| lower.as_bytes().get(i));
        if !matches!(before, Some(b' ' | b'\t' | b'\n' | b'\r' | b'<')) {
            continue;
        }
        let rest = lower.get(at..)?.trim_start();
        if !rest.starts_with('=') {
            continue;
        }
        let value_at = tag.len() - rest.len() + 1;
        let value = tag.get(value_at..)?.trim_start();
        return Some(match value.chars().next() {
            Some(quote @ ('"' | '\'')) => value
                .get(1..)?
                .split(quote)
                .next()
                .unwrap_or_default()
                .to_owned(),
            _ => value
                .split([' ', '\t', '\n', '\r', '>'])
                .next()
                .unwrap_or_default()
                .to_owned(),
        });
    }
    None
}

/// The text between two markers, case-insensitively.
fn between<'a>(html: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find(open)? + open.len();
    let end = lower.get(start..)?.find(close)? + start;
    html.get(start..end)
}

/// Decode the handful of entities that actually appear in titles.
///
/// Not a full entity table: `&amp;` and the numeric forms are what a title
/// carries, and the rest render as themselves, which is a better failure than
/// dropping the text.
fn decode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        out.push_str(rest.get(..start).unwrap_or_default());
        let after = rest.get(start..).unwrap_or_default();
        let Some(end) = after.find(';').filter(|end| *end <= 10) else {
            out.push('&');
            rest = after.get(1..).unwrap_or_default();
            continue;
        };
        let entity = after.get(1..end).unwrap_or_default();
        let decoded = match entity.to_ascii_lowercase().as_str() {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            "nbsp" => Some(' '),
            _ => entity
                .strip_prefix('#')
                .and_then(|number| match number.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => number.parse().ok(),
                })
                .and_then(char::from_u32),
        };
        match decoded {
            Some(character) => out.push(character),
            // Unrecognised, so it goes back verbatim: an entity nobody decodes
            // renders as itself, which is a better outcome than dropping the
            // text around it.
            None => out.push_str(after.get(..=end).unwrap_or_default()),
        }
        rest = after.get(end + 1..).unwrap_or_default();
    }
    out.push_str(rest);
    // Collapsed, because HTML treats a newline in a title as a space and a
    // client rendering one gets a preview card with a hole in it.
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A byline, or nothing where the page gave a link instead of a name.
///
/// `article:author` is a URL on about half the pages that set it, pointing at
/// the author's profile. A URL printed on the line that says who wrote this
/// reads as a bug, and there is no honest way to turn one into a name, so it
/// is dropped and the card carries no byline - which is what the page
/// effectively said.
fn byline(value: &str) -> String {
    let value = value.trim();
    if value.contains("://") || value.starts_with('/') {
        return String::new();
    }
    value.to_owned()
}

/// Playing time in seconds, from any of the three ways a page writes one.
///
/// Plain seconds (`3614`), ISO-8601 (`PT1H0M14S`), and the clock form
/// (`1:00:14`). All three are in the wild, sometimes on the same site for
/// different media, and the difference between them is not one a reader should
/// ever see.
fn seconds(value: &str) -> u32 {
    let value = value.trim();
    if let Ok(plain) = value.parse::<u32>() {
        return plain;
    }
    // The clock form, most significant unit first, so it is read from the
    // right: "14" is fourteen seconds, "0:14" is still fourteen.
    if value.contains(':') {
        let mut total: u32 = 0;
        for part in value.split(':') {
            let Ok(part) = part.trim().parse::<u32>() else {
                return 0;
            };
            total = total.saturating_mul(60).saturating_add(part);
        }
        return total;
    }
    // ISO-8601. Only the parts of it a duration under a day uses: a preview
    // for a nine-hour video is as wrong at 9h as it is at 9h30, and a page
    // that writes years into a playing time is not describing one.
    let Some(rest) = value
        .strip_prefix("PT")
        .or_else(|| value.strip_prefix("pt"))
    else {
        return 0;
    };
    let mut total: u32 = 0;
    let mut digits = String::new();
    for character in rest.chars() {
        if character.is_ascii_digit() {
            digits.push(character);
            continue;
        }
        let count: u32 = digits.parse().unwrap_or(0);
        digits.clear();
        let unit = match character.to_ascii_uppercase() {
            'H' => 3600,
            'M' => 60,
            'S' => 1,
            // A fractional second, or a unit this does not read: what came
            // before it is not a number of anything known, so it is dropped
            // rather than counted as seconds.
            _ => 0,
        };
        total = total.saturating_add(count.saturating_mul(unit));
    }
    total
}

/// The amount in `value`, normalised to a `.` decimal point.
///
/// Pages write prices in both conventions - `1.234,56` and `1,234.56` - and
/// half of them wrap the number in a currency symbol or a word. The rule that
/// sorts the two out is that the *last* separator is the decimal point when
/// two digits follow it, and everything else is grouping.
fn decimal(value: &str) -> String {
    let digits: String = value
        .chars()
        .filter(|character| character.is_ascii_digit() || *character == '.' || *character == ',')
        .collect();
    let digits = digits.trim_matches(['.', ',']).to_owned();
    if digits.is_empty() {
        return String::new();
    }
    let last = digits
        .rfind([',', '.'])
        .filter(|at| matches!(digits.len() - at - 1, 1 | 2));
    match last {
        Some(at) => {
            let whole: String = digits
                .get(..at)
                .unwrap_or_default()
                .chars()
                .filter(char::is_ascii_digit)
                .collect();
            let fraction = digits.get(at + 1..).unwrap_or_default();
            format!("{whole}.{fraction}")
        }
        // No decimal part: every separator was grouping.
        None => digits.chars().filter(char::is_ascii_digit).collect(),
    }
}

/// The currency named inside `value`, as ISO 4217, or empty.
///
/// For the pages that state a price only as a labelled fact - "89,99 €" in one
/// string - where there is no `og:price:currency` to read.
fn currency_in(value: &str) -> &'static str {
    let upper = value.to_ascii_uppercase();
    const SYMBOLS: [(&str, &str); 12] = [
        ("€", "EUR"),
        ("EUR", "EUR"),
        ("£", "GBP"),
        ("GBP", "GBP"),
        ("¥", "JPY"),
        ("JPY", "JPY"),
        ("CHF", "CHF"),
        ("PLN", "PLN"),
        ("ZŁ", "PLN"),
        ("SEK", "SEK"),
        ("USD", "USD"),
        // Last: "US$" and "CA$" both contain it, and by then the three-letter
        // codes above have already answered for the ones that are not dollars.
        ("$", "USD"),
    ];
    SYMBOLS
        .into_iter()
        .find(|(symbol, _)| upper.contains(symbol))
        .map_or("", |(_, code)| code)
}

/// The crawler's reading of a page's own label, or `""` where it has none.
///
/// A label is prose a publisher wrote - "Reply count", "Antworten", "Votes" -
/// and the point of reducing it to a key is that a client can draw the handful
/// of facts it has a shape for. Anything unrecognised keeps its label and is
/// printed as it stands, so a miss here costs nothing.
#[must_use]
pub fn fact_key(label: &str) -> &'static str {
    let label = label.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|needle| label.contains(needle));
    if has(&["price", "preis", "prix", "cost"]) {
        "price"
    } else if has(&["availab", "in stock", "stock", "verfügbar", "lieferbar"]) {
        "availability"
    } else if has(&["shipping", "versand", "delivery"]) {
        "shipping"
    } else if has(&["comment", "repl", "kommentar", "antwort"]) {
        "comments"
    } else if has(&["vote", "score", "point", "karma"]) {
        "score"
    } else if has(&["like", "favorit", "favourit", "heart"]) {
        "likes"
    } else if has(&["view", "aufrufe", "watch"]) {
        "views"
    } else if has(&["rating", "stars", "bewertung"]) {
        "rating"
    } else if has(&["seller", "shop", "merchant", "offer", "angebot"]) {
        "sellers"
    } else if has(&["duration", "length", "runtime", "dauer"]) {
        "duration"
    } else if has(&["author", "artist", "creator", "posted by", "autor"]) {
        "author"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opengraph_wins_and_the_title_tag_is_the_fallback() {
        let card = card(
            r#"<html><head>
                 <title>Fallback</title>
                 <meta property="og:title" content="The Real Title">
                 <meta property="og:site_name" content="Example">
               </head><body>ignored</body></html>"#,
        );
        assert_eq!(card.title, "The Real Title");
        assert_eq!(card.site, "Example");
    }

    #[test]
    fn a_page_with_only_a_title_tag_still_previews() {
        let card = card("<html><head><title lang=\"en\">Just This</title></head>");
        assert_eq!(card.title, "Just This");
    }

    #[test]
    fn entities_are_decoded_and_whitespace_collapsed() {
        let card = card(
            "<head><title>Fish &amp; Chips\n   &#128512; a review &#x1F600; part&nbsp;2</title></head>",
        );
        // U+1F600, decimal and hex, because an emoji is the widest a single
        // `char` gets: four UTF-8 bytes, and above the BMP, so it is also a
        // surrogate pair anywhere the text passes through UTF-16. A decoder
        // holding a codepoint in a `u16`, or truncating to one byte, passes on
        // a Latin-1 entity and fails here.
        //
        // Written as `\u{...}` rather than as the character, so the assertion is
        // byte-for-byte what the entity decodes to while the file stays ASCII.
        assert_eq!(
            card.title,
            "Fish & Chips \u{1F600} a review \u{1F600} part 2"
        );
    }

    #[test]
    fn the_widest_codepoint_and_the_longest_entity_that_can_name_it_both_survive() {
        // Two limits that meet. `char::from_u32` accepts up to U+10FFFF, and
        // `decode` only treats `&...;` as an entity when the `;` is within ten
        // bytes of the `&` - which the *longest* way to write that codepoint,
        // seven decimal digits, just fits with one byte to spare. Tightening
        // that window would silently stop decoding the top of the range,
        // leaving the entity rendered as its own source text.
        let widest = card("<head><title>&#1114111; and &#x10FFFF;</title></head>");
        assert_eq!(widest.title, "\u{10FFFF} and \u{10FFFF}");

        // A grapheme built from two codepoints, eight bytes in all: each entity
        // decodes on its own and they are concatenated untouched, so the pair
        // is still one cluster to anything that renders it. The whitespace
        // collapse runs over the decoded string, and must not find a seam here.
        let flag = card("<head><title>a &#x1F1E9;&#x1F1EA; b</title></head>");
        assert_eq!(flag.title, "a \u{1F1E9}\u{1F1EA} b");
    }

    #[test]
    fn single_quoted_and_bare_attributes_are_read() {
        let card = card("<head><meta property='og:title' content='Quoted'></head>");
        assert_eq!(card.title, "Quoted");
    }

    #[test]
    fn a_tag_whose_name_merely_starts_the_same_is_not_a_meta_tag() {
        // `<metadata>` is not `<meta>`. Reading it as one is how a parser picks
        // up content from a tag that was never about the document.
        let card = card(r#"<head><metadata content="Not This"></metadata></head>"#);
        assert!(card.title.is_empty());
    }

    #[test]
    fn an_attribute_that_merely_ends_the_same_is_not_that_attribute() {
        let card = card(r#"<head><meta data-content="No" property="og:title"></head>"#);
        // `data-content` must not answer for `content`, so there is nothing to
        // take and the title stays empty rather than becoming "No".
        assert!(card.title.is_empty());
    }

    #[test]
    fn the_body_is_not_scanned() {
        // Bounded on purpose: metadata is in the head, and a `<meta>` in the
        // body is either a mistake or somebody's idea of a joke.
        let card = card(
            "<head><title>Head</title></head><body><meta property=\"og:title\" content=\"Body\"></body>",
        );
        assert_eq!(card.title, "Head");
    }

    #[test]
    fn the_first_value_wins() {
        let card = card(
            r#"<head>
                 <meta property="og:title" content="First">
                 <meta property="og:title" content="Second">
               </head>"#,
        );
        assert_eq!(card.title, "First");
    }

    #[test]
    fn the_picture_and_the_size_it_claims_are_both_read() {
        let card = card(
            r#"<head>
                 <meta property="og:image" content="https://cdn.example/card.png">
                 <meta property="og:image:width" content="1200">
                 <meta property="og:image:height" content="630">
               </head>"#,
        );
        assert_eq!(card.image, "https://cdn.example/card.png");
        assert_eq!((card.image_width, card.image_height), (1200, 630));
    }

    #[test]
    fn a_size_that_is_not_a_number_is_the_same_as_no_size() {
        // The dimensions are a hint used to decline enormous pictures early. A
        // page that writes "large" has said nothing, and nothing is `0`, not a
        // refusal and not a panic.
        let card = card(
            r#"<head>
                 <meta property="og:image" content="/c.png">
                 <meta property="og:image:width" content="large">
               </head>"#,
        );
        assert_eq!(card.image_width, 0);
        assert_eq!(card.image, "/c.png");
    }

    #[test]
    fn twitter_names_the_picture_when_opengraph_does_not() {
        let card = card(r#"<head><meta name="twitter:image" content="/t.png"></head>"#);
        assert_eq!(card.image, "/t.png");
    }

    #[test]
    fn what_the_page_says_it_is_is_read_and_left_as_it_was_written() {
        let card = card(
            r#"<head>
                 <meta property="og:type" content="Video.Other">
                 <meta name="twitter:card" content="player">
                 <meta name="generator" content="Discourse 3.2.0">
               </head>"#,
        );
        // Lowercased, because these are vocabularies rather than prose and
        // half the web capitalises them; otherwise untouched, because
        // deciding what "video.other" *means* is a different job.
        assert_eq!(card.page_type, "video.other");
        assert_eq!(card.twitter_card, "player");
        assert_eq!(card.generator, "discourse 3.2.0");
    }

    #[test]
    fn a_playing_time_is_read_in_all_three_forms_pages_write_it_in() {
        let iso = card(r#"<head><meta itemprop="duration" content="PT1H0M14S"></head>"#);
        assert_eq!(iso.duration, 3614);
        let plain = card(r#"<head><meta property="og:video:duration" content="212"></head>"#);
        assert_eq!(plain.duration, 212);
        let clock = card(r#"<head><meta property="video:duration" content="3:32"></head>"#);
        assert_eq!(clock.duration, 212);
        // A page that writes something else has said nothing, which is `0`
        // and not a card without a preview.
        let nonsense = card(r#"<head><meta property="video:duration" content="ages"></head>"#);
        assert_eq!(nonsense.duration, 0);
    }

    #[test]
    fn a_byline_is_a_name_and_never_a_link() {
        let named = card(r#"<head><meta name="author" content="UberCrow"></head>"#);
        assert_eq!(named.author, "UberCrow");
        // `article:author` is a profile URL on about half the pages that set
        // it. A URL on the line that says who wrote this reads as a bug, and
        // there is no honest way to turn one into a name.
        let linked = card(
            r#"<head><meta property="article:author" content="https://x.example/u/ame"></head>"#,
        );
        assert!(linked.author.is_empty());
    }

    #[test]
    fn both_price_conventions_come_out_the_same_way() {
        let german = card(
            r#"<head>
                 <meta property="product:price:amount" content="1.234,56">
                 <meta property="product:price:currency" content="eur">
                 <meta property="product:original_price:amount" content="1.499,00">
                 <meta property="og:availability" content="InStock">
               </head>"#,
        );
        assert_eq!(german.price.amount, "1234.56");
        assert_eq!(german.price.was, "1499.00");
        assert_eq!(german.price.currency, "EUR");
        assert_eq!(german.price.availability, "instock");

        // The same amount the other way round, and a symbol in the way.
        let english = card(r#"<head><meta property="og:price:amount" content="$1,234.56"></head>"#);
        assert_eq!(english.price.amount, "1234.56");
        // No decimal part at all: every separator was grouping.
        let whole = card(r#"<head><meta property="og:price:amount" content="1.234"></head>"#);
        assert_eq!(whole.price.amount, "1234");
    }

    #[test]
    fn labelled_facts_are_paired_and_the_ones_we_know_are_named() {
        let card = card(
            r#"<head>
                 <meta name="twitter:label1" content="Reply count">
                 <meta name="twitter:data1" content="206">
                 <meta name="twitter:label2" content="Likes">
                 <meta name="twitter:data2" content="3.4K">
                 <meta name="twitter:label3" content="Assembled by">
                 <meta name="twitter:data3" content="hand">
               </head>"#,
        );
        assert_eq!(card.facts.len(), 3);
        assert_eq!(card.facts[0].key, "comments");
        assert_eq!(card.facts[0].label, "Reply count");
        assert_eq!(card.facts[0].value, "206");
        assert_eq!(card.facts[1].key, "likes");
        // Unrecognised keeps its label and is printed as it stands: a miss
        // costs the shape a client would have drawn, not the fact.
        assert_eq!(card.facts[2].key, "");
        assert_eq!(card.facts[2].label, "Assembled by");
    }

    #[test]
    fn half_a_labelled_fact_is_not_a_fact() {
        // A label with nothing under it is a heading for something the page
        // did not say, and a value with no label is a number nobody can read.
        let card = card(
            r#"<head>
                 <meta name="twitter:label1" content="Reply count">
                 <meta name="twitter:data2" content="3.4K">
               </head>"#,
        );
        assert!(card.facts.is_empty());
    }

    #[test]
    fn a_price_stated_only_as_a_labelled_fact_is_still_a_price() {
        // Shops that publish no `product:price:amount` still put the price in
        // the Twitter card, currency and all, because that is what renders.
        let card = card(
            r#"<head>
                 <meta name="twitter:label1" content="Price">
                 <meta name="twitter:data1" content="89,99 €">
               </head>"#,
        );
        assert_eq!(card.price.amount, "89.99");
        assert_eq!(card.price.currency, "EUR");
    }

    #[test]
    fn the_typed_tags_beat_the_labelled_facts_for_the_same_thing() {
        let card = card(
            r#"<head>
                 <meta property="og:price:amount" content="10.00">
                 <meta property="og:price:currency" content="GBP">
                 <meta name="twitter:label1" content="Price">
                 <meta name="twitter:data1" content="99,00 €">
               </head>"#,
        );
        // The tag that exists for no other purpose wins over the one that is
        // a label somebody typed.
        assert_eq!(card.price.amount, "10.00");
        assert_eq!(card.price.currency, "GBP");
    }

    #[test]
    fn the_site_icon_prefers_the_one_drawn_for_a_screen_over_the_one_for_a_tab() {
        let card = card(
            r#"<head>
                 <link rel="shortcut icon" href="/favicon.ico">
                 <link rel="apple-touch-icon" href="/touch.png">
               </head>"#,
        );
        // `rel="icon"` is as often a 16-pixel `.ico` drawn for a browser tab
        // in 1999; the touch icon is a PNG somebody drew this decade.
        assert_eq!(card.icon, "/touch.png");
    }

    #[test]
    fn an_icon_the_fetcher_would_refuse_is_not_chosen() {
        // SVG is a document with scripts and external references in it, which
        // is why the image fetch refuses one. Preferring it would mean
        // choosing the icon that cannot arrive.
        let chosen = card(
            r#"<head>
                 <link rel="icon" href="/mark.svg">
                 <link rel="icon" href="/mark.png">
               </head>"#,
        );
        assert_eq!(chosen.icon, "/mark.png");
        // And a page that declares nothing declares nothing: the client draws
        // a monogram rather than the server guessing at a path.
        assert!(card("<head><title>x</title></head>").icon.is_empty());
    }

    #[test]
    fn a_byline_and_a_date_are_read_from_the_vocabularies_pages_actually_use() {
        // Measured off a real news page: a German broadcaster publishes
        // neither in the `OpenGraph` namespace, and both in the plain names a
        // CMS writes.
        let card = card(
            r#"<head>
                 <meta name="author" content="A Reporter">
                 <meta name="date" content="2026-09-01T07:30:00+02:00">
                 <meta name="rating" content="General">
               </head>"#,
        );
        assert_eq!(card.author, "A Reporter");
        assert_eq!(card.published, "2026-09-01T07:30:00+02:00");
        assert_eq!(card.rating, "general");
    }

    #[test]
    fn structured_data_fills_what_the_sharing_tags_have_no_room_for() {
        // Who made it, when, how it was rated and how many watched: none of
        // these are in `OpenGraph` at all, and on most pages `schema.org` is
        // the only place they exist.
        let card = card(
            r#"<head>
                 <meta property="og:title" content="A Piece">
                 <script type="application/ld+json">
                   {"@type":"ImageObject","creator":{"@type":"Person","name":"ame"},
                    "datePublished":"2026-08-04","contentRating":"Safe",
                    "aggregateRating":{"ratingValue":"4.6","bestRating":"5","ratingCount":128},
                    "interactionStatistic":{"interactionType":"https://schema.org/LikeAction",
                                            "userInteractionCount":12400}}
                 </script>
               </head>"#,
        );
        assert_eq!(card.author, "ame");
        assert_eq!(card.published, "2026-08-04");
        assert_eq!(card.rating, "safe");
        // The counts and the stars join the page's own labelled facts: they
        // are the same kind of thing, and a client that draws one draws all.
        let fact = |key: &str| {
            card.facts
                .iter()
                .find(|fact| fact.key == key)
                .map(|fact| fact.value.as_str())
        };
        assert_eq!(fact("likes"), Some("12400"));
        assert_eq!(fact("rating"), Some("4.6/5 (128)"));
    }

    #[test]
    fn a_sharing_tag_beats_the_structured_data_for_the_same_fact() {
        // `OpenGraph` is what the author wrote *for* a card like this one, so
        // where the two disagree it wins; `schema.org` fills the gaps.
        let card = card(
            r#"<head>
                 <meta name="author" content="The Tag">
                 <script type="application/ld+json">{"author":"The Script","datePublished":"2026-01-01"}</script>
               </head>"#,
        );
        assert_eq!(card.author, "The Tag");
        assert_eq!(card.published, "2026-01-01");
    }

    #[test]
    fn a_page_with_nothing_to_say_yields_an_empty_card() {
        assert_eq!(card("<html><body>hello</body></html>"), Card::default());
    }

    #[test]
    fn a_truncated_page_still_yields_what_it_had() {
        // The byte cap cuts pages mid-document, so this is the ordinary case
        // for anything large, not an edge one.
        let card = card("<html><head><meta property=\"og:title\" content=\"Cut Off\"><meta prop");
        assert_eq!(card.title, "Cut Off");
    }
}
