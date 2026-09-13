//! A plugin from the marketplace: its manifest, the one artifact that fits this
//! server, and the binary inside that artifact.
//!
//! The host writes and loads bytes and fetches nothing (`install.rs` in
//! `starling-plugin-host`). This is the half the C++ server's host did in
//! process, here because this service can own an HTTP client. What it keeps from
//! that version: every body is capped, the manifest can be pinned to the digest
//! the admin reviewed, and the artifact must match the digest the manifest names.

use std::io::{Cursor, Read};
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use starling_plugin_host::api::PLUGIN_ABI_VERSION;
use starling_plugin_host::{MAX_ARTIFACT_BYTES, digest};

/// Largest manifest read: JSON describing a handful of downloads.
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// How long one download may take, end to end.
const TIMEOUT: Duration = Duration::from_secs(60);

/// One downloadable build in a manifest.
#[derive(Debug, Deserialize)]
pub(crate) struct Artifact {
    /// `linux`, `windows` or `macos`; ignored for `wasm`.
    #[serde(default)]
    pub os: String,
    /// `x86_64`, `aarch64`; ignored for `wasm`.
    #[serde(default)]
    pub arch: String,
    /// `tar.gz` or `zip`.
    pub format: String,
    pub download_url: String,
    /// Hex SHA-256 of the archive.
    pub sha256: String,
    /// The binary's file name inside the archive.
    pub cdylib_filename: String,
    /// `native` unless the manifest says `wasm`.
    #[serde(default = "native")]
    pub kind: String,
}

fn native() -> String {
    "native".to_owned()
}

/// The part of a marketplace manifest an install reads.
#[derive(Debug, Deserialize)]
pub(crate) struct Manifest {
    pub marketplace_id: String,
    pub version: String,
    #[serde(default)]
    pub required_abi_version: Option<u32>,
    pub artifacts: Vec<Artifact>,
}

/// What an admin asked for.
#[derive(Debug)]
pub(crate) struct Wanted<'a> {
    pub marketplace_id: &'a str,
    /// Empty or `None` accepts whatever version the manifest names.
    pub version: Option<&'a str>,
    pub manifest_url: &'a str,
    /// Hex SHA-256 the manifest must hash to; empty or `None` skips the pin.
    pub manifest_sha256: Option<&'a str>,
}

/// A plugin binary, fetched and checked, ready for the host.
#[derive(Debug)]
pub(crate) struct Fetched {
    pub file_name: String,
    pub bytes: Vec<u8>,
    pub version: String,
}

/// Fetch `wanted`'s manifest and the build of it this server can run.
///
/// # Errors
///
/// A reason an admin can act on: the download failed, a digest did not match,
/// the manifest is for another plugin, version or plugin ABI, or it has no build
/// for this platform.
pub(crate) async fn fetch(wanted: &Wanted<'_>) -> Result<Fetched, String> {
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(|error| format!("cannot build an HTTP client: {error}"))?;

    let raw = get(&client, wanted.manifest_url, MAX_MANIFEST_BYTES).await?;
    if let Some(pin) = wanted.manifest_sha256.filter(|pin| !pin.is_empty()) {
        let actual = digest(&raw);
        if !pin.eq_ignore_ascii_case(&actual) {
            return Err(format!(
                "the manifest changed after it was reviewed: expected {pin}, got {actual}"
            ));
        }
    }
    let manifest = parse(&raw)?;
    check(&manifest, wanted)?;
    let artifact = pick(&manifest, platform())?;

    let archive = get(&client, &artifact.download_url, MAX_ARTIFACT_BYTES).await?;
    let actual = digest(&archive);
    if !artifact.sha256.eq_ignore_ascii_case(&actual) {
        return Err(format!(
            "the download does not match the manifest: expected {}, got {actual}",
            artifact.sha256
        ));
    }
    let format = artifact.format.clone();
    let file_name = artifact.cdylib_filename.clone();
    let bytes = {
        let file_name = file_name.clone();
        // Inflating up to 32 MiB is enough CPU to stall a runtime worker.
        tokio::task::spawn_blocking(move || {
            extract(&format, &archive, &file_name, MAX_ARTIFACT_BYTES)
        })
        .await
        .map_err(|error| format!("unpacking the artifact failed: {error}"))??
    };
    Ok(Fetched {
        file_name,
        bytes,
        version: manifest.version,
    })
}

/// `url`'s body, refused past `cap` bytes.
async fn get(client: &reqwest::Client, url: &str, cap: usize) -> Result<Vec<u8>, String> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err(format!("{url} is not an http(s) URL"));
    }
    let too_large = || format!("{url} is larger than {cap} B");
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("fetching {url} failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("{url} answered HTTP {}", response.status()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(cap).unwrap_or(u64::MAX))
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("reading {url} failed: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > cap {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn parse(raw: &[u8]) -> Result<Manifest, String> {
    serde_json::from_slice(raw).map_err(|error| format!("the manifest is not valid: {error}"))
}

/// This server's `(os, arch)`, spelled the way manifests spell it.
fn platform() -> (&'static str, &'static str) {
    (std::env::consts::OS, std::env::consts::ARCH)
}

/// The manifest is for the plugin, version and plugin ABI that were asked for.
fn check(manifest: &Manifest, wanted: &Wanted<'_>) -> Result<(), String> {
    if !manifest
        .marketplace_id
        .eq_ignore_ascii_case(wanted.marketplace_id)
    {
        return Err(format!(
            "the manifest is for '{}', not '{}'",
            manifest.marketplace_id, wanted.marketplace_id
        ));
    }
    if let Some(version) = wanted.version.filter(|version| !version.is_empty())
        && manifest.version != version
    {
        return Err(format!(
            "the manifest is version {}, not {version}",
            manifest.version
        ));
    }
    if let Some(required) = manifest.required_abi_version
        && required != PLUGIN_ABI_VERSION
    {
        return Err(format!(
            "the plugin needs plugin API {required} and this server has {PLUGIN_ABI_VERSION}"
        ));
    }
    Ok(())
}

/// The build this server should install.
///
/// A native build for this exact platform first, then a portable WASM one. A
/// manifest may bundle several plugins' builds (the marketplace's own example
/// release does), so the build whose binary is named after the plugin wins;
/// taking the first platform match installed a different plugin than the one
/// asked for.
fn pick<'m>(manifest: &'m Manifest, (os, arch): (&str, &str)) -> Result<&'m Artifact, String> {
    let native: Vec<&Artifact> = manifest
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact.kind.eq_ignore_ascii_case("native")
                && artifact.os.eq_ignore_ascii_case(os)
                && artifact.arch.eq_ignore_ascii_case(arch)
        })
        .collect();
    let wasm: Vec<&Artifact> = manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind.eq_ignore_ascii_case("wasm"))
        .collect();

    for candidates in [native, wasm] {
        if let Some(named) = candidates
            .iter()
            .find(|artifact| names_plugin(&artifact.cdylib_filename, &manifest.marketplace_id))
        {
            return Ok(named);
        }
        if let [only] = candidates.as_slice() {
            return Ok(only);
        }
        if !candidates.is_empty() {
            return Err(format!(
                "the manifest has {} builds that fit {os}/{arch} and none is named after '{}'",
                candidates.len(),
                manifest.marketplace_id
            ));
        }
    }
    let available: Vec<String> = manifest
        .artifacts
        .iter()
        .map(|artifact| format!("{}/{}/{}", artifact.kind, artifact.os, artifact.arch))
        .collect();
    Err(format!(
        "no build for {os}/{arch} and no portable wasm build; the manifest has {}",
        available.join(", ")
    ))
}

/// Whether `file_name` (`libfancy_greeter.so`, `fancy_greeter.dll`) is the
/// binary of `marketplace_id` (`fancy-greeter`).
fn names_plugin(file_name: &str, marketplace_id: &str) -> bool {
    let Some(stem) = Path::new(file_name)
        .file_stem()
        .and_then(|stem| stem.to_str())
    else {
        return false;
    };
    let wanted = marketplace_id.replace('-', "_");
    let matches = |stem: &str| stem.replace('-', "_").eq_ignore_ascii_case(&wanted);
    matches(stem) || stem.strip_prefix("lib").is_some_and(matches)
}

/// `file_name` out of `archive`, capped at `cap` bytes once inflated.
fn extract(format: &str, archive: &[u8], file_name: &str, cap: usize) -> Result<Vec<u8>, String> {
    match format.to_ascii_lowercase().as_str() {
        "tar.gz" | "tgz" => extract_tar_gz(archive, file_name, cap),
        "zip" => extract_zip(archive, file_name, cap),
        other => Err(format!("unsupported artifact format '{other}'")),
    }
}

fn extract_tar_gz(archive: &[u8], file_name: &str, cap: usize) -> Result<Vec<u8>, String> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(Cursor::new(archive)));
    let entries = archive
        .entries()
        .map_err(|error| format!("the artifact is not a tar.gz: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("the artifact is corrupt: {error}"))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|error| format!("the artifact is corrupt: {error}"))?
            .into_owned();
        if is_named(&path, file_name) {
            return read_capped(entry, cap);
        }
    }
    Err(format!("'{file_name}' is not in the artifact"))
}

fn extract_zip(archive: &[u8], file_name: &str, cap: usize) -> Result<Vec<u8>, String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(archive))
        .map_err(|error| format!("the artifact is not a zip: {error}"))?;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("the artifact is corrupt: {error}"))?;
        if entry.is_file()
            && entry
                .enclosed_name()
                .is_some_and(|path| is_named(&path, file_name))
        {
            return read_capped(entry, cap);
        }
    }
    Err(format!("'{file_name}' is not in the artifact"))
}

fn is_named(path: &Path, file_name: &str) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some(file_name)
}

/// Read one entry, refused past `cap`: a small archive can inflate to anything.
fn read_capped(entry: impl Read, cap: usize) -> Result<Vec<u8>, String> {
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    let _ = entry
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read the artifact: {error}"))?;
    if bytes.len() > cap {
        return Err(format!("the plugin binary inflates past {cap} B"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    fn artifact(os: &str, arch: &str, file: &str, kind: &str) -> serde_json::Value {
        serde_json::json!({
            "os": os, "arch": arch, "format": "tar.gz",
            "download_url": format!("https://example.invalid/{file}"),
            "sha256": "00", "cdylib_filename": file, "kind": kind,
        })
    }

    fn manifest(id: &str, artifacts: Vec<serde_json::Value>) -> Manifest {
        serde_json::from_value(serde_json::json!({
            "marketplace_id": id, "version": "0.3.0",
            "artifacts": serde_json::Value::Array(artifacts),
        }))
        .expect("a valid manifest")
    }

    fn wanted(id: &str) -> Wanted<'_> {
        Wanted {
            marketplace_id: id,
            version: None,
            manifest_url: "https://example.invalid/manifest",
            manifest_sha256: None,
        }
    }

    fn tar_gz(path: &str, bytes: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, bytes)
            .expect("append");
        builder.into_inner().expect("tar").finish().expect("gzip")
    }

    #[test]
    fn a_bundled_manifest_installs_the_plugin_that_was_asked_for() {
        // The live `fancy-greeter` 0.3.0 manifest lists six plugins' builds,
        // chat-card first. Taking the first Linux match installed chat-card.
        let bundle = manifest(
            "fancy-greeter",
            vec![
                artifact("linux", "x86_64", "libfancy_chat_card.so", "native"),
                artifact("linux", "x86_64", "libfancy_greeter.so", "native"),
                artifact("windows", "x86_64", "fancy_greeter.dll", "native"),
            ],
        );
        let picked = pick(&bundle, ("linux", "x86_64")).expect("a build");
        assert_eq!(picked.cdylib_filename, "libfancy_greeter.so");
        let picked = pick(&bundle, ("windows", "x86_64")).expect("a build");
        assert_eq!(picked.cdylib_filename, "fancy_greeter.dll");
    }

    #[test]
    fn a_lone_build_is_taken_whatever_its_binary_is_called() {
        let single = manifest(
            "fancy-greeter",
            vec![artifact("linux", "x86_64", "libgreeter.so", "native")],
        );
        assert!(pick(&single, ("linux", "x86_64")).is_ok());
    }

    #[test]
    fn several_unnamed_builds_are_refused_rather_than_guessed() {
        let ambiguous = manifest(
            "fancy-greeter",
            vec![
                artifact("linux", "x86_64", "liba.so", "native"),
                artifact("linux", "x86_64", "libb.so", "native"),
            ],
        );
        let error = pick(&ambiguous, ("linux", "x86_64")).expect_err("ambiguous");
        assert!(error.contains("none is named"), "{error}");
    }

    #[test]
    fn wasm_is_the_fallback_and_a_missing_platform_says_what_exists() {
        let portable = manifest(
            "fancy-greeter",
            vec![
                artifact("windows", "x86_64", "fancy_greeter.dll", "native"),
                artifact("any", "any", "fancy_greeter.wasm", "wasm"),
            ],
        );
        let picked = pick(&portable, ("linux", "aarch64")).expect("wasm");
        assert_eq!(picked.kind, "wasm");

        let windows_only = manifest(
            "fancy-greeter",
            vec![artifact("windows", "x86_64", "fancy_greeter.dll", "native")],
        );
        let error = pick(&windows_only, ("linux", "x86_64")).expect_err("no build");
        assert!(error.contains("native/windows/x86_64"), "{error}");
    }

    #[test]
    fn a_manifest_for_another_plugin_version_or_abi_is_refused() {
        let greeter = manifest("fancy-greeter", Vec::new());
        assert!(check(&greeter, &wanted("fancy-greeter")).is_ok());
        assert!(check(&greeter, &wanted("FANCY-GREETER")).is_ok());
        assert!(check(&greeter, &wanted("fancy-poll")).is_err());

        let mut other_version = wanted("fancy-greeter");
        other_version.version = Some("0.2.0");
        assert!(check(&greeter, &other_version).is_err());
        let mut any_version = wanted("fancy-greeter");
        any_version.version = Some("");
        assert!(check(&greeter, &any_version).is_ok());

        let mut old = manifest("fancy-greeter", Vec::new());
        old.required_abi_version = Some(PLUGIN_ABI_VERSION.wrapping_sub(1));
        let error = check(&old, &wanted("fancy-greeter")).expect_err("abi");
        assert!(error.contains("plugin API"), "{error}");
    }

    #[test]
    fn the_binary_comes_out_of_a_tar_gz_and_a_zip() {
        let binary = b"\x7fELF not really".as_slice();
        let archive = tar_gz("fancy-greeter/libfancy_greeter.so", binary);
        assert_eq!(
            extract("tar.gz", &archive, "libfancy_greeter.so", 1024).expect("tar.gz"),
            binary
        );
        assert!(extract("tar.gz", &archive, "libother.so", 1024).is_err());

        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "fancy_greeter.dll",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .expect("start");
        writer.write_all(binary).expect("write");
        let archive = writer.finish().expect("zip").into_inner();
        assert_eq!(
            extract("zip", &archive, "fancy_greeter.dll", 1024).expect("zip"),
            binary
        );
    }

    #[test]
    fn a_binary_that_inflates_past_the_cap_is_refused() {
        let archive = tar_gz("libfancy_greeter.so", &[0; 4096]);
        let error = extract("tar.gz", &archive, "libfancy_greeter.so", 1024).expect_err("cap");
        assert!(error.contains("inflates"), "{error}");
    }

    /// Serve the routes `build` makes from the base URL, over HTTP/1.1 on
    /// loopback. The base goes in first because a manifest names its own
    /// download URLs.
    async fn serve(build: impl FnOnce(&str) -> Vec<(&'static str, Vec<u8>)>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let routes = build(&base);
        drop(tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut request = vec![0; 4096];
                let read = socket.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(request.get(..read).unwrap_or_default());
                let path = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let (status, body) = routes
                    .iter()
                    .find(|(route, _)| *route == path)
                    .map_or(("404 Not Found", Vec::new()), |(_, body)| {
                        ("200 OK", body.clone())
                    });
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&body).await;
            }
        }));
        base
    }

    #[tokio::test]
    async fn an_install_fetches_the_build_and_holds_both_digests_to_account() {
        let binary = b"a plugin, notionally".to_vec();
        let file = format!("libfancy_greeter{}", starling_plugin_host::cdylib_suffix());
        let archive = tar_gz(&file, &binary);
        let (os, arch) = platform();
        let manifest_for = |base: &str, sha256: &str| {
            serde_json::json!({
                "marketplace_id": "fancy-greeter", "version": "0.3.0",
                "artifacts": [{
                    "os": os, "arch": arch, "format": "tar.gz",
                    "download_url": format!("{base}/greeter.tar.gz"),
                    "sha256": sha256, "cdylib_filename": file,
                }],
            })
            .to_string()
            .into_bytes()
        };
        let mut pin = String::new();
        let base = serve(|base| {
            let manifest = manifest_for(base, &digest(&archive));
            pin = digest(&manifest);
            vec![
                ("/manifest", manifest),
                ("/tampered", manifest_for(base, &"0".repeat(64))),
                ("/greeter.tar.gz", archive.clone()),
            ]
        })
        .await;

        let manifest_url = format!("{base}/manifest");
        let mut request = wanted("fancy-greeter");
        request.manifest_url = &manifest_url;
        request.manifest_sha256 = Some(&pin);
        let fetched = fetch(&request).await.expect("install");
        assert_eq!(fetched.bytes, binary);
        assert_eq!(fetched.file_name, file);
        assert_eq!(fetched.version, "0.3.0");

        let stale = "f".repeat(64);
        request.manifest_sha256 = Some(&stale);
        let error = fetch(&request).await.expect_err("pin");
        assert!(error.contains("changed after it was reviewed"), "{error}");

        let tampered_url = format!("{base}/tampered");
        request.manifest_url = &tampered_url;
        request.manifest_sha256 = None;
        let error = fetch(&request).await.expect_err("artifact digest");
        assert!(error.contains("does not match the manifest"), "{error}");
    }
}
