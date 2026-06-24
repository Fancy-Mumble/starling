//! Tracing, a request id threaded through every hop, and the metrics endpoint.
//!
//! Separate processes cost this: a hung permission check that spans three
//! services is unattributable without it (`docs/ARCHITECTURE.md` §8). The
//! request id is generated at the gateway, carried in gRPC metadata, and put on
//! every span, so one grep follows a client's frame across the whole system.
//!
//! Note the deliberate separation from `crate::log`: that is the
//! **operator-facing** record — who connected, what was refused — and it
//! survives independently of whatever `RUST_LOG` happens to say.

use tonic::metadata::{MetadataMap, MetadataValue};
use tracing_subscriber::EnvFilter;

use crate::config::{LogFormat, TelemetryConfig};
use crate::ids::Uuid7;

/// The metadata key a request id travels under.
pub const REQUEST_ID_HEADER: &str = "x-starling-request-id";

/// Install the tracing subscriber for this process.
///
/// Idempotent: a second call is a no-op rather than a panic, because
/// `--all-in-one` starts many services in one process and each of them would
/// otherwise try.
pub fn install(config: &TelemetryConfig) {
    // `warn`, not `info`, when `RUST_LOG` says nothing.
    //
    // Both this and `crate::log` write to stderr, and at `info` they narrated
    // the same events twice in two different shapes — the operator log's
    // `INFO session client connected …` next to tracing's
    // `INFO starling_gateway::listener: client connected …`. The operator log
    // is the one meant to be *read*: it is curated, categorised, and covers
    // startup, connections and refusals. This one is a developer's dial.
    //
    // So the default is the level at which a developer's dial is worth
    // interrupting an operator: something went wrong. `RUST_LOG=debug` brings
    // back the per-connection detail, `trace` every frame, and
    // `RUST_LOG=starling_voice=trace` one service's worth.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    let installed = match config.log_format {
        LogFormat::Json => builder.json().try_init().is_ok(),
        LogFormat::Text => builder.try_init().is_ok(),
    };
    if installed {
        tracing::debug!(format = ?config.log_format, "tracing installed");
    }
    if let Some(endpoint) = &config.otlp_endpoint {
        // Recorded rather than silently ignored: an operator who configured a
        // collector and sees nothing arrive deserves to know why.
        tracing::info!(
            %endpoint,
            "otlp export is configured but not built into this binary; spans stay local"
        );
    }
}

/// A fresh request id.
#[must_use]
pub fn new_request_id() -> String {
    Uuid7::now().to_string()
}

/// Read the request id from inbound metadata, or mint one.
///
/// Minting rather than failing is deliberate: a call without an id is a caller
/// that has not been taught yet, and refusing it would turn an observability
/// gap into an outage.
#[must_use]
pub fn request_id(metadata: &MetadataMap) -> String {
    metadata
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(new_request_id)
}

/// Put a request id onto an outbound call.
pub fn set_request_id(metadata: &mut MetadataMap, id: &str) {
    if let Ok(value) = MetadataValue::try_from(id) {
        let _ = metadata.insert(REQUEST_ID_HEADER, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_id_survives_a_hop() {
        // If it did not, a trace would restart at every service and the whole
        // point — following one frame across processes — would be lost.
        let mut metadata = MetadataMap::new();
        let id = new_request_id();
        set_request_id(&mut metadata, &id);
        assert_eq!(request_id(&metadata), id);
    }

    #[test]
    fn a_call_without_an_id_gets_one_rather_than_being_refused() {
        let id = request_id(&MetadataMap::new());
        assert!(!id.is_empty());
    }
}
