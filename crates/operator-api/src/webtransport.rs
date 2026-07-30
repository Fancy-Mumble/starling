//! The live channel over WebTransport (HTTP/3).
//!
//! The same events as the WebSocket at `/v1/events`, over QUIC. Both encode
//! with [`crate::events::encode`], so a consumer written against one reads the
//! other unchanged.
//!
//! # Two unidirectional streams, not one bidirectional
//!
//! A WebTransport `BidiStream` implements sending and receiving on one object,
//! so reading and writing it concurrently would mean sharing it behind a lock —
//! and a lock held across a write would stall event delivery whenever a command
//! arrived. Two unidirectional streams have no such coupling: the server opens
//! one for events, the client opens one for commands, and neither waits on the
//! other. Replies to commands go out on the event stream, exactly as they do on
//! the WebSocket, so a consumer sees one ordered sequence either way.
//!
//! # Why this is off unless configured
//!
//! It needs the deployment to terminate QUIC. Reverse proxies do not generally
//! forward Extended CONNECT over HTTP/3, so a proxied deployment reaches this
//! channel over the WebSocket instead and never binds a UDP port at all.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use h3::quic::{RecvStream as _, SendStreamUnframed};
use tokio::sync::broadcast::error::RecvError;

use crate::OperatorApi;
use crate::events::encode;

/// The path a WebTransport session is established against.
///
/// The same path as the WebSocket route, so the two transports are the same
/// endpoint reached two ways rather than two endpoints that happen to agree.
const PATH: &str = "/v1/events";

/// What went wrong starting the listener.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The certificate or key could not be read or generated.
    #[error("the WebTransport certificate could not be loaded: {0}")]
    Identity(#[from] starling_crypto::identity::TlsError),
    /// rustls refused the certificate and key.
    #[error("the WebTransport TLS configuration is invalid: {0}")]
    Tls(#[from] rustls::Error),
    /// The QUIC crypto configuration was rejected.
    #[error("the QUIC configuration is invalid: {0}")]
    Quic(String),
    /// The UDP socket could not be bound.
    #[error("the WebTransport listener could not bind {0}: {1}")]
    Bind(SocketAddr, std::io::Error),
}

/// Bind the UDP socket and serve until `shutdown`.
///
/// # Errors
///
/// [`Error`] when the certificate cannot be loaded or the socket cannot be
/// bound. A failure here is reported and does not stop the rest of the API:
/// the WebSocket channel is unaffected by a QUIC port that would not bind.
pub async fn serve(
    api: Arc<OperatorApi>,
    listen: SocketAddr,
    cert: &Path,
    key: &Path,
    shutdown: starling_runtime::shutdown::Shutdown,
) -> Result<(), Error> {
    // Generated on first boot if absent, as the gateway's is. A deployment
    // behind a proxy that terminates TLS still needs a real certificate here,
    // because this listener is the one thing the proxy is not terminating.
    let identity = starling_crypto::identity::load_or_generate(cert, key)?;

    // rustls 0.23 installs no default provider; the gateway may already have
    // installed the same one, and a second install of the same backend is a
    // no-op rather than a conflict.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(identity.certs, identity.key)?;
    // Without this ALPN entry a browser's HTTP/3 handshake is refused, and the
    // failure surfaces as a connection that simply never establishes.
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| Error::Quic(error.to_string()))?;
    let server = quinn::ServerConfig::with_crypto(Arc::new(crypto));

    let endpoint =
        quinn::Endpoint::server(server, listen).map_err(|error| Error::Bind(listen, error))?;
    tracing::info!(%listen, "WebTransport listening");

    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => incoming,
            () = shutdown.wait() => break,
        };
        let Some(incoming) = incoming else { break };

        let api = Arc::clone(&api);
        drop(tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    if let Err(error) = session(api, connection).await {
                        // Debug, not warn: a browser closing a tab ends a QUIC
                        // connection abruptly, and that is not an incident.
                        tracing::debug!(%error, "a WebTransport connection ended");
                    }
                }
                Err(error) => tracing::debug!(%error, "a QUIC handshake failed"),
            }
        }));
    }

    // Lets in-flight sessions finish rather than cutting them mid-event.
    endpoint.wait_idle().await;
    Ok(())
}

/// One QUIC connection: the HTTP/3 handshake, then the WebTransport session.
async fn session(
    api: Arc<OperatorApi>,
    connection: quinn::Connection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut h3 = h3::server::builder()
        // All three are required for WebTransport, and a client checks them:
        // without extended CONNECT there is no way to open a session at all.
        .enable_webtransport(true)
        .enable_extended_connect(true)
        .enable_datagram(true)
        .max_webtransport_sessions(1)
        .send_grease(true)
        .build(h3_quinn::Connection::new(connection))
        .await?;

    let Some(resolver) = h3.accept().await? else {
        return Ok(());
    };
    let (request, stream) = resolver.resolve_request().await?;

    // Only this path, and only a CONNECT. Anything else is answered rather
    // than dropped, so a misconfigured client is told what it got wrong.
    if request.uri().path() != PATH {
        tracing::debug!(path = request.uri().path(), "WebTransport path not found");
        return Ok(());
    }

    // The same credential the WebSocket takes, from the same header. A
    // WebTransport CONNECT carries request headers, so nothing here needs a
    // second authentication scheme.
    let header = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    let subject = match api.identify(header) {
        Ok(identity) if identity.allows("session-view:read") => identity.subject,
        Ok(identity) => {
            tracing::info!(
                subject = identity.subject,
                "a WebTransport subscriber lacked session-view:read"
            );
            return Ok(());
        }
        Err(refusal) => {
            tracing::info!(%refusal, "a WebTransport subscriber was refused");
            return Ok(());
        }
    };

    // Recorded before the session is established, as every other action is.
    // A live channel is a read of everything, so it is not exempt.
    if let Err(error) = api.record(&crate::AuditRecord {
        subject: subject.clone(),
        action: format!("CONNECT {PATH} (webtransport)"),
        outcome: "accepted".to_owned(),
    }) {
        tracing::error!(%error, "a WebTransport session was refused: not recorded");
        return Ok(());
    }

    let session = h3_webtransport::server::WebTransportSession::accept(request, stream, h3).await?;
    tracing::info!(subject, "a WebTransport subscriber attached");

    let result = pump(&api, &session, &subject).await;
    tracing::info!(subject, "a WebTransport subscriber detached");
    result
}

/// Events out on a server-opened stream, commands in on a client-opened one.
async fn pump(
    api: &OperatorApi,
    session: &h3_webtransport::server::WebTransportSession<h3_quinn::Connection, Bytes>,
    subject: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let id = session.session_id();
    let mut out = session.open_uni(id).await?;
    let mut events = api.events().subscribe();

    // The same greeting the WebSocket sends, for the same reason: `started` is
    // published once and this channel is not a replay, so a subscriber that
    // arrives afterwards has no other way to learn the channel is live.
    if api.events().is_live() {
        write_line(
            &mut out,
            &encode(&crate::events::Event::Started { server_id: 1 }),
        )
        .await?;
    }

    // Registered context entries, withdrawn when this session ends — the same
    // contract the WebSocket keeps, for the same reason.
    let mut registered: Vec<String> = Vec::new();
    // Commands arrive newline-delimited and a read may split one, so partial
    // input is held here rather than parsed as a truncated line.
    let mut pending = Vec::new();
    let mut commands: Option<_> = None;

    loop {
        tokio::select! {
            received = events.recv() => match received {
                Ok(event) => write_line(&mut out, &encode(&event)).await?,
                Err(RecvError::Lagged(missed)) => {
                    tracing::warn!(subject, missed, "a WebTransport subscriber fell behind");
                    write_line(&mut out, &format!(r#"{{"event":"lagged","missed":{missed}}}"#))
                        .await?;
                }
                Err(RecvError::Closed) => break,
            },

            // The client's command stream, accepted once and then read from.
            accepted = session.accept_uni(), if commands.is_none() => {
                match accepted {
                    Ok(Some((_, stream))) => commands = Some(stream),
                    // No command stream is a perfectly good subscriber: one
                    // that only listens never opens one.
                    Ok(None) => break,
                    Err(error) => {
                        tracing::debug!(subject, %error, "a WebTransport command stream failed");
                        break;
                    }
                }
            },

            chunk = read_chunk(&mut commands), if commands.is_some() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        pending.extend_from_slice(&bytes);
                        while let Some(at) = pending.iter().position(|byte| *byte == b'\n') {
                            let line: Vec<u8> = pending.drain(..=at).collect();
                            let text = String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
                            if let Some(reply) =
                                crate::live::run_command(api, &text, &mut registered).await
                            {
                                write_line(&mut out, &reply).await?;
                            }
                        }
                    }
                    // End of the command stream: the subscriber is still
                    // listening, so only the inbound half is finished.
                    Some(Err(_)) | None => commands = None,
                }
            },
        }
    }

    crate::live::withdraw_entries(api, &registered).await;
    Ok(())
}

/// Read the next chunk of the command stream, if one is open.
async fn read_chunk(
    commands: &mut Option<h3_webtransport::stream::RecvStream<h3_quinn::RecvStream, Bytes>>,
) -> Option<Result<Bytes, h3::quic::StreamErrorIncoming>> {
    let stream = commands.as_mut()?;
    match futures_util::future::poll_fn(|cx| stream.poll_data(cx)).await {
        Ok(Some(mut buf)) => {
            let len = bytes::Buf::remaining(&buf);
            Some(Ok(bytes::Buf::copy_to_bytes(&mut buf, len)))
        }
        Ok(None) => None,
        Err(error) => Some(Err(error)),
    }
}

/// Write one newline-delimited JSON line.
///
/// Newline-delimited because a WebTransport stream is a byte stream with no
/// message boundaries: without a delimiter a reader cannot tell where one event
/// ends, and two events written back to back would arrive as one.
async fn write_line<S>(out: &mut S, line: &str) -> Result<(), h3::quic::StreamErrorIncoming>
where
    S: SendStreamUnframed<Bytes> + Unpin,
{
    let mut payload = Bytes::from(format!("{line}\n"));
    while bytes::Buf::has_remaining(&payload) {
        let _ = futures_util::future::poll_fn(|cx| out.poll_send(cx, &mut payload)).await?;
    }
    Ok(())
}
