//! Voice messages: recorded clips sent into chat as files.
//!
//! A clip is an ordinary upload with a [`VoiceClip`] attached, so everything
//! after the grant (the signed `PUT`, the share announcement, retention) is the
//! file path unchanged. What differs is who may start one. A clip is checked
//! against the operator's `allow_voice_messages`, `voice_message_max_seconds`
//! and `voice_message_max_bytes`, and against the `SendVoiceMessage` bit rather
//! than `ShareFiles`, so a server can have voice notes without arbitrary
//! uploads.
//!
//! The settings are also *announced*, because a recorder has to know its
//! ceiling before the take rather than be refused after it: once on request
//! ([`VoiceSupportQuery`]) and again to everyone whenever one of them changes.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use prost::Message as _;
use starling_proto_fancy::fancy::files::{
    FilesEnvelope, UploadRequest, Visibility, VoiceClip, VoiceSupport, files_envelope,
};
use starling_proto_fancy::fancy::wire::refusal;
use starling_proto_fancy::perm::Perm;
use starling_proto_fancy::serverconfig::Snapshot;
use starling_proto_fancy::types::ServiceKind;
use starling_runtime::log::{Category, LogEvent};
use starling_runtime::plane::{Inbound, to_sessions};

use crate::{FilesService, refused};

/// How far past the ceiling a clip's stated duration may run.
///
/// A recorder that stops itself at the limit still hands over the last frame
/// it had started, and a clip refused for twenty milliseconds after two
/// minutes of talking is the recorder's fault in nobody's eyes but the server's.
const DURATION_GRACE_MS: u64 = 1_000;

/// The byte ceiling a clip meets: the voice cap, or the upload ceiling if that
/// is lower. Zero only if both are, which `max_upload` never is.
fn byte_ceiling(settings: &Snapshot, max_upload: u64) -> u64 {
    match u64::from(settings.voice_message_max_bytes) {
        0 => max_upload,
        cap if max_upload == 0 => cap,
        cap => cap.min(max_upload),
    }
}

impl FilesService {
    /// What this server says about voice clips to `scope`'s members.
    pub(crate) fn voice_support(&self, scope: u32, request_id: &str) -> FilesEnvelope {
        let settings = self.settings.get(scope);
        FilesEnvelope {
            body: Some(files_envelope::Body::VoiceSupport(VoiceSupport {
                request_id: request_id.to_owned(),
                available: settings.allow_voice_messages,
                max_seconds: settings.voice_message_max_seconds,
                max_bytes: byte_ceiling(&settings, self.max_upload()),
            })),
        }
    }

    /// Tell everyone connected what voice clips may be now.
    pub(crate) fn broadcast_voice_support(&self, scope: u32) {
        let sessions = self.roster.sessions();
        if sessions.is_empty() {
            return;
        }
        self.fanout.push(to_sessions(
            sessions,
            ServiceKind::Files.outer_type(),
            self.voice_support(scope, "").encode_to_vec(),
        ));
    }

    /// Push the voice settings again each time the operator changes them.
    ///
    /// A lagged subscriber has missed nothing that matters: the announcement
    /// is built from the settings as they are when it is sent, so one late
    /// push says what every missed one would have.
    pub(crate) async fn follow_voice_settings(
        self: Arc<Self>,
        mut changes: tokio::sync::broadcast::Receiver<u32>,
    ) {
        use tokio::sync::broadcast::error::RecvError;
        loop {
            match changes.recv().await {
                Ok(scope) => self.broadcast_voice_support(scope),
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => break,
            }
        }
    }

    /// The refusal for this upload as a voice clip, or `None` to let it go on.
    ///
    /// Checked in the order a person could act on: the server's switch first,
    /// because nothing else matters if it is off, then the channel's bit, then
    /// the two limits.
    pub(crate) async fn voice_clip_refusal(
        &self,
        inbound: &Inbound,
        upload: &UploadRequest,
        clip: &VoiceClip,
    ) -> Option<FilesEnvelope> {
        let settings = self.settings.get(inbound.scope);
        let refuse =
            |kind: refusal::Kind, detail: &str| Some(refused(&upload.request_id, kind, detail));

        if !settings.allow_voice_messages {
            // PERMISSION rather than LIMIT: no smaller clip would get through.
            return refuse(
                refusal::Kind::Permission,
                "voice messages are turned off on this server",
            );
        }
        // Session only. `SendVoiceMessage` stands in for `ShareFiles` and for
        // nothing else, so a clip must not become the way round
        // `ShareFilesPublic`.
        if Visibility::try_from(upload.visibility).unwrap_or(Visibility::Session)
            != Visibility::Session
        {
            return refuse(
                refusal::Kind::Invalid,
                "a voice message is shared with the channel, not by link",
            );
        }
        if !upload.content_type.starts_with("audio/") {
            return refuse(refusal::Kind::Invalid, "a voice message is audio");
        }
        if !self
            .allows(inbound, upload.channel, Perm::SEND_VOICE_MESSAGE)
            .await
        {
            self.logger.log(
                LogEvent::notice(Category::Permission, "voice message refused: not allowed")
                    .with("channel", upload.channel)
                    .with("session", inbound.session),
            );
            return refuse(
                refusal::Kind::Permission,
                "you may not send voice messages here",
            );
        }
        let max_seconds = u64::from(settings.voice_message_max_seconds);
        if max_seconds > 0 && u64::from(clip.duration_ms) > max_seconds * 1_000 + DURATION_GRACE_MS
        {
            return refuse(
                refusal::Kind::Limit,
                &format!("a voice message may be at most {max_seconds} seconds"),
            );
        }
        let ceiling = byte_ceiling(&settings, self.max_upload.load(Ordering::Relaxed));
        if ceiling > 0 && upload.size > ceiling {
            return refuse(
                refusal::Kind::Limit,
                &format!("a voice message may be at most {ceiling} bytes"),
            );
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{ask, service_with_settings};
    use starling_runtime::settings::defaults;

    fn clip(duration_ms: u32, size: u64) -> UploadRequest {
        UploadRequest {
            request_id: "v1".to_owned(),
            channel: 3,
            filename: "voice-message.ogg".to_owned(),
            content_type: "audio/ogg".to_owned(),
            size,
            voice: Some(VoiceClip { duration_ms }),
            ..UploadRequest::default()
        }
    }

    fn refusal_of(envelope: &FilesEnvelope) -> Option<(refusal::Kind, String)> {
        match &envelope.body {
            Some(files_envelope::Body::Refused(refused)) => refused.refusal.as_ref().map(|r| {
                (
                    refusal::Kind::try_from(r.kind).unwrap_or(refusal::Kind::Other),
                    r.detail.clone(),
                )
            }),
            _ => None,
        }
    }

    fn is_grant(envelope: &FilesEnvelope) -> bool {
        matches!(envelope.body, Some(files_envelope::Body::Grant(_)))
    }

    #[tokio::test]
    async fn a_clip_needs_the_voice_bit_and_not_share_files() {
        // The point of the separate bit: a server that lets its members leave
        // voice notes has not thereby let them upload whatever they like.
        let service =
            service_with_settings(Perm::SEND_VOICE_MESSAGE | Perm::ENTER, defaults(1)).await;
        assert!(is_grant(&ask(&service, clip(5_000, 512)).await));

        let plain_file = UploadRequest {
            voice: None,
            ..clip(5_000, 512)
        };
        let (kind, _) = refusal_of(&ask(&service, plain_file).await).expect("refused");
        assert_eq!(kind, refusal::Kind::Permission);
    }

    #[tokio::test]
    async fn share_files_alone_does_not_buy_a_voice_message() {
        let service = service_with_settings(Perm::SHARE_FILES | Perm::ENTER, defaults(1)).await;
        let (kind, detail) = refusal_of(&ask(&service, clip(5_000, 512)).await).expect("refused");
        assert_eq!(kind, refusal::Kind::Permission);
        assert!(detail.contains("voice"), "{detail}");
    }

    #[tokio::test]
    async fn a_server_with_voice_messages_off_refuses_every_clip() {
        let settings = Snapshot {
            allow_voice_messages: false,
            ..defaults(1)
        };
        let service = service_with_settings(Perm::SEND_VOICE_MESSAGE, settings).await;
        let (kind, detail) = refusal_of(&ask(&service, clip(1_000, 64)).await).expect("refused");
        assert_eq!(kind, refusal::Kind::Permission);
        assert!(detail.contains("turned off"), "{detail}");
    }

    #[tokio::test]
    async fn a_clip_longer_than_the_operator_allows_is_refused_with_the_limit() {
        let settings = Snapshot {
            voice_message_max_seconds: 10,
            ..defaults(1)
        };
        let service = service_with_settings(Perm::SEND_VOICE_MESSAGE, settings).await;
        // The last frame a recorder had started is not a violation.
        assert!(is_grant(&ask(&service, clip(10_400, 64)).await));
        let (kind, detail) = refusal_of(&ask(&service, clip(12_000, 64)).await).expect("refused");
        assert_eq!(kind, refusal::Kind::Limit);
        assert!(detail.contains("10 seconds"), "{detail}");
    }

    #[tokio::test]
    async fn a_clip_larger_than_the_voice_cap_is_refused_below_the_upload_ceiling() {
        // The test service's `max_upload` is 1024 bytes.
        let settings = Snapshot {
            voice_message_max_bytes: 100,
            ..defaults(1)
        };
        let service = service_with_settings(Perm::SEND_VOICE_MESSAGE, settings).await;
        let (kind, detail) = refusal_of(&ask(&service, clip(1_000, 200)).await).expect("refused");
        assert_eq!(kind, refusal::Kind::Limit);
        assert!(detail.contains("100 bytes"), "{detail}");
    }

    #[tokio::test]
    async fn a_clip_cannot_be_the_way_round_share_files_public() {
        let service = service_with_settings(Perm::SEND_VOICE_MESSAGE, defaults(1)).await;
        let public = UploadRequest {
            visibility: Visibility::Public as i32,
            ..clip(1_000, 64)
        };
        let (kind, _) = refusal_of(&ask(&service, public).await).expect("refused");
        assert_eq!(kind, refusal::Kind::Invalid);
    }

    #[tokio::test]
    async fn a_clip_that_is_not_audio_is_refused() {
        let service = service_with_settings(Perm::SEND_VOICE_MESSAGE, defaults(1)).await;
        let picture = UploadRequest {
            content_type: "image/png".to_owned(),
            ..clip(1_000, 64)
        };
        let (kind, _) = refusal_of(&ask(&service, picture).await).expect("refused");
        assert_eq!(kind, refusal::Kind::Invalid);
    }

    #[tokio::test]
    async fn support_states_the_smaller_of_the_two_byte_ceilings() {
        let settings = Snapshot {
            voice_message_max_seconds: 30,
            voice_message_max_bytes: 4 * 1024 * 1024,
            ..defaults(1)
        };
        let service = service_with_settings(Perm::empty(), settings).await;
        let Some(files_envelope::Body::VoiceSupport(support)) = service.voice_support(1, "q").body
        else {
            panic!("a support answer");
        };
        assert!(support.available);
        assert_eq!(support.request_id, "q");
        assert_eq!(support.max_seconds, 30);
        // `max_upload` is 1024 in the test service, below the voice cap.
        assert_eq!(support.max_bytes, 1024);
    }

    #[tokio::test]
    async fn a_changed_setting_is_pushed_to_everyone_connected() {
        // A recorder already on screen has to learn its new ceiling without a
        // reconnect, so the push goes to every session, unasked.
        use starling_proto_fancy::control::server_action::Action;
        use starling_proto_fancy::sessionview::Session;

        let service = service_with_settings(Perm::empty(), defaults(1)).await;
        service.roster.replace(vec![
            Session {
                session: 7,
                conn: 100,
                ..Default::default()
            },
            Session {
                session: 9,
                conn: 101,
                ..Default::default()
            },
        ]);
        let mut pushed = service.fanout.subscribe();
        let (changes, heard) = tokio::sync::broadcast::channel(4);
        let follower = tokio::spawn(Arc::clone(&service).follow_voice_settings(heard));
        let _ = changes.send(1);

        let action = tokio::time::timeout(std::time::Duration::from_secs(5), pushed.recv())
            .await
            .expect("a push within the timeout")
            .expect("the fanout is open");
        follower.abort();
        let Some(Action::Send(sent)) = action.action else {
            panic!("a push is a send");
        };
        let mut sessions = sent.sessions.clone();
        sessions.sort_unstable();
        assert_eq!(sessions, vec![7, 9]);
        let Some(files_envelope::Body::VoiceSupport(support)) =
            FilesEnvelope::decode(sent.payload.as_slice())
                .expect("a files envelope")
                .body
        else {
            panic!("a voice support push");
        };
        assert!(
            support.request_id.is_empty(),
            "a push answers nobody's question"
        );
        assert!(support.available);
    }

    #[test]
    fn a_voice_cap_of_zero_leaves_only_the_upload_ceiling() {
        let settings = Snapshot {
            voice_message_max_bytes: 0,
            ..defaults(1)
        };
        assert_eq!(byte_ceiling(&settings, 5_000), 5_000);
        let settings = Snapshot {
            voice_message_max_bytes: 300,
            ..defaults(1)
        };
        assert_eq!(byte_ceiling(&settings, 5_000), 300);
    }
}
