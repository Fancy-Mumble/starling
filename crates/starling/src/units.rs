//! The table of what this binary can be.
//!
//! One entry per service, and the only place the concrete service types are
//! named. Everything below this file depends on the `Serve` trait and nothing
//! else — which is what makes the composition swappable without a service
//! knowing it has been composed.

use starling_runtime::serve::{ServiceContext, ServiceError};

// Used by the test below, which is the only thing in this binary that needs the
// protocol's own view of which services exist.
use starling_proto_fancy as _;

/// Start one service by name.
///
/// Returns `None` when nothing answers to that name, so the caller can print
/// the list rather than guess.
pub(crate) fn spawn(
    name: &str,
    ctx: ServiceContext,
) -> Option<tokio::task::JoinHandle<Result<(), ServiceError>>> {
    use starling_runtime::serve::spawn;
    Some(match name {
        "session-lifecycle" => spawn::<starling_session_lifecycle::SessionLifecycleService>(ctx),
        "session-view" => spawn::<starling_session_view::SessionViewService>(ctx),
        "permissions" => spawn::<starling_permissions::PermissionsService>(ctx),
        "metadata" => spawn::<starling_metadata::MetadataService>(ctx),
        "userdata" => spawn::<starling_userdata::UserdataService>(ctx),
        "server-config" => spawn::<starling_server_config::ServerConfigService>(ctx),
        "voice" => spawn::<starling_voice::VoiceService>(ctx),
        "text" => spawn::<starling_text::TextService>(ctx),
        "pchat" => spawn::<starling_pchat::PchatService>(ctx),
        "moderation" => spawn::<starling_moderation::ModerationService>(ctx),
        "screenshare" => spawn::<starling_screenshare::ScreenshareService>(ctx),
        "files" => spawn::<starling_files::FilesService>(ctx),
        "plugins" => spawn::<starling_plugins::PluginsService>(ctx),
        "push" => spawn::<starling_push::PushService>(ctx),
        "audit" => spawn::<starling_audit::AuditService>(ctx),
        "onboarding" => spawn::<starling_onboarding::OnboardingService>(ctx),
        "social" => spawn::<starling_social::SocialService>(ctx),
        "link-preview" => spawn::<starling_link_preview::LinkPreviewService>(ctx),
        "context-actions" => spawn::<starling_context_actions::ContextActionsService>(ctx),
        "directory" => spawn::<starling_directory::DirectoryService>(ctx),
        "operator-api" => spawn::<starling_operator_api::OperatorApi>(ctx),
        "gateway" => spawn::<starling_gateway::GatewayService>(ctx),
        _ => return None,
    })
}

/// Every service this binary can be, in tier order.
#[must_use]
pub(crate) fn names() -> &'static [&'static str] {
    &[
        "session-lifecycle",
        "session-view",
        "permissions",
        "metadata",
        "userdata",
        "server-config",
        "voice",
        "text",
        "pchat",
        "moderation",
        "screenshare",
        "files",
        "plugins",
        "push",
        "audit",
        "onboarding",
        "social",
        "link-preview",
        "context-actions",
        // No wire type and no gRPC surface: nothing calls it, it calls out.
        "directory",
        "operator-api",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::ServiceKind;

    #[test]
    fn every_service_with_an_outer_type_can_be_started() {
        // A service the protocol allocates a type to but the binary cannot run
        // is a routing table entry that never answers.
        for kind in ServiceKind::all() {
            assert!(
                names().contains(&kind.name()),
                "{} cannot be started by name",
                kind.name()
            );
        }
    }
}
