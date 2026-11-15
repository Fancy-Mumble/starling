//! How a group looks as a role: the Fancy fields of `ACL.ChanGroup`
//! (1000-1003), carried between the wire and the stored set.
//!
//! The evaluator never reads them. They are kept because a role editor saves
//! the whole table and reads it back, and murmur's fork stores them with the
//! group (`vendor/server/src/murmur/Messages.cpp:2869`, sent back at `:2791`).
//! An unset field stays absent on the wire, as murmur sends it, so a classic
//! client reads a styled role exactly as an unstyled one.

use starling_proto::proto::tcp::acl::{ChanGroup, chan_group::KeyValue};
use starling_proto_fancy::permissions::{AclSet, RoleMetadata, RolePresentation};
use starling_runtime::over_limit;

/// What `group` says about its looks, or `None` when it says nothing.
#[must_use]
pub fn from_wire(group: &ChanGroup) -> Option<RolePresentation> {
    let presentation = RolePresentation {
        color: group.color.clone().unwrap_or_default(),
        icon: group.icon.clone().unwrap_or_default(),
        style_preset: group.style_preset.clone().unwrap_or_default(),
        metadata: group
            .metadata
            .iter()
            .map(|pair| RoleMetadata {
                key: pair.key.clone(),
                value: pair.value.clone().unwrap_or_default(),
            })
            .collect(),
    };
    (presentation != RolePresentation::default()).then_some(presentation)
}

/// Put `presentation` on `group`, leaving every empty field absent.
pub fn to_wire(presentation: Option<&RolePresentation>, group: &mut ChanGroup) {
    let Some(presentation) = presentation else {
        return;
    };
    let set = |text: &str| (!text.is_empty()).then(|| text.to_owned());
    group.color = set(&presentation.color);
    group.style_preset = set(&presentation.style_preset);
    group.icon = (!presentation.icon.is_empty()).then(|| presentation.icon.clone());
    group.metadata = presentation
        .metadata
        .iter()
        .map(|pair| KeyValue {
            key: pair.key.clone(),
            value: Some(pair.value.clone()),
        })
        .collect();
}

/// Drop every role icon in `set` longer than `limit` bytes, returning the
/// names of the roles that lost one.
///
/// murmur refuses such an icon against `imagemessagelength`
/// (`Messages.cpp:2873`) and keeps the rest of the group; so does this.
pub fn drop_oversized_icons(set: &mut AclSet, limit: u32) -> Vec<String> {
    let mut dropped = Vec::new();
    for group in &mut set.groups {
        let Some(presentation) = group.presentation.as_mut() else {
            continue;
        };
        if over_limit(presentation.icon.len(), limit) {
            presentation.icon.clear();
            dropped.push(group.name.clone());
        }
    }
    dropped
}

#[cfg(test)]
mod tests {
    use super::*;
    use starling_proto_fancy::permissions::Group;

    fn with_icon(bytes: usize) -> AclSet {
        AclSet {
            groups: vec![Group {
                name: "crew".to_owned(),
                presentation: Some(RolePresentation {
                    color: "#3f9fd8".to_owned(),
                    icon: vec![1; bytes],
                    ..RolePresentation::default()
                }),
                ..Group::default()
            }],
            ..AclSet::default()
        }
    }

    #[test]
    fn an_icon_over_the_image_limit_is_dropped_and_the_rest_of_the_role_kept() {
        let mut set = with_icon(10);
        assert_eq!(drop_oversized_icons(&mut set, 9), ["crew"]);
        let kept = set.groups[0].presentation.as_ref().expect("still styled");
        assert!(kept.icon.is_empty());
        assert_eq!(kept.color, "#3f9fd8");
    }

    #[test]
    fn an_icon_within_the_limit_or_with_no_limit_is_kept() {
        let mut set = with_icon(10);
        assert!(drop_oversized_icons(&mut set, 10).is_empty());
        assert!(
            drop_oversized_icons(&mut set, 0).is_empty(),
            "zero is no limit"
        );
        assert_eq!(
            set.groups[0].presentation.as_ref().map(|p| p.icon.len()),
            Some(10)
        );
    }

    #[test]
    fn a_metadata_key_with_no_value_reads_back_as_an_empty_one() {
        // murmur stores an absent value as an empty string (`Messages.cpp:2893`).
        let group = ChanGroup {
            name: "crew".to_owned(),
            metadata: vec![KeyValue {
                key: "badge".to_owned(),
                value: None,
            }],
            ..ChanGroup::default()
        };
        let mut read = ChanGroup::default();
        to_wire(from_wire(&group).as_ref(), &mut read);
        assert_eq!(read.metadata[0].value.as_deref(), Some(""));
    }
}
