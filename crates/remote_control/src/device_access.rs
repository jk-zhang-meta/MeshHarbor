// SPDX-License-Identifier: MPL-2.0
//! Capabilities selected by the person accepting a device invitation.
//! Missing bits never grant access. This is a ceiling, not a service switch.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeviceAccessFeatures {
    pub desktop_view: bool,
    pub desktop_control: bool,
    pub clipboard: bool,
    pub files: bool,
    pub ssh: bool,
    pub exec: bool,
    pub rdp: bool,
    pub network: bool,
}

impl DeviceAccessFeatures {
    pub const fn none() -> Self {
        Self {
            desktop_view: false,
            desktop_control: false,
            clipboard: false,
            files: false,
            ssh: false,
            exec: false,
            rdp: false,
            network: false,
        }
    }

    pub const fn all() -> Self {
        Self {
            desktop_view: true,
            desktop_control: true,
            clipboard: true,
            files: true,
            ssh: true,
            exec: true,
            rdp: true,
            network: true,
        }
    }

    pub const fn valid(self) -> bool {
        (!self.desktop_control || self.desktop_view) && (!self.clipboard || self.desktop_view)
    }

    pub fn permits_session(self, requested: crate::permissions::Permissions) -> bool {
        use crate::permissions::Permissions as P;
        (!requested.intersects(P::VIEW | P::AUDIO | P::RECORD) || self.desktop_view)
            && (!requested.intersects(P::INPUT | P::PRIVACY) || self.desktop_control)
            && (!requested.contains(P::CLIPBOARD) || self.clipboard)
            && (!requested.contains(P::FILES) || self.files)
    }

    pub const fn allows(self, feature: DeviceAccessFeature) -> bool {
        match feature {
            DeviceAccessFeature::DesktopView => self.desktop_view,
            DeviceAccessFeature::DesktopControl => self.desktop_control,
            DeviceAccessFeature::Clipboard => self.clipboard,
            DeviceAccessFeature::Files => self.files,
            DeviceAccessFeature::Ssh => self.ssh,
            DeviceAccessFeature::Exec => self.exec,
            DeviceAccessFeature::Rdp => self.rdp,
            DeviceAccessFeature::Network => self.network,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAccessFeature {
    DesktopView,
    DesktopControl,
    Clipboard,
    Files,
    Ssh,
    Exec,
    Rdp,
    Network,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_feature_is_an_independent_allow_and_deny() {
        let fields = [
            "desktop_view",
            "desktop_control",
            "clipboard",
            "files",
            "ssh",
            "exec",
            "rdp",
            "network",
        ];
        let features = [
            DeviceAccessFeature::DesktopView,
            DeviceAccessFeature::DesktopControl,
            DeviceAccessFeature::Clipboard,
            DeviceAccessFeature::Files,
            DeviceAccessFeature::Ssh,
            DeviceAccessFeature::Exec,
            DeviceAccessFeature::Rdp,
            DeviceAccessFeature::Network,
        ];
        for (index, field) in fields.iter().enumerate() {
            let mut value = serde_json::to_value(DeviceAccessFeatures::none()).unwrap();
            value[*field] = serde_json::json!(true);
            let selected: DeviceAccessFeatures = serde_json::from_value(value).unwrap();
            for (other, feature) in features.iter().enumerate() {
                assert_eq!(
                    selected.allows(*feature),
                    index == other,
                    "{field} vs {feature:?}"
                );
                assert!(DeviceAccessFeatures::all().allows(*feature));
                assert!(!DeviceAccessFeatures::none().allows(*feature));
            }
        }
    }

    #[test]
    fn partial_selection_never_grants_unspecified_features() {
        let selected: DeviceAccessFeatures = serde_json::from_str(r#"{"ssh":true}"#).unwrap();
        assert!(selected.ssh);
        assert!(!selected.exec && !selected.files && !selected.network);
        assert_eq!(
            serde_json::from_str::<DeviceAccessFeatures>("{}").unwrap(),
            DeviceAccessFeatures::none()
        );
        assert!(
            serde_json::from_str::<DeviceAccessFeatures>(r#"{"ssh":true,"admin":true}"#).is_err()
        );
    }
    #[test]
    fn control_and_clipboard_require_view() {
        assert!(DeviceAccessFeatures::all().valid());
        assert!(DeviceAccessFeatures::none().valid());
        assert!(
            !DeviceAccessFeatures {
                desktop_control: true,
                ..DeviceAccessFeatures::none()
            }
            .valid()
        );
        assert!(
            !DeviceAccessFeatures {
                clipboard: true,
                ..DeviceAccessFeatures::none()
            }
            .valid()
        );
    }
}

/// One host-selected grant; identity and capabilities must stay paired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceFeatureGrant {
    #[serde(default)]
    pub access_until_ms: Option<u64>,
    pub inviter_user_id: bson::oid::ObjectId,
    pub allow_role_ids: Vec<bson::oid::ObjectId>,
    pub features: Option<DeviceAccessFeatures>,
}
