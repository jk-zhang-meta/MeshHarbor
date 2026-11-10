// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! What a room or a message is bound to, when another module owns it.

use serde::{Deserialize, Serialize};

/// A generic pointer from a chat object to the module that owns its meaning:
/// `{module: "hive", ref: "<session id>"}` for an agent session's room, and
/// `{module: "hive", ref: "<session id>#<turn>"}` for a turn's stub message
/// (FR-90).
///
/// Chat STORES it and never interprets it — that is the whole contract. A room
/// or message with a binding is still an ordinary room or message to every
/// chat path (membership, visibility, search, export); the binding only tells
/// a client which module to ask about the rest. It is not an access control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// The owning module's id, as `meshharbor_core::graph::MODULES` spells it.
    pub module: String,
    /// What the module calls the object; opaque to chat.
    #[serde(rename = "ref")]
    pub reference: String,
}

impl Binding {
    pub fn new(module: &str, reference: impl Into<String>) -> Self {
        Self {
            module: module.to_string(),
            reference: reference.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stored and wire spelling is `{module, ref}` — `ref` is a Rust
    /// keyword, so the field is renamed, and the rename is the contract.
    #[test]
    fn the_stored_shape_is_module_and_ref() {
        let b = Binding::new("hive", "0123456789abcdef01234567");
        assert_eq!(
            serde_json::to_value(&b).unwrap(),
            serde_json::json!({"module": "hive", "ref": "0123456789abcdef01234567"})
        );
        let doc = bson::to_document(&b).unwrap();
        assert_eq!(doc.get_str("ref").unwrap(), "0123456789abcdef01234567");
    }
}
