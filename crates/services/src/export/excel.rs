// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::oid::ObjectId;
use meshharbor_db::models::{Message, User};
use rust_xlsxwriter::{Format, Workbook};
use std::collections::HashMap;

/// Export conversation messages to an Excel file.
/// Full implementation in Phase 9.
pub fn export_conversation(
    messages: &[Message],
    users: &HashMap<ObjectId, User>,
) -> Result<Vec<u8>, rust_xlsxwriter::XlsxError> {
    let mut workbook = Workbook::new();
    let worksheet = workbook.add_worksheet();

    // Header format
    let header_format = Format::new().set_bold();

    // Headers
    worksheet.write_string_with_format(0, 0, "Timestamp", &header_format)?;
    worksheet.write_string_with_format(0, 1, "Author", &header_format)?;
    worksheet.write_string_with_format(0, 2, "Message", &header_format)?;
    worksheet.write_string_with_format(0, 3, "Type", &header_format)?;
    worksheet.write_string_with_format(0, 4, "Reactions", &header_format)?;

    // Set column widths
    worksheet.set_column_width(0, 20)?;
    worksheet.set_column_width(1, 20)?;
    worksheet.set_column_width(2, 60)?;
    worksheet.set_column_width(3, 15)?;
    worksheet.set_column_width(4, 20)?;

    for (i, msg) in messages.iter().enumerate() {
        let row = (i + 1) as u32;
        let timestamp = msg
            .created_at
            .to_chrono()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        // FR-90 — an agent's turn carries its own name; a user's comes from users.
        let author = msg
            .agent_display()
            .or_else(|| users.get(&msg.author_id).map(|u| u.display_name.as_str()))
            .unwrap_or("Unknown");

        worksheet.write_string(row, 0, &timestamp)?;
        worksheet.write_string(row, 1, author)?;
        worksheet.write_string(row, 2, &msg.content)?;
        worksheet.write_string(row, 3, format!("{:?}", msg.message_type))?;

        let reactions: String = msg
            .reaction_summary
            .iter()
            .map(|r| format!("{} {}", r.emoji, r.count))
            .collect::<Vec<_>>()
            .join(", ");
        worksheet.write_string(row, 4, &reactions)?;
    }

    workbook.save_to_buffer()
}
