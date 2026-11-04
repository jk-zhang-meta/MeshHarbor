// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use bson::oid::ObjectId;
use meshharbor_db::models::{Message, User};
use std::collections::HashMap;
use std::io::Write;

/// Export conversation messages to a simple PDF.
/// Uses raw PDF generation (no external font files needed).
pub fn export_conversation(
    messages: &[Message],
    users: &HashMap<ObjectId, User>,
) -> Result<Vec<u8>, String> {
    let mut pdf = SimplePdf::new();

    pdf.add_text("Conversation Export", 16.0, true);
    pdf.add_text("", 10.0, false); // blank line

    for msg in messages {
        // FR-90 — an agent's turn carries its own name; a user's comes from users.
        let author = msg
            .agent_display()
            .or_else(|| users.get(&msg.author_id).map(|u| u.display_name.as_str()))
            .unwrap_or("Unknown");
        let timestamp = msg
            .created_at
            .to_chrono()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        pdf.add_text(&format!("[{}] {}", timestamp, author), 9.0, true);
        pdf.add_text(&msg.content, 10.0, false);

        if !msg.reaction_summary.is_empty() {
            let reactions: String = msg
                .reaction_summary
                .iter()
                .map(|r| format!("{} {}", r.emoji, r.count))
                .collect::<Vec<_>>()
                .join("  ");
            pdf.add_text(&format!("Reactions: {}", reactions), 8.0, false);
        }

        pdf.add_text("", 6.0, false);
    }

    pdf.render()
}

/// Minimal PDF generator using built-in Helvetica font.
/// Produces valid PDF 1.4 without external dependencies.
struct SimplePdf {
    lines: Vec<PdfLine>,
}

struct PdfLine {
    text: String,
    font_size: f64,
    bold: bool,
}

impl SimplePdf {
    fn new() -> Self {
        Self { lines: Vec::new() }
    }

    fn add_text(&mut self, text: &str, font_size: f64, bold: bool) {
        self.lines.push(PdfLine {
            text: text.to_string(),
            font_size,
            bold,
        });
    }

    fn escape_pdf_string(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('(', "\\(")
            .replace(')', "\\)")
            // Strip non-ASCII for basic PDF compatibility
            .chars()
            .filter(|c| c.is_ascii())
            .collect()
    }

    fn render(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();

        // PDF header
        writeln!(buf, "%PDF-1.4").unwrap();
        // Binary comment to mark as binary PDF
        buf.extend_from_slice(&[b'%', 0xE2, 0xE3, 0xCF, 0xD3, b'\n']);

        // Track object offsets
        let mut offsets: Vec<usize> = Vec::new();

        // Obj 1: Catalog
        offsets.push(buf.len());
        write!(buf, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n").unwrap();

        // Obj 2: Pages
        offsets.push(buf.len());
        write!(
            buf,
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        )
        .unwrap();

        // Build the content stream
        let mut stream = String::new();
        stream.push_str("BT\n");

        let page_height = 792.0; // Letter size
        let margin_top = 50.0;
        let margin_left = 50.0;
        let line_height_factor = 1.4;
        let mut y = page_height - margin_top;

        for line in &self.lines {
            if line.text.is_empty() {
                y -= line.font_size * line_height_factor;
                continue;
            }

            let font_ref = if line.bold { "/F2" } else { "/F1" };
            stream.push_str(&format!("{} {} Tf\n", font_ref, line.font_size));
            stream.push_str(&format!("{} {} Td\n", margin_left, y));
            stream.push_str(&format!("({}) Tj\n", Self::escape_pdf_string(&line.text)));

            y -= line.font_size * line_height_factor;

            // Reset position for next absolute positioning
            stream.push_str(&format!("{} {} Td\n", -margin_left, -y));
        }

        stream.push_str("ET\n");

        let stream_bytes = stream.as_bytes();

        // Obj 3: Page
        offsets.push(buf.len());
        write!(
            buf,
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>\nendobj\n"
        )
        .unwrap();

        // Obj 4: Content stream
        offsets.push(buf.len());
        write!(
            buf,
            "4 0 obj\n<< /Length {} >>\nstream\n",
            stream_bytes.len()
        )
        .unwrap();
        buf.extend_from_slice(stream_bytes);
        write!(buf, "\nendstream\nendobj\n").unwrap();

        // Obj 5: Helvetica font
        offsets.push(buf.len());
        write!(
            buf,
            "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        )
        .unwrap();

        // Obj 6: Helvetica-Bold font
        offsets.push(buf.len());
        write!(
            buf,
            "6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n"
        )
        .unwrap();

        // Cross-reference table
        let xref_start = buf.len();
        write!(buf, "xref\n0 {}\n", offsets.len() + 1).unwrap();
        writeln!(buf, "0000000000 65535 f ").unwrap();
        for offset in &offsets {
            writeln!(buf, "{:010} 00000 n ", offset).unwrap();
        }

        // Trailer
        write!(
            buf,
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            offsets.len() + 1,
            xref_start
        )
        .unwrap();

        Ok(buf)
    }
}
