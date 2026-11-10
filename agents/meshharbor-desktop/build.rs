// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// Tauri build script. Generates Tauri-runtime bindings + bundles
// front-end assets per `tauri.conf.json`. Required entry point — the
// macros in main.rs depend on the artifacts this produces.
//
// Also emits placeholder icon files (`icons/icon.ico`, `icons/icon.png`,
// `icons/tray.png`) at build time if absent. Tauri's Windows-resource
// generation insists on a valid `icon.ico` and the bundler wants the
// PNG; rather than commit binary blobs to the repo, generate minimal
// 1×1 placeholders here. The release-agent.yml CI pipeline overrides
// these with the real branded icons before invoking `cargo tauri build`
// for the production MSI/.pkg artifacts.

use std::fs;
use std::path::Path;

// Minimal 1×1 ARGB ICO. Header + directory entry + BITMAPINFOHEADER +
// 4 bytes BGRA pixel + 4 bytes AND mask. Tauri's tauri-winres only
// needs the file to parse as a valid ICO; visual content irrelevant
// for dev builds.
const PLACEHOLDER_ICO: &[u8] = &[
    // ICO header: reserved=0, type=1 (icon), count=1
    0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
    // Directory entry: 1×1, 0 colours, reserved=0, planes=1, bpp=32,
    // size=40+8 = 48 bytes, offset=22 (after the directory)
    0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x30, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00,
    // BITMAPINFOHEADER (40 bytes): size=40, w=1, h=2 (1 image + 1
    // AND-mask), planes=1, bpp=32, compression=0, sizeimage=0,
    // x/y pixels per metre=0, clrUsed=0, clrImportant=0
    0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // XOR image: 1 pixel BGRA = solid blue, alpha 0xFF
    0xD2, 0x76, 0x19, 0xFF, // AND mask: 4 bytes (1 row, padded to 32-bit alignment) = 0
    0x00, 0x00, 0x00, 0x00,
];

// Minimal 1×1 transparent PNG (67 bytes). Standard test fixture
// — same as what the W3C "transparent.png" reference image uses.
const PLACEHOLDER_PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x62, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

fn write_if_missing(path: &Path, bytes: &[u8]) {
    if !path.exists()
        && let Some(parent) = path.parent()
    {
        let _ = fs::create_dir_all(parent);
    }
    if !path.exists() {
        let _ = fs::write(path, bytes);
    }
}

fn main() {
    write_if_missing(Path::new("icons/icon.ico"), PLACEHOLDER_ICO);
    write_if_missing(Path::new("icons/icon.png"), PLACEHOLDER_PNG);
    write_if_missing(Path::new("icons/tray.png"), PLACEHOLDER_PNG);
    // FR-85 — the tray's two icons are embedded by `tauri::include_image!`
    // (tray.rs), which cargo cannot see as inputs: without these a
    // regenerated icon ships its old pixels on an incremental build.
    // (tauri-build emits its own `rerun-if-changed` lines, so these only add
    // to the list.)
    println!("cargo:rerun-if-changed=icons/tray.png");
    println!("cargo:rerun-if-changed=icons/tray-recording.png");
    tauri_build::build()
}
