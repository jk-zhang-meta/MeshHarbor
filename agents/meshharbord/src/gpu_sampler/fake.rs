// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Fake GPU backend (`MESHHARBORD_GPU_FAKE=<file>`) for deterministic testing
//! without hardware (FR-139 §3, §9).
//!
//! Accepts either:
//! - A JSONL file where each non-empty line is a [`FakeFrame`] (either a raw
//!   [`GpuReport`] or a directive `{"directive": "sleep_forever"}` /
//!   `{"directive": "exit", "code": 42}`), cycling through frames on each
//!   sample tick; OR
//! - A single JSON object (`GpuReport`) replayed on every sample tick.

use std::fs;
use std::path::Path;

use meshharbor_remote_control::gpu::{GpuInventory, GpuInventoryItem, GpuReport};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub enum FakeStep {
    Report(Box<GpuReport>),
    SleepForever,
    Exit(i32),
}

#[derive(Debug, Deserialize)]
struct Directive {
    directive: String,
    #[serde(default)]
    code: i32,
}

pub struct FakeBackend {
    steps: Vec<FakeStep>,
    cursor: usize,
}

impl FakeBackend {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)?;
        let trimmed = raw.trim();
        let mut steps = Vec::new();

        // Try whole-file single JSON first if it starts with `{` and parses cleanly.
        if trimmed.starts_with('{')
            && let Ok(step) = parse_line(trimmed)
        {
            steps.push(step);
        } else {
            for line in trimmed.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                steps.push(parse_line(line)?);
            }
        }

        if steps.is_empty() {
            anyhow::bail!("fake GPU fixture {} contained no frames", path.display());
        }

        Ok(Self { steps, cursor: 0 })
    }

    pub fn inventory(&self) -> Option<GpuInventory> {
        for step in &self.steps {
            if let FakeStep::Report(r) = step {
                return Some(inventory_from_report(r));
            }
        }
        None
    }

    pub fn next_step(&mut self) -> FakeStep {
        let step = self.steps[self.cursor].clone();
        if self.cursor + 1 < self.steps.len() {
            self.cursor += 1;
        }
        step
    }
}

fn parse_line(line: &str) -> anyhow::Result<FakeStep> {
    if let Ok(d) = serde_json::from_str::<Directive>(line) {
        match d.directive.as_str() {
            "sleep_forever" => return Ok(FakeStep::SleepForever),
            "exit" => return Ok(FakeStep::Exit(if d.code == 0 { 1 } else { d.code })),
            _ => {}
        }
    }
    let report: GpuReport = serde_json::from_str(line)?;
    Ok(FakeStep::Report(Box::new(report)))
}

pub fn inventory_from_report(r: &GpuReport) -> GpuInventory {
    GpuInventory {
        backend: r.backend.clone().or_else(|| Some("fake".into())),
        driver_version: r.driver_version.clone(),
        gpus: r
            .gpus
            .iter()
            .map(|g| GpuInventoryItem {
                uuid: g.uuid.clone(),
                idx: g.idx,
                name: g.name.clone().unwrap_or_else(|| format!("GPU {}", g.idx)),
                mem_total_mb: g.mem_total_mb,
                power_limit_w: g.power_limit_w,
                mig: g.mig,
                pci_bus: g.pci_bus.clone(),
                unified: g.unified,
            })
            .collect(),
        status: r.status,
    }
}
