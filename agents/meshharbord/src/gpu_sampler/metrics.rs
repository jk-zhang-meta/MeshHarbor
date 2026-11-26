// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Optional loopback-only Prometheus `/metrics` endpoint for GPU telemetry
//! (FR-139 §5.1, §8).
//!
//! Strictly refuses any non-loopback address (`127.0.0.1` / `::1` only).
//! Emits aggregate per-GPU gauges only (NO process usernames or PIDs) to keep
//! Prometheus label cardinality bounded and avoid leaking local account names.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use meshharbor_remote_control::gpu::{
    GpuReport, GpuStateThresholds, classify_gpu_state,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// Format the latest [`GpuReport`] in Prometheus text exposition format 0.0.4.
pub fn format_prometheus(report: Option<&GpuReport>, now_s: i64) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str("# HELP meshharbor_gpu_utilization_ratio GPU compute utilization (0..1).\n");
    out.push_str("# TYPE meshharbor_gpu_utilization_ratio gauge\n");
    out.push_str("# HELP meshharbor_gpu_memory_used_bytes GPU memory currently used in bytes.\n");
    out.push_str("# TYPE meshharbor_gpu_memory_used_bytes gauge\n");
    out.push_str("# HELP meshharbor_gpu_memory_total_bytes GPU total memory in bytes.\n");
    out.push_str("# TYPE meshharbor_gpu_memory_total_bytes gauge\n");
    out.push_str("# HELP meshharbor_gpu_temperature_celsius GPU temperature in Celsius.\n");
    out.push_str("# TYPE meshharbor_gpu_temperature_celsius gauge\n");
    out.push_str("# HELP meshharbor_gpu_power_watts GPU power draw in watts.\n");
    out.push_str("# TYPE meshharbor_gpu_power_watts gauge\n");
    out.push_str("# HELP meshharbor_gpu_state GPU classification state (1 = active state).\n");
    out.push_str("# TYPE meshharbor_gpu_state gauge\n");

    let Some(report) = report else {
        return out;
    };
    let thresholds = GpuStateThresholds::default();
    for g in &report.gpus {
        let name = escape_label(g.name.as_deref().unwrap_or("unknown"));
        let uuid = escape_label(&g.uuid);
        let labels = format!("gpu=\"{}\",uuid=\"{uuid}\",name=\"{name}\"", g.idx);

        if let Some(u) = g.util_pct {
            out.push_str(&format!(
                "meshharbor_gpu_utilization_ratio{{{labels}}} {:.4}\n",
                f64::from(u) / 100.0
            ));
        }
        if let Some(m) = g.mem_used_mb {
            out.push_str(&format!(
                "meshharbor_gpu_memory_used_bytes{{{labels}}} {}\n",
                u64::from(m) * 1024 * 1024
            ));
        }
        if let Some(m) = g.mem_total_mb {
            out.push_str(&format!(
                "meshharbor_gpu_memory_total_bytes{{{labels}}} {}\n",
                u64::from(m) * 1024 * 1024
            ));
        }
        if let Some(t) = g.temp_c {
            out.push_str(&format!(
                "meshharbor_gpu_temperature_celsius{{{labels}}} {t}\n"
            ));
        }
        if let Some(p) = g.power_w {
            out.push_str(&format!("meshharbor_gpu_power_watts{{{labels}}} {p}\n"));
        }
        let st = classify_gpu_state(report.status, g, now_s, thresholds);
        out.push_str(&format!(
            "meshharbor_gpu_state{{{labels},state=\"{}\"}} 1\n",
            st.wire()
        ));
    }
    out
}

/// Spawn the loopback-only Prometheus `/metrics` listener if `raw_addr` is set.
pub fn spawn_if_configured(
    raw_addr: Option<&str>,
    latest_report: Arc<RwLock<Option<GpuReport>>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let Some(raw) = raw_addr.map(str::trim).filter(|s| !s.is_empty()) else {
        return;
    };
    let addr: SocketAddr = match crate::config::validate_gpu_metrics_listen(raw) {
        Ok(a) => a,
        Err(reason) => {
            tracing::error!(addr = raw, %reason, "gpu-metrics: refusing non-loopback or invalid address");
            return;
        }
    };
    tokio::spawn(async move {
        // Belt-and-suspenders loopback gate right before bind.
        if !addr.ip().is_loopback() {
            return;
        }
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(%addr, %e, "gpu-metrics: bind failed");
                return;
            }
        };
        tracing::info!(%addr, "gpu-metrics: loopback Prometheus /metrics listening");
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                res = listener.accept() => {
                    let Ok((mut sock, _peer)) = res else { continue };
                    let report_slot = latest_report.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
                        let n = match tokio::time::timeout(
                            std::time::Duration::from_secs(2),
                            sock.read(&mut buf),
                        ).await {
                            Ok(Ok(n)) if n > 0 => n,
                            _ => return,
                        };
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let first_line = req.lines().next().unwrap_or("");
                        let is_metrics = first_line.starts_with("GET /metrics ")
                            || first_line.starts_with("GET /metrics?");
                        let resp = if is_metrics {
                            let snap = report_slot.read().ok().and_then(|g| g.clone());
                            let now_s = chrono::Utc::now().timestamp();
                            let body = format_prometheus(snap.as_ref(), now_s);
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            )
                        } else {
                            "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found\n"
                                .to_string()
                        };
                        let _ = sock.write_all(resp.as_bytes()).await;
                    });
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_remote_control::gpu::{GpuHostStatus, GpuSample, ProcsState};

    #[test]
    fn fr139_prometheus_format_emits_gauges_without_process_labels() {
        let rep = GpuReport {
            seq: 1,
            interval_ms: 2000,
            status: GpuHostStatus::Ok,
            backend: Some("nvml".into()),
            driver_version: Some("550.90".into()),
            host: Default::default(),
            gpus: vec![GpuSample {
                uuid: "GPU-123".into(),
                idx: 0,
                name: Some("RTX 4090".into()),
                util_pct: Some(50),
                mem_used_mb: Some(1024),
                mem_total_mb: Some(24_576),
                temp_c: Some(61),
                power_w: Some(220),
                procs_state: ProcsState::Ok,
                procs: Some(vec![]),
                ..Default::default()
            }],
        };
        let text = format_prometheus(Some(&rep), 10_000);
        assert!(text.contains(r#"meshharbor_gpu_utilization_ratio{gpu="0",uuid="GPU-123",name="RTX 4090"} 0.5000"#));
        assert!(text.contains(r#"meshharbor_gpu_memory_used_bytes{gpu="0",uuid="GPU-123",name="RTX 4090"} 1073741824"#));
        assert!(text.contains(r#"meshharbor_gpu_state{gpu="0",uuid="GPU-123",name="RTX 4090",state="free"} 1"#));
    }
}
