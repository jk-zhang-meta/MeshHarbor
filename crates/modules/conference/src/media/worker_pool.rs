// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
use mediasoup::worker::{Worker, WorkerSettings};
use mediasoup::worker_manager::WorkerManager;
use meshharbor_config::MediasoupSettings;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{error, info};

/// Pool of mediasoup workers with round-robin selection.
pub struct WorkerPool {
    workers: Vec<Worker>,
    next: AtomicUsize,
}

impl WorkerPool {
    /// Creates a pool of mediasoup workers based on settings.
    pub async fn new(settings: &MediasoupSettings) -> anyhow::Result<Self> {
        let worker_manager = WorkerManager::new();
        let mut workers = Vec::with_capacity(settings.num_workers as usize);

        for i in 0..settings.num_workers {
            let mut worker_settings = WorkerSettings::default();
            worker_settings.rtc_port_range = settings.rtc_min_port..=settings.rtc_max_port;

            let worker = worker_manager
                .create_worker(worker_settings)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create mediasoup worker {}: {}", i, e))?;

            let worker_id = worker.id();
            worker
                .on_dead(move |reason| {
                    error!(?reason, %worker_id, "mediasoup worker died");
                })
                .detach();

            info!(worker_id = %worker.id(), "mediasoup worker {} created", i);
            workers.push(worker);
        }

        Ok(Self {
            workers,
            next: AtomicUsize::new(0),
        })
    }

    /// Returns the next worker using round-robin selection.
    pub fn get_worker(&self) -> &Worker {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.workers.len();
        &self.workers[idx]
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }
}
