// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * Onboarding view: enroll this device into a tenant.
 *   1. Operator pastes an enrollment token (from the Roomler admin UI).
 *   2. Operator confirms the device name (defaulted to the hostname).
 *   3. Enroll → `cmd_enroll` → on success offer per-user auto-start and a
 *      jump back to the Overview.
 *
 * Result content is built with createElement/textContent — the ids echoed
 * back come from the server and must not be innerHTML'd.
 */
(function () {
  'use strict';
  const { $, invoke, show, on, navigate, refreshStatus } = window.Roomler;

  async function prefillDeviceName() {
    try {
      const name = await invoke('cmd_default_device_name');
      const el = $('device-name');
      if (el && !el.value) el.value = name;
    } catch (e) {
      console.warn('default device name lookup failed', e);
    }
  }

  function resultSlot() {
    const el = $('enroll-result');
    el.hidden = false;
    el.replaceChildren();
    return el;
  }

  function showError(text) {
    const el = resultSlot();
    el.className = 'banner banner-error';
    el.textContent = text;
  }

  function showEnrolled(status) {
    const el = resultSlot();
    el.className = 'banner banner-ok';

    const box = document.createElement('div');
    const head = document.createElement('strong');
    head.textContent = 'Enrolled.';
    box.appendChild(head);

    const detail = document.createElement('p');
    detail.className = 'muted small';
    detail.style.margin = '4px 0 8px';
    detail.textContent =
      'device ' + (status.agent_id || '?') + ' · tenant ' + (status.tenant_id || '?');
    box.appendChild(detail);

    const actions = document.createElement('div');
    actions.className = 'actions';
    actions.style.marginTop = '0';

    const install = document.createElement('button');
    install.type = 'button';
    install.className = 'primary';
    install.textContent = 'Install auto-start';
    install.addEventListener('click', async () => {
      install.disabled = true;
      install.textContent = 'Installing…';
      try {
        await invoke('cmd_service_install', { asService: false });
        install.textContent = 'Auto-start installed';
      } catch (e) {
        install.textContent = 'Install failed: ' + e;
        install.disabled = false;
      }
    });
    actions.appendChild(install);

    // FR-84 D6 — enrolled from the Welcome tour (a first run): back into it.
    if (window.Roomler.welcomePending) {
      const tour = document.createElement('button');
      tour.type = 'button';
      tour.textContent = 'Continue the Welcome tour';
      tour.addEventListener('click', () => navigate('welcome'));
      actions.appendChild(tour);
    }

    const done = document.createElement('button');
    done.type = 'button';
    done.textContent = 'Go to Overview';
    done.addEventListener('click', () => navigate('overview'));
    actions.appendChild(done);

    box.appendChild(actions);
    el.appendChild(box);
  }

  // S1b: whether the view is in re-enroll mode (device already enrolled).
  // Re-enroll is a TOKEN refresh: server URL + device name are locked to
  // the current enrollment and the daemon-honest `cmd_re_enroll` runs
  // (targeting the config the daemon actually reads) — the old path ran a
  // FULL fresh enroll into the per-user file, which on SCM installs
  // manufactured the split-config the Settings banner warns about.
  let enrolledMode = false;

  function showReEnrolled() {
    const el = resultSlot();
    el.className = 'banner banner-ok';
    const head = document.createElement('strong');
    head.textContent = 'Re-enrolled — token refreshed.';
    el.appendChild(head);
    const actions = document.createElement('div');
    actions.className = 'actions';
    const done = document.createElement('button');
    done.type = 'button';
    done.textContent = 'Go to Overview';
    done.addEventListener('click', () => navigate('overview'));
    actions.appendChild(done);
    el.appendChild(actions);
  }

  document.addEventListener('DOMContentLoaded', () => {
    void prefillDeviceName();

    on('status', (s) => {
      enrolledMode = !!s.enrolled;
      const btn = $('btn-enroll');
      if (btn) btn.textContent = enrolledMode ? 'Re-enroll this device' : 'Enroll this device';
      const note = $('onboard-reenroll-note');
      if (note) note.hidden = !enrolledMode;
      const server = $('server');
      const name = $('device-name');
      if (server) {
        server.disabled = enrolledMode;
        if (enrolledMode && s.server_url) server.value = s.server_url;
      }
      if (name) {
        name.disabled = enrolledMode;
        if (enrolledMode && s.device_name && !name.matches(':focus')) {
          name.value = s.device_name;
        }
      }
    });

    $('enroll-form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const token = $('token').value.trim();
      const btn = $('btn-enroll');
      const label = btn.textContent;

      if (enrolledMode) {
        if (!token) {
          showError('Paste a fresh enrollment token.');
          return;
        }
        btn.disabled = true;
        btn.textContent = 'Re-enrolling…';
        try {
          await invoke('cmd_re_enroll', { token });
          $('token').value = '';
          showReEnrolled();
          void refreshStatus();
        } catch (e) {
          showError('Re-enrollment failed: ' + e);
        } finally {
          btn.disabled = false;
          btn.textContent = label;
        }
        return;
      }

      const server = $('server').value.trim();
      const deviceName = $('device-name').value.trim();
      if (!server || !deviceName || !token) {
        showError('Fill all three fields.');
        return;
      }
      btn.disabled = true;
      btn.textContent = 'Enrolling…';
      try {
        const s = await invoke('cmd_enroll', { server, token, deviceName });
        $('token').value = '';
        showEnrolled(s);
        void refreshStatus();
      } catch (e) {
        showError('Enrollment failed: ' + e);
      } finally {
        btn.disabled = false;
        btn.textContent = label;
      }
    });
  });
})();
