// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * Onboarding view: enroll this device into a tenant.
 *   1. Operator pastes an enrollment token (from the MeshHarbor admin UI).
 *   2. Operator confirms the device name (defaulted to the hostname).
 *   3. Enroll → `cmd_enroll` → on success offer per-user auto-start and a
 *      jump back to the Overview.
 *
 * Result content is built with createElement/textContent — the ids echoed
 * back come from the server and must not be innerHTML'd.
 */
(function () {
  'use strict';
  const { $, invoke, show, on, navigate, refreshStatus } = window.MeshHarbor;

  const featureLabels = [
    ['desktop_view', 'View screen'], ['desktop_control', 'Control keyboard and mouse'],
    ['clipboard', 'Clipboard'], ['files', 'Read and write files'],
    ['ssh', 'SSH shell (may run as root / SYSTEM)'], ['exec', 'Run commands (may run as root / SYSTEM)'],
    ['rdp', 'Remote Desktop (RDP)'], ['network', 'Any network service, including system SSH / RDP'],
  ];

  function featurePicker(parent, initial) {
    const group = document.createElement('fieldset');
    const legend = document.createElement('legend');
    legend.textContent = 'Features this invitation may use';
    group.appendChild(legend);
    const inputs = {};
    for (const [name, label] of featureLabels) {
      const row = document.createElement('label');
      row.style.display = 'block';
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.checked = initial === null ? true : initial[name] === true;
      inputs[name] = input;
      row.append(input, document.createTextNode(' ' + label));
      group.appendChild(row);
    }
    const sync = () => {
      for (const name of ['desktop_control', 'clipboard']) {
        inputs[name].disabled = !inputs.desktop_view.checked;
        if (!inputs.desktop_view.checked) inputs[name].checked = false;
      }
    };
    inputs.desktop_view.addEventListener('change', sync);
    sync();
    parent.appendChild(group);
    const warning = document.createElement('p');
    warning.className = 'muted small';
    warning.textContent = 'SSH and commands can give full system privileges. Network access may reach other services even if their dedicated feature is off. This selects permission, not installed build support: missing capture/input/SSH components require a full package. Local OFF switches, administrator service policies and OS permissions still apply. You may narrow or revoke this invitation later.';
    parent.appendChild(warning);
    return () => featureLabels.filter(([name]) => inputs[name].checked).map(([name]) => name).join(',') || 'none';
  }

  async function refreshInvitations() {
    const target = $('held-invitations');
    if (!target) return;
    target.replaceChildren();
    try {
      const held = await invoke('cmd_invitations');
      if (!held || !held.grants.length) {
        target.textContent = 'No invitation is recorded on this device.';
        return;
      }
      for (const [, grant] of held.grants) {
        const card = document.createElement('div');
        card.className = 'card';
        const title = document.createElement('p');
        title.textContent = (grant.inviter || grant.org || 'Invitation') + ' · until ' + new Date(grant.access_until_ms).toLocaleString();
        card.appendChild(title);
        if (grant.revocation_pending) {
          const pending = document.createElement('p');
          pending.textContent = 'New authorizations are updated. Revocation of existing SSH / command sessions is still unconfirmed; restarting the device agent does not confirm its separate system service has closed them.';
          card.appendChild(pending);
        }
        if (!grant.features) {
          const note = document.createElement('p');
          note.textContent = 'Legacy invitation: its prior feature scope was not recorded. Choose an explicit scope before saving; no features are preselected.';
          card.appendChild(note);
        }
        const selection = featurePicker(card, grant.features || {});
        const save = document.createElement('button');
        save.type = 'button';
        save.textContent = grant.revocation_pending ? 'Save / retry confirmed cleanup' : 'Save features and restart connections';
        save.disabled = !grant.invite_id;
        const result = document.createElement('p');
        result.className = 'small';
        save.addEventListener('click', async () => {
          save.disabled = true;
          result.textContent = 'Saving and interrupting managed connections / foreground commands across ALL organizations on this device. Other authorization settings stay unchanged; completed command effects and deliberately detached tasks are not undone. Waiting for confirmed cleanup.';
          try {
            result.textContent = await invoke('cmd_invite_features', { inviteId: grant.invite_id, features: selection(), expectedRevision: grant.features_revision || 0 });
            await refreshInvitations();
          }
          catch (e) { result.textContent = 'Not fully completed: ' + e; }
          finally { save.disabled = false; }
        });
        card.append(save, result);
        target.appendChild(card);
      }
    } catch (e) { target.textContent = 'Could not read invitations: ' + e; }
  }

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
    if (window.MeshHarbor.welcomePending) {
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
    void refreshInvitations();
    $('refresh-invitations').addEventListener('click', refreshInvitations);

    on('status', (s) => {
      enrolledMode = !!s.enrolled;
      const loginCard = $('login-card');
      if (loginCard) loginCard.hidden = enrolledMode;
      // A machine may hold several invitations, signed in or not.
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

    // Device login: start → show the code (and the link, if no browser
    // opened) → wait for the approval → the same Enrolled banner.
    const loginBtn = $('btn-login');
    if (loginBtn) loginBtn.addEventListener('click', async () => {
      const deviceName = ($('device-name').value || '').trim();
      if (!deviceName) {
        showError('Fill in the device name first.');
        return;
      }
      const box = $('login-pending');
      loginBtn.disabled = true;
      loginBtn.textContent = 'Starting…';
      try {
        const started = await invoke('cmd_login_start', { server: '', deviceName });
        box.hidden = false;
        box.className = 'banner';
        box.replaceChildren();
        const p1 = document.createElement('p');
        p1.textContent = started.opened
          ? 'Approve this device in the browser window that just opened.'
          : 'Open this link and approve the device:';
        box.appendChild(p1);
        const link = document.createElement('code');
        link.textContent = started.url;
        link.style.wordBreak = 'break-all';
        box.appendChild(link);
        const p2 = document.createElement('p');
        p2.textContent = 'The page must show the code ' + started.user_code + '. Waiting for approval…';
        box.appendChild(p2);
        loginBtn.textContent = 'Waiting…';
        const s = await invoke('cmd_login_wait', { deviceName });
        box.hidden = true;
        showEnrolled(s);
        void refreshStatus();
      } catch (e) {
        box.hidden = true;
        showError('Sign-in failed: ' + e);
      } finally {
        loginBtn.disabled = false;
        loginBtn.textContent = 'Sign in…';
      }
    });

    // Invitations: look at the code first (who, for how long), then accept.
    const joinBtn = $('btn-join');
    if (joinBtn) joinBtn.addEventListener('click', async () => {
      const code = ($('join-code').value || '').trim();
      if (!/^\d{4}[- ]?\d{4}$/.test(code)) {
        showError('An invite code is 8 digits, like 1234-5678.');
        return;
      }
      const deviceName = ($('device-name').value || '').trim();
      const box = $('join-pending');
      joinBtn.disabled = true;
      joinBtn.textContent = 'Checking…';
      let p;
      try {
        p = await invoke('cmd_join_preview', { code });
        if (!p.features_supported) throw new Error('Update the server first: it cannot enforce selected invitation features.');
      } catch (e) {
        showError('Could not check the code: ' + e);
        joinBtn.disabled = false;
        joinBtn.textContent = 'Join';
        return;
      }
      box.textContent = '';
      const what = document.createElement('p');
      what.textContent = p.from + ' invites this device for ' + p.remaining +
        ' (until ' + new Date(p.access_until_ms).toLocaleString() + ').';
      const how = document.createElement('p');
      how.className = 'muted small';
      how.textContent = 'Choose what this invitation may access. It cannot initiate access to their devices. ' +
        'You can change the selection here or leave at any time from the tray menu.';
      const row = document.createElement('div');
      row.className = 'actions';
      const accept = document.createElement('button');
      accept.type = 'button';
      accept.className = 'primary';
      accept.textContent = 'Accept';
      const cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.textContent = 'Cancel';
      row.append(accept, cancel);
      box.append(what, how);
      const selection = featurePicker(box, null);
      box.appendChild(row);
      box.hidden = false;
      const reset = () => {
        box.hidden = true;
        joinBtn.disabled = false;
        joinBtn.textContent = 'Join';
      };
      cancel.addEventListener('click', reset);
      accept.addEventListener('click', async () => {
        accept.disabled = true;
        cancel.disabled = true;
        accept.textContent = 'Joining…';
        try {
          const s = await invoke('cmd_join', { code, deviceName, features: selection() });
          reset();
          $('join-code').value = '';
          showEnrolled(s);
          void refreshStatus();
          void refreshInvitations();
        } catch (e) {
          reset();
          showError('Could not join: ' + e);
        }
      });
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
