// SPDX-License-Identifier: MPL-2.0
/* Account data lives in an unprivileged embedded server window, not agent IPC. */
(function () {
  'use strict';
  const R = window.Roomler;
  const choices = [['account-devices', 'devices'], ['account-received', 'received'], ['account-sent', 'sent']];
  let busy = false;
  choices.forEach(([id, section]) => {
    const button = R.$(id);
    if (!button) return;
    button.addEventListener('click', async () => {
      if (busy) return;
      busy = true;
      choices.forEach(([key]) => { const el = R.$(key); if (el) el.disabled = true; });
      const error = R.$('account-error');
      if (error) { error.hidden = true; error.textContent = ''; }
      try { await R.invoke('cmd_open_account', { section }); }
      catch (_) { if (error) { error.textContent = 'Cannot open the account centre. Check this device’s server URL and try again.'; error.hidden = false; } }
      finally { busy = false; choices.forEach(([key]) => { const el = R.$(key); if (el) el.disabled = false; }); }
    });
  });
})();
