// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// MeshHarbor Setup — unified SPA controller.
//
// Vanilla JS state machine driving the 5-step wizard (Welcome →
// Server → Token → Install → Done) via Tauri invoke calls into the
// `wizard_app` lib. Merges the two legacy SPA drivers:
//
//   - role cards + cross-flavour ack gate + force-kill flow from the
//     legacy agent wizard's SPA
//   - the {type, data} adjacently-tagged ProgressEvent handling from
//     the legacy tunnel wizard's SPA
//   (both legacy wizard crates retired in P4c-2)
//
// plus two NET-NEW patterns:
//   - `cmd_install_progress_replay` fast-forward on the Install step
//     (the legacy SPAs shipped the command but never called it), and
//   - an in-HTML force-kill confirmation section instead of relying
//     on a native dialog.
//
// Wire contracts:
//   - ProgressEvent: {type: "PascalCase", data: {camelCase fields}}
//     (wizard_shared::progress).
//   - WizardState: {schemaVersion, step, role, serverUrl, deviceName}
//     — camelCase, token NEVER included (H5).
//   - Command payloads (DetectResult / TokenValidation / DoneReport):
//     camelCase.

const { invoke, Channel } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const I18N = window.MeshHarborSetupI18n;
const t = (key, params) => (I18N ? I18N.t(key, params) : key);

const STEPS = ["welcome", "server", "token", "install", "done"];
const ROLES = ["daemon-system", "daemon-machine", "daemon-user", "tunnel-client"];

const state = {
  step: "welcome",
  role: null,          // one of ROLES, or null until picked
  roleAck: false,      // cross-flavour acknowledgement checkbox
  detection: null,     // DetectResult {agent: {...}, tunnel: {...}}
  server: "",
  device: "",
  token: "",           // pasted JWT — kept in JS memory ONLY, never
                       // sent through cmd_save_state.
  tokenView: null,     // TokenValidation (or {error}) from cmd_validate_token
  tokenValidating: false,
  installError: null,
  installErrorStep: null, // step scope from the last Error event
  installDone: null,   // DoneReport
  installInFlight: false,
  msiSpawned: false,   // relabels Cancel → Force-kill installer
  totalBytes: 0,       // download denominator
  overlayChoice: null, // FR-84 S2: the overlay box once the operator touched
                       // it (true/false); null = follow the role. Memory
                       // only — deliberately NOT in the persisted
                       // WizardState, so a relaunch re-derives it from the
                       // role instead of replaying a stale click.
  anchorSkipReason: null, // FR-104: why the anchor step did not anchor
  diagOptIn: false,    // FR-102 P3b: the Welcome page's diagnostics box.
                       // Memory only — deliberately NOT in the persisted
                       // WizardState and never defaulted from an earlier
                       // run: unticked is the default, every launch.
  pageEnteredAt: 0,    // performance.now() when the current page was shown;
                       // a page boundary's elapsed_ms is measured from it.
};

// Checklist rows keyed by event type — replay + live events render
// idempotently (a repeated type overwrites its row instead of
// appending a duplicate). JS Map preserves insertion order.
let installRows = new Map();

// ─── Bootstrap ─────────────────────────────────────────────────────────────

async function init() {
  wireGlobalListeners();
  await loadPersistedState();
  await probeAndRender();
}

async function loadPersistedState() {
  try {
    const persisted = await invoke("cmd_load_state");
    // Unknown / stale role strings re-prompt the picker on resume.
    state.role = ROLES.includes(persisted.role) ? persisted.role : null;
    state.server = persisted.serverUrl ?? "";
    state.device = persisted.deviceName ?? "";
    // Step "install" or "done" on relaunch means the previous install
    // was either interrupted or successful; either way, dump the
    // operator back at Welcome so they can re-detect and decide.
    if (persisted.step === "install" || persisted.step === "done") {
      state.step = "welcome";
    } else {
      state.step = STEPS.includes(persisted.step) ? persisted.step : "welcome";
    }
  } catch (err) {
    console.warn("load wizard state failed:", err);
  }
}

async function persistState() {
  try {
    await invoke("cmd_save_state", {
      state: {
        schemaVersion: 1,
        step: state.step,
        role: state.role,
        serverUrl: state.server,
        deviceName: state.device,
        // Token is deliberately NEVER part of this payload (H5).
      },
    });
  } catch (err) {
    console.warn("save wizard state failed:", err);
  }
}

async function probeAndRender() {
  // Welcome step's pre-flight detection runs once on bootstrap.
  try {
    state.detection = await invoke("cmd_detect_install");
  } catch (err) {
    state.detection = {
      agent: { supported: false, canElevate: false, kind: "clean", peruserVersion: null, permachineVersion: null, ambiguous: false },
      tunnel: { installed: false, machineName: null, configPath: null },
    };
    showSnackbar(t("snack.detectFailed", { err }));
  }

  // Clean Windows Setup Wizard installs default to full machine-wide
  // Administrator (`NT AUTHORITY\SYSTEM`) mode ("daemon-system") while
  // keeping all other roles selectable.
  if (!state.role && state.detection?.agent?.supported && state.detection.agent.kind === "clean") {
    state.role = state.detection.agent.canElevate === false ? "daemon-user" : "daemon-system";
  }

  // Default server URL + device name come from the lib helpers when
  // the persisted state didn't already supply values.
  if (!state.server) {
    state.server = await invoke("cmd_default_server_url");
  }
  if (!state.device) {
    state.device = await invoke("cmd_default_device_name");
  }

  state.pageEnteredAt = performance.now();
  render();
}

function wireGlobalListeners() {
  // Wire the step handlers FIRST — the Next/Back buttons are critical,
  // and NOTHING below may prevent them from being bound. (Regression
  // 2026-07-17: the optional single-instance listener was wired first;
  // when the `event:listen` capability was missing it threw the whole
  // function aborted before these ran, so every Next button was dead.)
  wireWelcome();
  wireServer();
  wireToken();
  wireInstall();
  wireDone();
  if (I18N) {
    I18N.wireLangToggles(document);
    I18N.applyI18n(document);
    document.addEventListener("meshharbor:lang", () => {
      render();
    });
  }

  // B9: single-instance plugin emits this when a second wizard EXE
  // launch finds an in-flight install in the first process. Pop a
  // snackbar; the new process exits silently on the Rust side. Fully
  // OPTIONAL + best-effort — guarded against both a synchronous throw
  // and a rejected promise so a missing/denied event capability can
  // never break wizard navigation.
  try {
    Promise.resolve(
      listen("installer-already-running", () => {
        showSnackbar(t("snack.alreadyRunning"));
      }),
    ).catch((e) => console.warn("single-instance listener unavailable:", e));
  } catch (e) {
    console.warn("single-instance listener unavailable:", e);
  }
}

// ─── Render dispatch ───────────────────────────────────────────────────────

function render() {
  for (const step of STEPS) {
    document.getElementById(`step-${step}`).hidden = state.step !== step;
  }
  renderStepIndicator();
  if (state.step === "welcome") renderWelcome();
  if (state.step === "server") renderServer();
  if (state.step === "token") renderToken();
  if (state.step === "install") renderInstall();
  if (state.step === "done") renderDone();
}

function renderStepIndicator() {
  const items = document.querySelectorAll(".step-indicator li");
  const idx = STEPS.indexOf(state.step);
  items.forEach((li, i) => {
    li.classList.remove("active", "done");
    if (i < idx) li.classList.add("done");
    else if (i === idx) li.classList.add("active");
  });
}

async function gotoStep(name) {
  state.step = name;
  state.pageEnteredAt = performance.now();
  await persistState();
  render();
}

// ─── FR-102 P3b: opt-in setup diagnostics ──────────────────────────────────

// A page boundary: `welcome` / `server` / `token` with `ok` (Continue) or
// `cancelled` (Cancel), and the time spent on the page. The Rust recorder is
// the gate — it drops everything while the box is unticked and buffers until
// cmd_install names the server — so this is only ever a report, never a
// send, and it can never fail the wizard (the invoke's error is swallowed).
async function pageBoundary(step, outcome) {
  if (!state.diagOptIn) return;
  const elapsedMs = Math.max(0, Math.round(performance.now() - state.pageEnteredAt));
  try {
    await invoke("cmd_diagnostics_page", { step, outcome, elapsedMs });
  } catch (err) {
    console.warn("[diagnostics] page boundary not recorded:", err);
  }
}

async function setDiagOptIn(enabled) {
  state.diagOptIn = enabled;
  try {
    await invoke("cmd_diagnostics_opt_in", { enabled });
  } catch (err) {
    console.warn("[diagnostics] opt-in not recorded:", err);
    // The recorder never heard the tick, so nothing is sent — the honest
    // state to show is unticked.
    state.diagOptIn = false;
    document.getElementById("diag-opt-in").checked = false;
  }
}

// ─── Role helpers ──────────────────────────────────────────────────────────

function roleFlavour(role) {
  // Mirror of Role::msi_flavour on the Rust side.
  if (role === "daemon-system") return "permachine-system-context";
  if (role === "daemon-machine") return "permachine";
  if (role === "daemon-user") return "peruser";
  return null; // tunnel-client
}

function roleLabel(role) {
  if (role === "daemon-system") return t("role.daemonSystem");
  if (role === "daemon-machine") return t("role.daemonMachine");
  if (role === "daemon-user") return t("role.daemonUser");
  if (role === "tunnel-client") return t("role.tunnelClient");
  return role ?? t("role.none");
}

function flavourLabel(flavour) {
  if (flavour === "peruser") return "perUser";
  if (flavour === "permachine") return "perMachine";
  if (flavour === "permachine-system-context") return "perMachine + SystemContext";
  return flavour;
}

// FR-84 S2 — what the overlay box shows: the operator's explicit choice if
// they made one, else the role's default — on for every daemon role (a
// per-user daemon joins through the userspace netstack; the hint says so).
// Mirrors `AdvancedOptions::with_flavour_defaults` on the Rust side, which
// applies the same rule when the option never reaches it.
function overlayChecked(role, choice) {
  return choice ?? role !== "tunnel-client";
}

// ─── Step 1: Welcome ────────────────────────────────────────────────────────

function wireWelcome() {
  document.getElementById("welcome-cancel").addEventListener("click", async () => {
    // FR-102 P3b: a cancel before any server is known is buffered in the
    // recorder and dies with the process — nothing is sent anywhere.
    await pageBoundary("welcome", "cancelled");
    await exitWizard();
  });
  document.getElementById("welcome-continue").addEventListener("click", async () => {
    await pageBoundary("welcome", "ok");
    await gotoStep("server");
  });
  // FR-102 P3b: the diagnostics box — memory only, reported to the recorder.
  document.getElementById("diag-opt-in").addEventListener("change", async (e) => {
    await setDiagOptIn(e.target.checked);
  });
  document.querySelectorAll("input[name='role']").forEach((radio) => {
    radio.addEventListener("change", (e) => {
      state.role = e.target.value;
      state.roleAck = false;
      document.getElementById("cross-flavour-ack").checked = false;
      // Role change invalidates any previous token introspection (the
      // audience gate depends on the role).
      state.tokenView = null;
      persistState();
      renderWelcome();
    });
  });
  document.getElementById("cross-flavour-ack").addEventListener("change", (e) => {
    state.roleAck = e.target.checked;
    renderWelcome();
  });
}

function renderWelcome() {
  const agentSummary = document.getElementById("detect-agent-summary");
  const tunnelSummary = document.getElementById("detect-tunnel-summary");
  const ambiguous = document.getElementById("detect-ambiguous-warning");
  if (!state.detection) {
    agentSummary.textContent = t("welcome.probing");
    return;
  }
  const a = state.detection.agent;
  const detTunnel = state.detection.tunnel;

  // Daemon detection summary.
  if (!a.supported) {
    agentSummary.textContent = t("welcome.detect.agentUnsupported");
  } else if (a.kind === "clean") {
    agentSummary.textContent = t("welcome.detect.agentClean");
  } else if (a.kind === "peruser") {
    agentSummary.textContent = t("welcome.detect.agentPerUser", {
      version: a.peruserVersion ?? t("welcome.unknown"),
    });
  } else if (a.kind === "permachine") {
    agentSummary.textContent = t("welcome.detect.agentPerMachine", {
      version: a.permachineVersion ?? t("welcome.unknown"),
    });
  } else if (a.kind === "ambiguous") {
    agentSummary.textContent = t("welcome.detect.agentAmbiguous", {
      perUser: a.peruserVersion ?? "?",
      perMachine: a.permachineVersion ?? "?",
    });
  }
  ambiguous.hidden = a.kind !== "ambiguous";

  // Tunnel detection summary.
  if (detTunnel.installed) {
    const machine = detTunnel.machineName
      ? t("welcome.detect.tunnelMachine", { name: detTunnel.machineName })
      : "";
    tunnelSummary.textContent = t("welcome.detect.tunnelConfigured", {
      machine,
      path: detTunnel.configPath,
    });
  } else {
    tunnelSummary.textContent = t("welcome.detect.tunnelNone");
  }

  // Non-Windows: only the tunnel-client card makes sense.
  document.getElementById("platform-note").hidden = a.supported;
  document.querySelectorAll("label.role-daemon").forEach((card) => {
    card.hidden = !a.supported;
  });
  if (!a.supported && state.role && state.role !== "tunnel-client") {
    state.role = null;
  }

  // Restore radio selection.
  if (state.role) {
    const radio = document.querySelector(`input[name='role'][value='${state.role}']`);
    if (radio) radio.checked = true;
  }

  // Cross-flavour warning gate (daemon roles only) — BLOCKER-7 of
  // the rc.28 plan critique, relocated from the agent wizard.
  const warningEl = document.getElementById("cross-flavour-warning");
  const warningText = document.getElementById("cross-flavour-warning-text");
  const warning = crossFlavourWarning(a, roleFlavour(state.role));
  if (warning) {
    warningText.textContent = warning;
    warningEl.hidden = false;
  } else {
    warningEl.hidden = true;
  }

  // Continue button gate.
  const canContinue = state.role !== null && (warning === null || state.roleAck);
  document.getElementById("welcome-continue").disabled = !canContinue;

  // FR-102 P3b: the box shows the in-memory state (unticked on every
  // launch) and names the server the diagnostics would go to — the one the
  // enrollment goes to, as the Server page currently has it.
  document.getElementById("diag-opt-in").checked = state.diagOptIn;
  document.getElementById("diag-server").textContent = state.server || "https://www.itachi.fans/meshharbor";
}

function crossFlavourWarning(agentDetect, flavour) {
  if (!flavour || !agentDetect || !agentDetect.supported) return null;
  const wantsPerMachine = flavour.startsWith("permachine");
  const wantsPerUser = flavour === "peruser";
  if (agentDetect.kind === "peruser" && wantsPerMachine) {
    return t("welcome.crossFlavour.userToMachine");
  }
  if (agentDetect.kind === "permachine" && wantsPerUser) {
    return t("welcome.crossFlavour.machineToUser");
  }
  if (agentDetect.kind === "ambiguous") {
    return t("welcome.crossFlavour.ambiguous");
  }
  return null;
}

// ─── Step 2: Server URL + device name ──────────────────────────────────────

function wireServer() {
  document.getElementById("server-back").addEventListener("click", async () => {
    await gotoStep("welcome");
  });
  document.getElementById("server-continue").addEventListener("click", async () => {
    state.server = document.getElementById("server-url").value.trim();
    state.device = document.getElementById("device-name").value.trim();
    await persistState();
    await pageBoundary("server", "ok");
    await gotoStep("token");
  });
  document.getElementById("server-url").addEventListener("input", () => {
    state.server = document.getElementById("server-url").value.trim();
    renderServer();
  });
  document.getElementById("server-url").addEventListener("blur", persistState);
  document.getElementById("device-name").addEventListener("input", () => {
    state.device = document.getElementById("device-name").value.trim();
    renderServer();
  });
  document.getElementById("device-name").addEventListener("blur", persistState);
  // FR-84 S2: a click on the overlay box is an explicit choice — it sticks
  // across Back → another role → Continue, where an untouched box would
  // follow the new role instead.
  document.getElementById("adv-overlay").addEventListener("change", (e) => {
    state.overlayChoice = e.target.checked;
    renderServer();
  });
  document.getElementById("adv-firewall").addEventListener("change", () => {
    const prepared = document.getElementById("adv-firewall").checked;
    document.getElementById("adv-firewall-public").disabled = !prepared;
    if (!prepared) document.getElementById("adv-firewall-public").checked = false;
  });
}

function renderServer() {
  document.getElementById("server-url").value = state.server;
  document.getElementById("device-name").value = state.device;
  const valid = /^https?:\/\/[^\s]+$/i.test(state.server) && state.device.length > 0;
  document.getElementById("server-continue").disabled = !valid;
  // S2: the advanced section holds daemon config keys — meaningless for
  // the tunnel-client role.
  document.getElementById("advanced-wrap").hidden = state.role === "tunnel-client";
  document.getElementById("adv-firewall-wrap").hidden = state.role !== "daemon-user";
  // FR-84 S2: the overlay box follows the role until touched — on for every
  // daemon role. A per-user worker runs with a filtered token and cannot
  // create the TUN adapter, so it joins through the userspace netstack (the
  // hint says so). The box stays enabled: the choice is the operator's, the
  // default is only the likely one.
  document.getElementById("adv-overlay").checked = overlayChecked(state.role, state.overlayChoice);
  document.getElementById("adv-overlay-hint").hidden = state.role !== "daemon-user";
}

// S2 — gather the advanced daemon options for cmd_install. `null` for
// the tunnel-client role (the section is hidden there; the Rust side
// ignores it anyway). The overlay box is sent as the operator SAW it
// (renderServer already resolved the role default into it), so what lands
// in config.toml is what the screen showed.
function gatherAdvanced() {
  if (state.role === "tunnel-client") return null;
  return {
    prepareFirewall: state.role === "daemon-user" && document.getElementById("adv-firewall").checked,
    firewallPublic: state.role === "daemon-user" && document.getElementById("adv-firewall").checked && document.getElementById("adv-firewall-public").checked,
    overlayEnabled: document.getElementById("adv-overlay").checked,
    advertiseLocalSubnets: document.getElementById("adv-local-subnets").checked,
    autoGrantSession: document.getElementById("adv-auto-grant").checked,
    overlayAdvertisedRoutes: document.getElementById("adv-overlay-routes").value.trim(),
    advertiseRoutes: document.getElementById("adv-tunnel-routes").value.trim(),
  };
}

// ─── Step 3: Enrollment token ──────────────────────────────────────────────

function wireToken() {
  document.getElementById("token-back").addEventListener("click", async () => {
    state.token = "";
    state.tokenView = null;
    document.getElementById("token-input").value = "";
    await gotoStep("server");
  });
  document.getElementById("token-continue").addEventListener("click", async () => {
    // FR-102 P3b: the token page is passed once, here; a Retry from the
    // Install page re-runs the pipeline, not this boundary.
    await pageBoundary("token", "ok");
    await runInstall();
  });
  let debounce;
  document.getElementById("token-input").addEventListener("input", (e) => {
    state.token = e.target.value;
    clearTimeout(debounce);
    debounce = setTimeout(validateToken, 350);
  });
}

async function validateToken() {
  const t = state.token.trim();
  if (!t) {
    state.tokenView = null;
    renderToken();
    return;
  }
  state.tokenValidating = true;
  renderToken();
  try {
    state.tokenView = await invoke("cmd_validate_token", { token: t, role: state.role });
    state.tokenView.error = null;
  } catch (err) {
    state.tokenView = { error: String(err) };
  } finally {
    state.tokenValidating = false;
    renderToken();
  }
}

function renderToken() {
  const lead = document.getElementById("token-lead");
  lead.textContent = state.role === "tunnel-client"
    ? t("token.leadTunnel")
    : t("token.leadAgent");

  const info = document.getElementById("token-info");
  const warnAudience = document.getElementById("token-warn-audience");
  const warnExpired = document.getElementById("token-warn-expired");
  const warnParse = document.getElementById("token-warn-parse");
  const continueBtn = document.getElementById("token-continue");

  // Reset.
  info.hidden = true;
  warnAudience.hidden = true;
  warnExpired.hidden = true;
  warnParse.hidden = true;
  continueBtn.disabled = true;

  if (state.tokenValidating || !state.tokenView) return;

  if (state.tokenView.error) {
    warnParse.hidden = false;
    return;
  }

  const view = state.tokenView;
  info.hidden = false;
  document.getElementById("token-issuer").textContent = view.issuer ?? t("token.none");
  document.getElementById("token-type").textContent =
    view.tokenType ?? view.audience ?? t("token.none");
  document.getElementById("token-expiry").textContent =
    view.expiresAtUnix ? formatExpiry(view.expiresAtUnix) : t("token.noExp");
  // FR-104 — say up front that a second administrator prompt is coming.
  document.getElementById("token-anchor-yes").hidden = view.willAnchor !== true;
  document.getElementById("token-anchor-no").hidden = view.willAnchor !== false;

  // Tunnel role gates Continue on the token-type match; daemon roles
  // are not gated client-side (audienceMatches is null for them).
  if (view.audienceMatches === false) {
    warnAudience.hidden = false;
    document.getElementById("token-warn-aud-name").textContent =
      view.tokenType ?? view.audience ?? t("token.none");
    return;
  }
  if (view.appearsExpired) {
    warnExpired.hidden = false;
    return;
  }
  continueBtn.disabled = false;
}

function formatExpiry(unix) {
  const date = new Date(unix * 1000);
  const now = new Date();
  const minutes = Math.round((date - now) / 60000);
  const stamp = date.toLocaleString();
  if (minutes < 0) return t("token.expiryAgo", { stamp, mins: -minutes });
  if (minutes < 60) return t("token.expiryIn", { stamp, mins: minutes });
  return stamp;
}

// ─── Step 4: Install ───────────────────────────────────────────────────────

function stepLabel(type) {
  const key = "install.step." + type;
  const translated = t(key);
  return translated === key ? type : translated;
}

function wireInstall() {
  document.getElementById("install-cancel").addEventListener("click", async () => {
    if (state.msiSpawned) {
      // Post-spawn: the polite cancel flag can't stop msiexec —
      // surface the force-kill confirmation instead (H4).
      document.getElementById("force-kill-confirm").hidden = false;
      return;
    }
    try {
      await invoke("cmd_cancel_in_progress");
      showSnackbar(t("snack.cancelRequested"));
    } catch (err) {
      showSnackbar(t("snack.cancelFailed", { err }));
    }
  });
  document.getElementById("force-kill-back").addEventListener("click", () => {
    document.getElementById("force-kill-confirm").hidden = true;
  });
  document.getElementById("force-kill-confirm-btn").addEventListener("click", async () => {
    document.getElementById("force-kill-confirm").hidden = true;
    try {
      await invoke("cmd_force_kill_msi");
      showSnackbar(t("snack.msiTerminated"));
    } catch (err) {
      showSnackbar(t("snack.forceKillFailed", { err }));
    }
  });
  document.getElementById("install-retry").addEventListener("click", async () => {
    await runInstall();
  });
  document.getElementById("install-back-to-welcome").addEventListener("click", async () => {
    state.installError = null;
    state.installErrorStep = null;
    installRows = new Map();
    await gotoStep("welcome");
  });
}

function updateInstallSummary() {
  const what = state.role === "tunnel-client"
    ? t("install.whatTunnel")
    : t("install.whatDaemon", { flavour: flavourLabel(roleFlavour(state.role)) });
  document.getElementById("install-summary").textContent = t("install.summary", {
    what,
    server: state.server,
    device: state.device,
  });
}

async function runInstall() {
  installRows = new Map();
  state.installError = null;
  state.installErrorStep = null;
  state.installDone = null;
  state.installInFlight = true;
  state.msiSpawned = false;
  state.totalBytes = 0;
  document.getElementById("install-systemcontext-error").hidden = true;
  document.getElementById("force-kill-confirm").hidden = true;
  await gotoStep("install");

  updateInstallSummary();
  renderInstall();

  // 1. Attach the Channel listener FIRST so no live event is dropped.
  const channel = new Channel();
  channel.onmessage = (event) => handleProgress(event, true);

  // 2. Fast-forward through the replay log (H1). The legacy SPAs
  //    shipped the command but never called it; here any events a
  //    previous attach raced past get re-rendered through the same
  //    handler. Rendering is idempotent (rows keyed by event type;
  //    a live `Started` clears the board), so overlap is harmless.
  try {
    const replayed = await invoke("cmd_install_progress_replay");
    for (const event of replayed) handleProgress(event, false);
  } catch (err) {
    console.warn("[runInstall] progress replay failed:", err);
  }

  // 3. Kick the install.
  try {
    const report = await invoke("cmd_install", {
      role: state.role,
      server: state.server,
      token: state.token,
      deviceName: state.device,
      advanced: gatherAdvanced(),
      onEvent: channel,
    });
    console.log("[runInstall] cmd_install returned:", report);
    state.installDone = report;
    state.installInFlight = false;
    // Token cleared from memory now that enrollment succeeded.
    state.token = "";
    document.getElementById("token-input").value = "";
    // Two-step transition: paint Done step FIRST (so the operator
    // sees the Finish button immediately), THEN persist state in the
    // background. If persistState ever hangs or rejects, the user is
    // already on the Done page and unblocked (rc.28 field lesson).
    state.step = "done";
    render();
    persistState().catch((err) =>
      console.warn("[runInstall] persistState failed:", err),
    );
  } catch (err) {
    console.error("[runInstall] cmd_install threw:", err);
    state.installError = String(err);
    state.installInFlight = false;
    renderInstall();
  }
}

// Throttle for the download progress bar (~10 Hz — DownloadProgress
// fires per 64 KiB chunk, hundreds of times per MB).
let lastProgressPaint = 0;

function handleProgress(event, live) {
  const type = event.type;
  const data = event.data ?? {};

  if (type === "DownloadProgress") {
    const now = performance.now();
    if (now - lastProgressPaint < 100) return;
    lastProgressPaint = now;
    if (state.totalBytes > 0) {
      const pct = Math.min(100, (data.receivedBytes / state.totalBytes) * 100);
      document.getElementById("progress-fill").style.width = `${pct.toFixed(1)}%`;
      document.getElementById("progress-label").textContent = t("install.progressLabel", {
        received: (data.receivedBytes / 1_000_000).toFixed(1),
        total: (state.totalBytes / 1_000_000).toFixed(1),
        pct: pct.toFixed(0),
      });
    }
    return;
  }

  // A (live) Started marks the beginning of a fresh pipeline run —
  // clear any rows a stale replay painted.
  if (type === "Started" && live) {
    installRows = new Map();
  }

  if (type === "AssetResolved" || type === "DownloadStarted") {
    state.totalBytes = data.sizeBytes ?? data.totalBytes ?? state.totalBytes;
  }

  if (type === "MsiSpawned") {
    state.msiSpawned = true;
  }

  // FR-104 — kept for the Done page's note.
  if (type === "AnchorSkipped") {
    state.anchorSkipReason = data.reason ?? null;
  }

  if (type === "SystemContextError") {
    const stageLabel = {
      env_var_write: t("install.sc.envVarWrite"),
      service_restart: t("install.sc.serviceRestart"),
      unknown: t("install.sc.unknown"),
    }[data.stage] ?? t("install.sc.other", { stage: data.stage });
    document.getElementById("systemcontext-error-stage").textContent = stageLabel;
    document.getElementById("systemcontext-error-message").textContent = data.message ?? "";
    document.getElementById("systemcontext-error-hint").textContent = data.hint ?? "";
    document.getElementById("install-systemcontext-error").hidden = false;
  }

  if (type === "Error") {
    state.installErrorStep = data.step ?? null;
  }

  // Idempotent checklist row keyed by event type.
  installRows.set(type, { type, data });
  renderInstall();
}

function renderInstall() {
  if (state.role) updateInstallSummary();
  const list = document.getElementById("install-checklist");
  list.innerHTML = "";
  for (const event of installRows.values()) {
    const li = document.createElement("li");
    li.className = checklistClass(event);
    const icon = document.createElement("span");
    icon.className = "icon";
    li.appendChild(icon);
    const label = document.createElement("span");
    label.textContent = checklistLabel(event);
    li.appendChild(label);
    list.appendChild(li);
  }

  // Progress bar visible only while a download is active.
  const downloadStarted = installRows.has("DownloadStarted");
  const downloadVerified = installRows.has("DownloadVerified");
  document.getElementById("install-progress").hidden = !(downloadStarted && !downloadVerified);

  // Cancel button: relabel once msiexec is running (the polite flag
  // can't interrupt it any more — only force-kill can).
  const cancelBtn = document.getElementById("install-cancel");
  cancelBtn.textContent = state.msiSpawned ? t("install.forceKillBtn") : t("btn.cancel");

  // Error recovery panel, scoped to the failing step.
  const errorEl = document.getElementById("install-error");
  if (state.installError) {
    errorEl.hidden = false;
    document.getElementById("install-error-title").textContent =
      state.installErrorStep
        ? t("install.errorTitleAt", { step: state.installErrorStep })
        : t("install.errorTitle");
    document.getElementById("install-error-message").textContent = state.installError;
    cancelBtn.hidden = true;
  } else {
    errorEl.hidden = true;
    cancelBtn.hidden = false;
  }
}

function checklistClass(event) {
  const et = event.type;
  if (et === "Error" || et === "SystemContextError") return "error";
  if (et === "PreflightWarning" || et === "AnchorSkipped") return "warning";
  if (
    et === "Done" || et === "EnrollOk" || et === "AnchorOk" || et === "MsiCompleted" ||
    et === "ExtractDone" || et === "IntegrationDone" ||
    et === "DownloadVerified" || et === "PreflightOk" || et === "AssetResolved"
  ) {
    return "ok";
  }
  return "running";
}

function checklistLabel(event) {
  const et = event.type;
  const d = event.data ?? {};
  const base = stepLabel(et);
  if (et === "PreflightOk") return t("install.row.preflightOk", { existing: d.existing });
  if (et === "PreflightWarning") return t("install.row.preflightWarning", { base, message: d.message });
  if (et === "AssetResolving") return t("install.row.assetResolving", { artifact: d.artifact });
  if (et === "AssetResolved") {
    return t("install.row.assetResolved", {
      tag: d.tag,
      mb: (d.sizeBytes / 1_000_000).toFixed(1),
    });
  }
  if (et === "MsiSpawned") return t("install.row.msiSpawned", { pid: d.pid });
  if (et === "MsiCompleted") return t("install.row.msiCompleted", { code: d.code, decoded: d.decoded });
  if (et === "ExtractDone") return t("install.row.extractDone", { path: d.tunnelBinary });
  if (et === "IntegrationDone") {
    return t("install.row.integrationDone", {
      pathState: d.pathUpdated ? t("install.row.pathUpdated") : t("install.row.pathUnchanged"),
      shortcutState: d.shortcutCreated ? t("install.row.shortcutCreated") : t("install.row.shortcutSkipped"),
    });
  }
  if (et === "EnrollOk") return t("install.row.enrollOk", { kind: d.principalKind, id: d.principalId });
  if (et === "AnchorSkipped") return t("install.row.anchorSkipped", { reason: d.reason });
  if (et === "Error") return t("install.row.error", { step: d.step, message: d.message });
  if (et === "SystemContextError") {
    const stageLabel = {
      env_var_write: t("install.scRow.envVarWrite"),
      service_restart: t("install.scRow.serviceRestart"),
      unknown: t("install.scRow.unknown"),
    }[d.stage] ?? t("install.scRow.other", { stage: d.stage });
    return t("install.scRow.failed", {
      stage: stageLabel,
      message: d.message,
      hint: d.hint ? " — " + d.hint : "",
    });
  }
  return base;
}

// ─── Step 5: Done ──────────────────────────────────────────────────────────

function wireDone() {
  document.getElementById("done-finish").addEventListener("click", exitWizard);
}

function renderDone() {
  // Defensive: NEVER short-circuit when installDone is missing — the
  // operator must always see the Finish button + a value (placeholder
  // is fine) so the Done page can't render blank (rc.28 field lesson).
  const done = state.installDone ?? {};
  const isTunnel = (done.principalKind ?? "") === "tunnel_client"
    || (!done.principalKind && state.role === "tunnel-client");

  // P4b: daemon MSIs carry the meshharbor CLI (role→action composition —
  // a daemon install subsumes the tunnel client). cliIncluded is the
  // orchestrator's post-install existence check; false/absent means an
  // old pre-P4b MSI was served, so we don't promise a CLI we didn't
  // deliver.
  const cliIncluded = !isTunnel && done.cliIncluded === true;
  // GAP-A/P6: daemon roles also place the meshharbor-desktop GUI beside
  // the daemon (best-effort; a stale server / download failure leaves
  // it false, so we don't claim a desktop we didn't install).
  const desktopInstalled = !isTunnel && done.desktopInstalled === true;
  let lead;
  if (isTunnel) {
    lead = t("done.leadTunnel");
  } else {
    lead = t("done.leadDaemon");
    if (cliIncluded) lead += t("done.leadCli");
    if (desktopInstalled) lead += t("done.leadDesktop");
    if (done.anchored === true) lead += t("done.leadAnchored");
  }
  document.getElementById("done-lead").textContent = lead;

  // FR-104 — the anchor step ran and did not anchor: the manual command,
  // with a placeholder where a fresh token goes (the one pasted here is
  // spent, and is never shown again).
  const anchorFailed = !isTunnel && done.anchored === false;
  document.getElementById("done-anchor-note").hidden = !anchorFailed;
  if (anchorFailed) {
    document.getElementById("done-anchor-reason").textContent = state.anchorSkipReason ?? "";
    const server = (state.server || "https://www.itachi.fans/meshharbor").replace(/\/+$/, "");
    document.getElementById("done-anchor-command").textContent =
      `meshharbord anchor create --server ${server} --token <fresh token> ` +
      `--device ${done.principalId ?? "<device id>"}`;
  }

  document.getElementById("done-principal-label").textContent =
    isTunnel ? t("done.tunnelClientId") : t("done.agentId");
  document.getElementById("done-principal-id").textContent =
    done.principalId ?? t("done.unknownMissing");
  document.getElementById("done-tenant-id").textContent = done.tenantId ?? t("done.unknown");
  document.getElementById("done-role").textContent = roleLabel(done.role ?? state.role);
  document.getElementById("done-tag").textContent = done.tag ?? t("done.unknown");

  // Daemon extras: MSI flavour.
  const flavour = done.flavour ?? (isTunnel ? null : roleFlavour(state.role));
  document.getElementById("done-flavour-label").hidden = !flavour;
  document.getElementById("done-flavour").hidden = !flavour;
  if (flavour) {
    document.getElementById("done-flavour").textContent = flavourLabel(flavour);
  }

  // Tunnel extras: binary path + PATH note.
  document.getElementById("done-binary-label").hidden = !done.binaryPath;
  document.getElementById("done-binary-path").hidden = !done.binaryPath;
  if (done.binaryPath) {
    document.getElementById("done-binary-path").textContent = done.binaryPath;
  }
  // P4b: the PATH note applies to BOTH principals now (daemon MSIs
  // append the install dir; the tunnel pipeline integrates its own
  // bin dir) — gate on pathUpdated alone.
  document.getElementById("done-path-note").hidden = !done.pathUpdated;

  // Config path (both pipelines report it).
  document.getElementById("done-config-label").hidden = !done.configPath;
  document.getElementById("done-config-path").hidden = !done.configPath;
  if (done.configPath) {
    document.getElementById("done-config-path").textContent = done.configPath;
  }

  document.getElementById("done-systemcontext-note").hidden =
    flavour !== "permachine-system-context";

  // Surface the underlying state for support — operator can copy
  // from DevTools or paste a screenshot when something looks off.
  console.log("[renderDone] state.installDone:", state.installDone);
  console.log("[renderDone] state.role:", state.role);
}

async function exitWizard() {
  // Tauri 2's JS `window.close()` from a webview can blank the
  // webview WITHOUT actually exiting the process — operator gets a
  // white/gray dead window with no controls (rc.28 field repro).
  // `cmd_exit_wizard` calls `AppHandle::exit(0)` on the Rust side.
  // Defensive fallback to `window.close()` if the invoke rejects.
  try {
    await invoke("cmd_exit_wizard");
  } catch (err) {
    console.warn("[exitWizard] cmd_exit_wizard failed, falling back:", err);
    window.close();
  }
}

// ─── Snackbar ──────────────────────────────────────────────────────────────

let snackbarTimer;
function showSnackbar(message, durationMs = 4000) {
  const el = document.getElementById("snackbar");
  el.textContent = message;
  el.hidden = false;
  clearTimeout(snackbarTimer);
  snackbarTimer = setTimeout(() => {
    el.hidden = true;
  }, durationMs);
}

// ─── Global error surfacing ────────────────────────────────────────────────

// Surface any unhandled JS exception or promise rejection in a sticky
// snackbar so the operator can take a screenshot for support. Without
// these handlers, a thrown exception mid-render leaves the wizard
// frozen on the previous step with no visible error.
window.addEventListener("error", (event) => {
  console.error("[window.error]", event.message, event.error);
  showSnackbar(t("snack.wizardError", { err: event.message }), 30_000);
});
window.addEventListener("unhandledrejection", (event) => {
  console.error("[unhandledrejection]", event.reason);
  showSnackbar(t("snack.wizardError", { err: event.reason }), 30_000);
});

// ─── Go ────────────────────────────────────────────────────────────────────

init().catch((err) => {
  console.error("init failed:", err);
  showSnackbar(t("snack.initFailed", { err }), 30_000);
});
