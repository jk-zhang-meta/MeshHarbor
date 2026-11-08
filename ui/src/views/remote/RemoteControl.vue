<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-0 remote-control-wrapper">
    <!-- ============================================================
         Toolbar Row 1: primary controls — Back / Title / status /
         Ctrl-Alt-Del / Connect-Disconnect / Fullscreen. Designed to
         fit on a single line at every viewport (down to ~320px) so
         the user never loses access to the primary actions. The
         five session-time tools that previously crowded this row
         (Quality / Scale / Resolution / Codec, Crystal-Clear,
         Low-Latency, clipboard send/get, file upload) moved to
         Row 2 below; on `<md` Row 2 collapses into the bottom-sheet.
         ============================================================ -->
    <v-toolbar density="compact" color="surface" class="px-2 rc-toolbar-primary">
      <v-btn
        icon="mdi-arrow-left"
        variant="text"
        class="rc-tb-back"
        :to="isExternal ? { name: 'connect' } : { name: 'devices', params: { tenantId } }"
        :aria-label="isExternal ? 'Back to Connect' : 'Back to Agents'"
      />
      <v-toolbar-title class="d-flex align-center text-truncate">
        <v-icon :color="statusColor" size="small" class="mr-2 flex-shrink-0">
          mdi-circle
        </v-icon>
        <!-- FR-26 — the admin-set display name wins, as it does on /devices
             and the dashboard mesh; the machine name rides the subtitle so
             the mapping stays visible, unless the viewer hides it with "Hide
             device name when a display name is set" — ONE preference, shared
             with the Devices grid (Settings › Display carries it here). -->
        <!-- FR-52 P4e — an outsider knows the device by its connect code
             only; its name and OS are its organization's to show. -->
        <span v-if="isExternal" class="text-truncate">{{ externalCode || 'Device' }}</span>
        <span v-else class="text-truncate">{{ agent?.display_name || agent?.name || 'Agent' }}</span>
        <!-- OS + version subtitle hidden on phone-sized viewports;
             they're useful context on a desktop but on mobile they
             push Connect/Disconnect off the right edge. -->
        <span v-if="agent" class="text-caption text-medium-emphasis ml-2 d-none d-sm-inline">
          <template v-if="secondaryDeviceName(agent, hideDeviceName)">
            {{ agent.name }} ·
          </template>
          {{ agent.os }} · {{ agent.agent_version || '—' }}
        </span>
      </v-toolbar-title>
      <v-spacer />
      <v-chip
        v-if="rc.phase.value !== 'idle'"
        size="small"
        :color="phaseColor"
        variant="flat"
        class="mr-2 rc-tb-status"
      >
        <template v-if="rc.phase.value === 'reconnecting'">
          Reconnecting (attempt {{ rc.reconnectAttempt.value }})…
        </template>
        <!-- S3 honest badge: connected-but-degraded gets a warning
             chip naming the problem instead of a dishonest solid
             green "connected". -->
        <template v-else-if="rc.phase.value === 'connected' && rc.degraded.value">
          {{ degradedLabel }}
        </template>
        <template v-else>{{ rc.phase.value }}</template>
      </v-chip>
      <!-- FR-100 P2a — the device proved the identity key this browser knows
           for it, or one it met for the first time and now remembers. An
           answer the device did not sign is said so, not hidden: the session
           runs, but nothing vouched for the device. A refused answer never
           gets here; the error view says why. -->
      <v-chip
        v-if="rc.phase.value === 'connected' && peerAuthBadgeShown"
        size="small"
        :color="peerAuthBadgeShown.color"
        variant="tonal"
        :prepend-icon="peerAuthBadgeShown.icon"
        :class="peerAuthBadgeShown.color === 'warning' ? 'mr-2 rc-tb-status' : 'mr-2 d-none d-sm-inline-flex'"
        :title="peerAuthBadgeShown.title"
        data-testid="rc-peer-auth"
      >
        {{ peerAuthBadgeShown.label }}
      </v-chip>
      <!-- Host-locked indicator. Shown only during a live session
           when the agent has signalled (via the rc:host_locked
           control-DC message, agent 0.2.2+) that the input desktop
           transitioned to winsta0\Winlogon. The video stream's
           padlock overlay frame is the primary signal; this badge
           supplements it for operators who scrolled the video out
           of view or are taking a screenshot for support. Older
           agents (<0.2.2) never emit the message, so the chip
           stays hidden and the experience falls back to the
           overlay-only state. -->
      <v-chip
        v-if="rc.phase.value === 'connected' && rc.hostLocked.value"
        size="small"
        color="warning"
        variant="flat"
        prepend-icon="mdi-lock"
        class="mr-2 rc-tb-status"
        :title="hostLockedChipTitle(rc.hostLockedInput.value)"
      >
        Host locked
      </v-chip>
      <!-- Secondary chip for the SYSTEM-context worker's input-desktop
           name (agents 0.3.0+). 'Default' = normal user desktop, no chip
           shown. 'Winlogon' / 'Screen-saver' / etc. = secure desktop, the
           operator is driving lock-screen / UAC / SAS UI. The hostLocked
           chip above and this one render side-by-side: hostLocked is the
           pre-0.3.0 binary lock signal, currentDesktop is the per-
           transition name from the SYSTEM-context path. They're not
           contradictory — on 0.3.0 perMachine MSI both fire. -->
      <v-chip
        v-if="rc.phase.value === 'connected' && rc.currentDesktop.value !== 'Default'"
        size="small"
        color="info"
        variant="flat"
        prepend-icon="mdi-shield-account"
        class="mr-2"
        :title="`Agent thread is bound to ${rc.currentDesktop.value} — type the host's password to unlock`"
      >
        On {{ rc.currentDesktop.value }}
      </v-chip>
      <!-- rc.227 — remote keyboard-layout chip. Self-gating: old agents /
           non-Windows hosts never send rc:layout, so remoteLayout stays
           null and the chip doesn't render. Hidden on phones (secondary
           status; the Settings picker remains reachable). -->
      <v-chip
        v-if="rc.phase.value === 'connected' && rc.remoteLayout.value"
        size="small"
        variant="tonal"
        prepend-icon="mdi-keyboard-settings-outline"
        class="mr-2 d-none d-sm-inline-flex"
        :title="`Remote keyboard layout: ${remoteLayoutLabel(rc.remoteLayout.value.activeTag)}. Typing auto-switches it when needed; pick manually in Settings.`"
      >
        {{ rc.remoteLayout.value.activeTag }}
      </v-chip>
      <!-- P6 — multi-user participants rail. Self-gating: pre-P6 agents
           never broadcast rc:control.state, so controlState stays null and
           nothing renders. Shows everyone on the device; the star marks
           the exclusive-mode floor holder.

           FR-27 — shown from ONE participant, not two. The rail is also the
           only place the input MODE is visible or changeable, and a solo
           viewer arriving on an `exclusive` device could previously neither
           see that nor do anything about it. -->
      <v-menu v-if="rc.phase.value === 'connected' && multiUserState && multiUserState.participants.length >= 1">
        <template #activator="{ props: railProps }">
          <v-chip
            v-bind="railProps"
            size="small"
            variant="tonal"
            prepend-icon="mdi-account-multiple"
            class="mr-2"
            :title="`${multiUserState.participants.length} viewers on this device (input: ${multiUserState.mode})`"
          >
            {{ multiUserState.participants.length }}
          </v-chip>
        </template>
        <v-list density="compact">
          <v-list-subheader>Viewers · input {{ multiUserState.mode }}</v-list-subheader>
          <v-list-item
            v-for="p in multiUserState.participants"
            :key="p.session"
            :title="p.name || 'Viewer'"
            :prepend-icon="p.input ? 'mdi-keyboard' : 'mdi-eye'"
          >
            <template #append>
              <v-icon
                v-if="multiUserState.holder === p.session"
                size="small"
                color="warning"
                title="Holds input control"
              >
                mdi-star
              </v-icon>
            </template>
          </v-list-item>
          <v-divider />
          <v-list-item
            v-if="multiUserState.mode === 'free'"
            title="Switch to exclusive input"
            prepend-icon="mdi-account-key"
            @click="rc.setInputMode('exclusive')"
          />
          <v-list-item
            v-else
            title="Switch to free-for-all input"
            prepend-icon="mdi-account-group"
            @click="rc.setInputMode('free')"
          />
        </v-list>
      </v-menu>
      <!-- FR-27 — I HOLD the floor and someone is waiting for it. Until now
           a refused request was dropped silently, so the holder never learned
           anyone wanted control and the requester had to keep clicking until
           one landed in an idle window. Grant hands it over immediately;
           Ignore clears the chip (they can always ask again). -->
      <div
        v-if="rc.phase.value === 'connected' && floorRequester && iHoldTheFloor"
        class="d-flex align-center mr-2"
      >
        <v-chip size="small" color="warning" variant="tonal" prepend-icon="mdi-hand-back-right">
          {{ floorRequester.name || 'A viewer' }} wants control
        </v-chip>
        <v-btn
          size="small"
          color="warning"
          variant="text"
          class="ml-1"
          @click="rc.grantControl(floorRequester.session)"
        >
          Grant
        </v-btn>
        <v-btn size="small" variant="text" @click="rc.dismissControlRequest()">Ignore</v-btn>
      </div>
      <!-- P6 — exclusive mode + someone else holds the floor: one-click
           request. Auto-granted when the holder has been idle ≥2 s.
           FR-27 — once asked, the button becomes a waiting state with a way
           to withdraw, instead of looking like it did nothing. -->
      <v-btn
        v-if="rc.phase.value === 'connected' && multiUserState?.mode === 'exclusive' && !iHoldTheFloor"
        size="small"
        :color="iAmWaitingForTheFloor ? undefined : 'warning'"
        variant="tonal"
        :prepend-icon="iAmWaitingForTheFloor ? 'mdi-timer-sand' : 'mdi-hand-back-right'"
        class="mr-2"
        :title="
          iAmWaitingForTheFloor
            ? 'Waiting for the current holder — granted automatically once they go idle. Click to withdraw.'
            : 'Request input control (auto-granted when the current holder is idle)'
        "
        @click="iAmWaitingForTheFloor ? rc.dismissControlRequest() : rc.requestControl()"
      >
        {{ iAmWaitingForTheFloor ? 'Waiting…' : 'Request control' }}
      </v-btn>
      <!-- Live stats (codec · bitrate · fps · resolution). Relocated here
           from over the video (2026-07-21) so it never hides a maximized
           remote window's caption buttons. Desktop only (md+) — the toolbar
           has no spare width on phones; the resolution pill still carries the
           `relay-limited (native …)` cue. Shown once media is flowing. -->
      <div
        v-if="rc.phase.value === 'connected' && rc.hasMedia.value && (statsCodecLabel || rc.vp9_444Active.value || rc.hevcActive.value)"
        class="stats-readout d-none d-md-flex mr-2"
        role="status"
        aria-live="polite"
      >
        <span v-if="metrics.codec" class="stats-pill">{{ statsCodecLabel }}</span>
        <!-- FR-93 P2 — the Linux capture arm, under the codec toggle: DRM and
             mutter capture without asking anyone, and the operator can see
             that they did. Absent on Windows, macOS and older agents. -->
        <span v-if="metrics.codec && statsCaptureLabel" class="stats-pill">{{ statsCaptureLabel }}</span>
        <span v-if="metrics.bitrate" class="stats-pill">{{ statsBitrateLabel }}</span>
        <span v-if="metrics.fps" class="stats-pill">{{ statsFpsLabel }}</span>
        <span v-if="metrics.resolution && statsResolutionLabel" class="stats-pill">{{ statsResolutionLabel }}</span>
        <!-- FR-74 P4 — the viewer's own pixel chain: screen pixels per
             remote pixel. `1:1 pixels` is the verified Match-remote-display
             case; anything else is a browser/FSR resample AFTER the codec,
             which no encoder setting can undo. The title says how to reach
             1:1 (Custom zoom 100/dpr %, or Match remote display). -->
        <span v-if="metrics.scale && statsScaleLabel" class="stats-pill" :title="statsScaleHint">{{ statsScaleLabel }}</span>
        <!-- FR-1 P7 — end-to-end frame age (agent framing → canvas paint),
             the RustDesk-"Delay" analogue. Appears once the rc:clock probe
             locks; absent on old agents and the classic video-tag path. -->
        <span v-if="metrics.age && statsAgeLabel" class="stats-pill">{{ statsAgeLabel }}</span>
        <!-- P1 — per-hop pipeline diagnostics (paint / fwd / decode ms,
             output gap, queue, drops, main-thread long tasks). Opt-in via
             localStorage meshharbor-rc-diag-hud=1; the numbers that decide
             whether an fps ceiling is paint-, decode-, or main-thread-bound. -->
        <span v-if="showDiagHud && diagLabel" class="stats-pill">{{ diagLabel }}</span>
      </div>
      <!-- rc.199 — Settings gear (all viewports): opens the unified
           Settings panel (Video / Display / Session). Replaces the old
           mobile-only bottom-sheet trigger + the desktop inline Row 2. -->
      <v-btn
        data-tour="viewer-settings"
        icon="mdi-tune-variant"
        variant="text"
        size="small"
        class="mr-1"
        aria-label="Open viewer settings"
        title="Viewer settings"
        @click="settingsOpen = true"
      />
      <!-- Soft-keyboard toggle: mounts the MobileKeyboard component
           which surfaces a hidden textarea so the OS soft keyboard
           appears. Useful on phones AND on touch-laptops with a
           stowed physical keyboard. Visible at every viewport
           during a connected session — the phone use case is the
           main driver but desktop operators have asked for it too
           (the field-test host use case where the user types the host's
           username during an unlock from another PC). -->
      <v-btn
        v-if="rc.phase.value === 'connected'"
        icon
        variant="text"
        size="small"
        class="mr-1"
        :color="mobileKeyboardOpen ? 'primary' : undefined"
        :aria-label="mobileKeyboardOpen ? 'Hide soft keyboard' : 'Show soft keyboard'"
        :title="mobileKeyboardOpen ? 'Hide keyboard' : 'Show keyboard'"
        @click="mobileKeyboardOpen = !mobileKeyboardOpen"
      >
        <v-icon>mdi-keyboard</v-icon>
      </v-btn>
      <!-- Ctrl+Alt+Del: the OS intercepts this key combo before the
           browser sees it, so expose an explicit toolbar button that
           emits the equivalent key sequence over the input DC.
           Visible at every viewport during a session — emergency-
           recovery action, must not hide behind an extra tap.
           FR-97 P0c — gone where the device says the chord means nothing
           on its OS (a Mac), and its title carries what the keys can and
           cannot do there. -->
      <v-btn
        v-if="rc.phase.value === 'connected' && sasOffered"
        icon
        variant="text"
        size="small"
        class="mr-1"
        aria-label="Send Ctrl+Alt+Del to remote"
        :title="sasTitle"
        data-testid="rc-ctrl-alt-del"
        @click="rc.sendCtrlAltDel()"
      >
        <v-icon>mdi-keyboard-outline</v-icon>
      </v-btn>
      <!-- FR-109 — relative mouse: Pointer Lock for an app that captures the
           pointer (a 3D viewport, a game camera). Offered only where the
           agent advertises `mouse-rel`; Esc releases the mouse. -->
      <v-btn
        v-if="rc.phase.value === 'connected' && relativeMouseOffered"
        icon
        variant="text"
        size="small"
        class="mr-1"
        :color="rc.relativeMouse.value ? 'primary' : undefined"
        aria-label="Relative mouse for 3D apps and games"
        title="Relative mouse: for 3D apps and games that capture the pointer. Esc releases the mouse."
        data-testid="rc-relative-mouse"
        @click="onRelativeMouse"
      >
        <v-icon>mdi-cursor-move</v-icon>
      </v-btn>
      <!-- FR-111 P2 — on a touch screen: the finger is the pointer (direct),
           or the screen is a trackpad that moves the pointer. Hidden where
           there is no touch, and under the `meshharbor-rc-touch=legacy` switch. -->
      <v-btn
        v-if="rc.phase.value === 'connected' && touchModeOffered"
        icon
        variant="text"
        size="small"
        class="mr-1"
        :color="rc.touchMode.value === 'trackpad' ? 'primary' : undefined"
        :aria-label="rc.touchMode.value === 'trackpad' ? 'Touch: trackpad (tap to use direct touch)' : 'Touch: direct (tap to use a trackpad)'"
        :title="rc.touchMode.value === 'trackpad'
          ? 'Trackpad: a finger moves the pointer; tap to click, hold then move to drag. Tap for direct touch.'
          : 'Direct touch: the finger is the pointer. Tap to use the screen as a trackpad.'"
        data-testid="rc-touch-mode"
        @click="rc.setTouchMode(rc.touchMode.value === 'trackpad' ? 'direct' : 'trackpad')"
      >
        <v-icon>{{ rc.touchMode.value === 'trackpad' ? 'mdi-gesture-swipe' : 'mdi-gesture-tap' }}</v-icon>
      </v-btn>
      <!-- FR-111 P3 — on-screen controls over the stage: off, or a built-in
           preset. Chosen per device and remembered in this browser. -->
      <v-menu v-if="rc.phase.value === 'connected' && touchModeOffered" location="bottom">
        <template #activator="{ props: menuProps }">
          <v-btn
            v-bind="menuProps"
            icon
            variant="text"
            size="small"
            class="mr-1"
            :color="touchControlsPreset ? 'primary' : undefined"
            :aria-label="touchControlsPreset ? `On-screen controls: ${touchControlsPreset.name}` : 'On-screen controls: off'"
            :title="touchControlsPreset ? `On-screen controls: ${touchControlsPreset.name}` : 'On-screen controls'"
            data-testid="rc-touch-controls-menu"
          >
            <v-icon>mdi-gamepad-variant-outline</v-icon>
          </v-btn>
        </template>
        <v-list density="compact">
          <v-list-item
            :active="!touchControlsPreset"
            title="Off"
            data-testid="rc-touch-controls-off"
            @click="setTouchControls(null)"
          />
          <v-list-item
            v-for="p in BUILTIN_PRESETS"
            :key="p.id"
            :active="touchControlsPreset?.id === p.id"
            :title="p.name"
            :data-testid="`rc-touch-controls-${p.id}`"
            @click="setTouchControls(p.id)"
          />
          <!-- FR-111 P4 — the org's own presets, under their own heading. -->
          <template v-if="orgTouchList.length">
            <v-list-subheader>Your organization</v-list-subheader>
            <v-list-item
              v-for="p in orgTouchList"
              :key="p.id"
              :active="touchControlsPreset?.id === p.id"
              :title="p.name"
              :data-testid="`rc-touch-controls-${p.id}`"
              @click="setTouchControls(p.id)"
            />
          </template>
          <!-- FR-111 P4b-2 — this member's own, kept in this browser. -->
          <template v-if="myTouchPresets.length">
            <v-list-subheader>This browser</v-list-subheader>
            <v-list-item
              v-for="p in myTouchPresets"
              :key="p.id"
              :active="touchControlsPreset?.id === p.id"
              :title="p.name"
              :data-testid="`rc-touch-controls-${p.id}`"
              @click="setTouchControls(p.id)"
            />
          </template>
          <v-divider />
          <v-list-item
            title="Edit layouts…"
            prepend-icon="mdi-pencil-outline"
            data-testid="rc-touch-controls-edit"
            @click="touchEditorOpen = true"
          />
        </v-list>
      </v-menu>
      <!-- FR-111 P4b-2 — the layout editor: the built-ins (copied, never
           changed), this member's own in this browser, the org's (changed by
           an org admin). The keyboard types into it, never into the host. -->
      <v-dialog v-model="touchEditorOpen" max-width="960" :fullscreen="mobile" scrollable>
        <TouchPresetEditor
          v-if="touchEditorOpen"
          :builtins="BUILTIN_PRESETS"
          :mine="myTouchPresets"
          :org="orgTouchList"
          :can-publish="canPublishTouch"
          :publish="publishTouchPreset"
          :delete-org="deleteOrgTouchPreset"
          :ctrl-is-cmd="rc.hostIsMac.value && rc.ctrlAsCmd.value"
          @save-mine="saveMyTouchPreset"
          @delete-mine="deleteMyTouchPreset"
          @close="touchEditorOpen = false"
        />
      </v-dialog>
      <!-- rc.199 — clipboard send / get: frequent connected-session
           actions, kept on the toolbar (not the Settings panel) at
           every viewport. Relocated here from the retired Row 2.
           Absent when the grant has no CLIPBOARD: the channel they need
           was closed at `rc:session.created` (dropClipboardChannel). -->
      <v-btn
        v-if="rc.phase.value === 'connected' && rc.clipboardGranted.value"
        icon
        variant="text"
        size="small"
        class="mr-1"
        :loading="clipboardBusy"
        :disabled="!!clipboardRefusal"
        aria-label="Send my clipboard to the remote host"
        :title="clipboardRefusal ?? 'Send my clipboard → remote'"
        data-testid="rc-clipboard-send"
        @click="onSendClipboard"
      >
        <v-icon>mdi-content-paste</v-icon>
      </v-btn>
      <v-btn
        v-if="rc.phase.value === 'connected' && rc.clipboardGranted.value"
        icon
        variant="text"
        size="small"
        class="mr-1"
        :loading="clipboardBusy"
        :disabled="!!clipboardRefusal"
        aria-label="Get the remote host's clipboard"
        :title="clipboardRefusal ?? 'Get remote clipboard → me'"
        data-testid="rc-clipboard-get"
        @click="onGetClipboard"
      >
        <v-icon>mdi-content-copy</v-icon>
      </v-btn>
      <!-- FR-85 P3c — record the remote screen. The recording is made and kept
           on the device (a banner shows there while it runs); the menu starts
           and stops it and downloads what this controller recorded. Offered
           only when the session's grant holds RECORD. -->
      <v-chip
        v-if="rc.phase.value === 'connected' && recRunning"
        color="error"
        size="small"
        variant="flat"
        class="mr-1"
        data-testid="rc-rec-chip"
      >
        <v-icon start size="x-small">mdi-record</v-icon>
        REC {{ fmtClock(rec.durationMs.value) }}
      </v-chip>
      <!-- FR-85 P3b-3 — the session dropped mid-recording: the device goes on
           recording for up to a minute, and this session's next connection
           picks it up. -->
      <v-chip
        v-if="rec.state.value === 'reconnecting'"
        color="warning"
        size="small"
        variant="flat"
        class="mr-1"
        title="The device goes on recording for up to a minute while this session reconnects."
        data-testid="rc-rec-reconnecting"
      >
        <v-icon start size="x-small">mdi-record</v-icon>
        REC · reconnecting
      </v-chip>
      <!-- FR-92 — keep busy. The device owns the state; the menu renders
           `rc:keep-busy.state` and asks for changes. -->
      <KeepBusyMenu
        v-if="rc.phase.value === 'connected' && (agentSupportsKeepBusy || rc.keepBusy.value)"
        :state="rc.keepBusy.value"
        :can-control="rc.inputGranted.value"
        :agent-id="agentId"
        :default-pattern="orgKeepBusyDefault"
        @set="rc.setKeepBusy"
      />
      <v-menu
        v-if="rc.phase.value === 'connected' && rc.recordGranted.value"
        :close-on-content-click="false"
        location="bottom end"
      >
        <template #activator="{ props: menuProps }">
          <v-btn
            v-bind="menuProps"
            icon
            variant="text"
            size="small"
            class="mr-1"
            :color="recRunning ? 'error' : undefined"
            aria-label="Record this screen"
            title="Record this screen"
            data-testid="rc-record-btn"
            @click="rec.list()"
          >
            <v-icon>{{ recRunning ? 'mdi-record-circle' : 'mdi-record-circle-outline' }}</v-icon>
          </v-btn>
        </template>
        <v-card min-width="320" max-width="440" data-testid="rc-record-menu">
          <v-card-title class="text-subtitle-1">Record this screen</v-card-title>
          <v-card-text>
            <p class="text-caption mb-3">
              The recording is saved on the device, and a banner shows there while it runs.
            </p>
            <div v-if="recRunning" class="d-flex align-center ga-2">
              <v-chip color="error" size="small" variant="flat">
                <v-icon start size="x-small">mdi-record</v-icon>
                {{ fmtClock(rec.durationMs.value) }} · {{ formatFileSize(rec.bytes.value) }}
              </v-chip>
              <v-btn size="small" color="error" data-testid="rc-record-stop" @click="rec.stop()">
                Stop
              </v-btn>
            </div>
            <div v-else-if="rec.state.value === 'pending_consent'" class="text-body-2">
              Waiting for the person at the device to allow it…
            </div>
            <div v-else>
              <!-- #1760 — where the device says computer audio cannot go into
                   a remote recording (a Mac; the owner has not allowed it),
                   the box is greyed out, unticked, with the sentence beside
                   it: never a box that only fails. A device older than the
                   field says nothing, and the box is offered as before. -->
              <v-checkbox
                v-model="recAudio"
                label="Include what the computer plays"
                density="compact"
                hide-details
                :disabled="!!rec.audioUnavailable.value"
                data-testid="rc-record-audio"
              />
              <p
                v-if="rec.audioUnavailable.value"
                class="text-caption text-medium-emphasis mb-1"
                data-testid="rc-record-audio-unavailable"
              >
                {{ describeRecordReason(rec.audioUnavailable.value) }}
              </p>
              <v-btn
                size="small"
                color="primary"
                class="mt-1"
                data-testid="rc-record-start"
                @click="rec.start(recAudio)"
              >
                Start recording
              </v-btn>
            </div>
            <p
              v-if="rec.reason.value && !recRunning"
              class="text-caption mt-2"
              data-testid="rc-record-reason"
            >
              {{ rec.state.value === 'stopped' ? 'Stopped: ' : 'Not recording: ' }}{{ describeRecordReason(rec.reason.value) }}
              <!-- #1760 — the device's own words, when it sent them. The
                   code's sentence alone read "the recorder could not start"
                   where the device had said why. -->
              <span
                v-if="rec.detail.value"
                class="d-block text-medium-emphasis rc-record-detail"
                data-testid="rc-record-detail"
              >{{ rec.detail.value }}</span>
            </p>
            <v-divider class="my-3" />
            <div class="text-subtitle-2 mb-1">Your recordings on this device</div>
            <v-list v-if="rec.items.value.length" density="compact" class="py-0">
              <v-list-item
                v-for="it in rec.items.value"
                :key="it.name"
                :title="it.name"
                :subtitle="`${fmtClock(it.duration_ms)} · ${formatFileSize(it.bytes)}`"
              >
                <template #append>
                  <v-btn
                    icon
                    size="small"
                    variant="text"
                    :aria-label="`Download ${it.name}`"
                    :disabled="rec.download.value?.status === 'active'"
                    @click="onDownloadRecording(it)"
                  >
                    <v-icon>mdi-download</v-icon>
                  </v-btn>
                </template>
              </v-list-item>
            </v-list>
            <p v-else class="text-caption">None yet.</p>
            <div v-if="rec.download.value" class="mt-2" data-testid="rc-record-download">
              <v-progress-linear
                :model-value="
                  rec.download.value.size
                    ? (100 * rec.download.value.received) / rec.download.value.size
                    : 0
                "
                :color="rec.download.value.status === 'error' ? 'error' : 'primary'"
                height="6"
                rounded
              />
              <div class="text-caption mt-1">
                {{ rec.download.value.name }} · {{ formatFileSize(rec.download.value.received) }}
                <template v-if="rec.download.value.size">
                  of {{ formatFileSize(rec.download.value.size) }}
                </template>
                ·
                <template v-if="rec.download.value.status === 'done'">
                  saved{{ rec.download.value.verified ? ', checksum verified' : '' }}
                </template>
                <template v-else-if="rec.download.value.status === 'paused'">
                  paused — it resumes when the session reconnects
                </template>
                <template v-else-if="rec.download.value.status === 'active'">downloading…</template>
                <template v-else>{{ describeRecordReason(rec.download.value.error) }}</template>
              </div>
              <div
                v-if="rec.download.value.status === 'done' && rec.download.value.verified === null"
                class="text-caption text-medium-emphasis"
                style="word-break: break-all"
              >
                SHA-256 on the device: {{ rec.download.value.sha256 }}
              </div>
              <v-btn
                v-if="rec.download.value.status === 'active' || rec.download.value.status === 'paused'"
                size="x-small"
                variant="text"
                class="mt-1"
                @click="rec.cancelDownload()"
              >
                Cancel
              </v-btn>
            </div>
          </v-card-text>
        </v-card>
      </v-menu>
      <span
        v-else-if="rc.phase.value === 'connected' && showsRecordRefusal(rc.recordRefused.value)"
        :title="`Recording unavailable: ${describeRecordReason(rc.recordRefused.value)}`"
        data-testid="rc-record-refused"
      >
        <v-btn icon variant="text" size="small" class="mr-1" disabled aria-label="Recording unavailable">
          <v-icon>mdi-record-circle-outline</v-icon>
        </v-btn>
      </span>
      <!-- FR-99 P1c — privacy mode. A toggle on a grant that holds PRIVACY:
           the device puts the curtain up after its own gates and says why
           when it does not. A disabled control explains the server's strip
           reason; nothing shows where no curtain could ever be. -->
      <v-btn
        v-if="rc.phase.value === 'connected' && rc.privacyGranted.value"
        icon
        variant="text"
        size="small"
        class="mr-1"
        :color="rc.privacy.on.value ? 'primary' : undefined"
        :loading="rc.privacy.pending.value"
        :disabled="!rc.privacy.ready.value"
        :aria-pressed="rc.privacy.on.value"
        :aria-label="rc.privacy.on.value ? 'Uncover the device screen' : 'Cover the device screen'"
        :title="privacyTitle"
        data-testid="rc-privacy-btn"
        @click="rc.privacy.set(!rc.privacy.on.value)"
      >
        <v-icon>{{ rc.privacy.on.value ? 'mdi-eye-off' : 'mdi-eye-off-outline' }}</v-icon>
      </v-btn>
      <span
        v-else-if="rc.phase.value === 'connected' && showsPrivacyRefusal(rc.privacyRefused.value)"
        :title="`Privacy mode unavailable: ${describePrivacyReason(rc.privacyRefused.value)}`"
        data-testid="rc-privacy-refused"
      >
        <v-btn icon variant="text" size="small" class="mr-1" disabled aria-label="Privacy mode unavailable">
          <v-icon>mdi-eye-off-outline</v-icon>
        </v-btn>
      </span>
      <!-- Transfers chip — in-progress uploads/downloads popover.
           Conditionally rendered so it never clutters the toolbar. -->
      <v-menu
        v-if="
          (rc.phase.value === 'connected' || rc.phase.value === 'reconnecting') &&
          rc.transfers.value.length > 0
        "
        :close-on-content-click="false"
        location="bottom end"
      >
        <template #activator="{ props: menuProps }">
          <v-btn
            v-bind="menuProps"
            icon
            variant="text"
            size="small"
            class="mr-1"
            :aria-label="`${transfersInFlightCount} transfer(s) in progress`"
            :title="`Transfers (${transfersInFlightCount} active, ${rc.transfers.value.length} total)`"
          >
            <v-badge
              v-if="transfersInFlightCount > 0"
              :content="transfersInFlightCount"
              color="primary"
              floating
              location="top end"
              offset-x="-2"
              offset-y="-2"
            >
              <v-icon>mdi-swap-vertical-circle-outline</v-icon>
            </v-badge>
            <v-icon v-else>mdi-swap-vertical-circle-outline</v-icon>
          </v-btn>
        </template>
        <v-card min-width="min(380px, calc(100vw - 24px))" max-width="460">
          <v-toolbar density="compact" color="primary">
            <v-icon class="ml-3">mdi-swap-vertical-circle-outline</v-icon>
            <v-toolbar-title>Transfers</v-toolbar-title>
          </v-toolbar>
          <v-list density="compact" class="pa-0" max-height="400" style="overflow-y: auto">
            <v-list-item
              v-for="t in transfersOrdered"
              :key="t.id"
              :class="`transfer-row transfer-${t.status}`"
            >
              <template #prepend>
                <v-icon :color="transferStatusColor(t)">
                  {{ t.kind === 'upload' ? 'mdi-upload' : 'mdi-download' }}
                </v-icon>
              </template>
              <v-list-item-title class="text-body-2 transfer-name" :title="t.name">
                {{ t.name }}
              </v-list-item-title>
              <v-list-item-subtitle>
                <span class="text-caption">{{ transferStatusLabel(t) }}</span>
                <v-progress-linear
                  v-if="
                    t.status === 'running' ||
                    t.status === 'queued' ||
                    t.status === 'reconnecting'
                  "
                  :model-value="transferProgressPct(t)"
                  :indeterminate="t.total === null"
                  color="primary"
                  height="4"
                  class="mt-1"
                />
              </v-list-item-subtitle>
              <template #append>
                <v-btn
                  v-if="
                    t.status === 'running' ||
                    t.status === 'queued' ||
                    t.status === 'reconnecting'
                  "
                  icon
                  size="x-small"
                  variant="text"
                  title="Cancel"
                  @click="rc.cancelTransfer(t.id)"
                >
                  <v-icon>mdi-close-circle-outline</v-icon>
                </v-btn>
                <v-icon v-else-if="t.status === 'complete'" color="success">
                  mdi-check-circle
                </v-icon>
                <v-icon v-else-if="t.status === 'error'" color="error" :title="t.error">
                  mdi-alert-circle
                </v-icon>
                <v-icon v-else-if="t.status === 'cancelled'" color="grey">
                  mdi-cancel
                </v-icon>
              </template>
            </v-list-item>
          </v-list>
        </v-card>
      </v-menu>
      <!-- Unmute affordance: only shown when the browser blocked
           autoplay-with-sound for the received host-audio track (no
           prior user gesture on the page). The click IS the gesture,
           so it retries playback. Amber to stand out. -->
      <v-btn
        v-if="rc.audioAutoplayBlocked.value"
        color="warning"
        variant="flat"
        size="small"
        class="mr-1"
        prepend-icon="mdi-volume-off"
        aria-label="Unmute host audio (autoplay was blocked)"
        title="Click to hear the host's audio — the browser blocked autoplay"
        @click="onUnmuteAudio"
      >
        Unmute
      </v-btn>
      <v-btn
        v-if="rc.phase.value === 'idle' || rc.phase.value === 'closed' || rc.phase.value === 'error'"
        data-tour="viewer-connect"
        color="primary"
        variant="flat"
        prepend-icon="mdi-play"
        class="rc-tb-session"
        :disabled="!canConnect"
        @click="startSession"
      >
        Connect
      </v-btn>
      <v-btn
        v-else
        color="error"
        variant="flat"
        prepend-icon="mdi-stop"
        class="rc-tb-session"
        aria-label="Disconnect"
        @click="leave()"
      >
        <!-- Icon-only on a phone, where the row has no room for the word. -->
        <span class="d-none d-sm-inline">Disconnect</span>
      </v-btn>
      <!-- Fullscreen: gated on (a) connected session AND (b) the
           document supports the Fullscreen API. iOS Safari only
           supports `webkitEnterFullscreen` on `<video>` elements,
           and won't show overlay canvases (cursor / stats), so we
           hide the button on iOS rather than pretend it works.
           ESC exits natively. -->
      <v-btn
        v-if="rc.phase.value === 'connected' && fullscreenEnabled"
        icon
        variant="text"
        size="small"
        class="ml-1 rc-tb-fullscreen"
        :aria-label="isFullscreen ? 'Exit fullscreen' : 'Enter fullscreen'"
        :title="isFullscreen ? 'Exit fullscreen (hold Esc)' : fullscreenButtonTooltip"
        @click="toggleFullscreen"
      >
        <v-icon>{{ isFullscreen ? 'mdi-fullscreen-exit' : 'mdi-fullscreen' }}</v-icon>
      </v-btn>
    </v-toolbar>

    <!-- File input (hidden); shared between Row 2 inline upload
         button and the bottom-sheet upload button. `multiple`
         lets the operator queue several files in one picker
         dialog (Phase 1 of file-DC v2). -->
    <input
      ref="fileInput"
      type="file"
      multiple
      style="display: none"
      @change="onFilePicked"
    />

    <!-- Viewer. Wrapped in a Material-elevation v-card so the
         render pane reads as a window into another machine —
         distinct from the host UI's toolbar/page chrome. The card
         is OUTSIDE the fullscreen target (`.video-frame`), so it
         disappears in fullscreen automatically (operator wants
         edge-to-edge pixels in that mode). -->
    <v-card
      variant="elevated"
      elevation="2"
      rounded="lg"
      border
      class="ma-2 ma-md-3 remote-stage-card flex-grow-1 d-flex"
    >
    <div class="remote-stage">
      <!-- An overlay along the top of the stage. As flex siblings of the
           picture in a ROW flexbox these alerts were 32 px strips beside it at
           every width — text, icon and close invisible — and each one's
           coming and going resized the frame, which re-sent rc:resolution
           (and rebuilt the agent's encoder) in Fit mode. Here the frame keeps
           its size; only the alerts themselves take a click. -->
      <div class="rc-stage-alerts">
      <v-alert
        v-if="rc.error.value"
        type="error"
        variant="tonal"
        class="ma-4"
        closable
        @click:close="rc.error.value = null"
      >
        {{ rc.error.value }}
      </v-alert>

      <!-- PR-1 rehome: non-terminal progress notice (e.g. rerouting to
           the device's pod). Retries continue underneath; never shown
           as an error and never carries pod internals. -->
      <v-alert
        v-if="rc.notice.value && !rc.error.value"
        type="info"
        variant="tonal"
        density="comfortable"
        class="ma-4"
      >
        {{ rc.notice.value }}
      </v-alert>

      <!-- FR-93 P1 — the agent says this session's mouse and keyboard will not
           reach the whole desktop. An injector that reaches nothing does not
           fail, so before this a GNOME Wayland session looked interactive and
           did nothing. Only for a session that HAS input: a view-only grant
           is already its own state. -->
      <v-alert
        v-if="rc.inputReach.value && rc.inputGranted.value && rc.phase.value === 'connected'
          && rc.inputReach.value !== dismissedInputReach"
        type="warning"
        variant="tonal"
        density="comfortable"
        class="ma-4"
        closable
        data-testid="rc-input-reach"
        @click:close="dismissedInputReach = rc.inputReach.value"
      >
        <strong>{{ rc.inputReach.value.reach === 'xwayland_only'
          ? 'Your mouse and keyboard reach only some apps on this device.'
          : 'Your mouse and keyboard do not reach this device’s desktop.' }}</strong>
        {{ asSentence(rc.inputReach.value.reason) }}
      </v-alert>

      <!-- FR-101 P4b-2b — the device's idle limit is about to end this session
           (`rc:idle`): no input from here and no change on its screen for a
           while. Any input sent from here withdraws it at once; the device
           withdraws it too when its screen comes alive. -->
      <v-alert
        v-if="idleLeft !== null && rc.phase.value === 'connected'"
        type="warning"
        variant="tonal"
        density="comfortable"
        class="ma-4"
        data-testid="rc-idle-warning"
      >
        <strong>No activity for a while.</strong>
        This session ends in {{ idleLeft }} s. Move the mouse or press a key over the remote
        screen to keep it.
      </v-alert>
      </div>

      <div v-if="rc.phase.value === 'idle' || rc.phase.value === 'closed'" class="empty-state">
        <!-- FR-27 P10 - the person at the device ended the session. Said in
             so many words, and the viewer stays put: reconnecting from here is
             an explicit act, and it goes through consent like any new session. -->
        <template v-if="rc.endedBy.value === 'host'">
          <v-icon size="96" color="warning">mdi-account-off-outline</v-icon>
          <p class="text-h6 mt-2" data-testid="rc-ended-by-host">
            {{ t('remote.session.endedByHost.title') }}
          </p>
          <p class="text-body-2 text-medium-emphasis">
            {{ t('remote.session.endedByHost.body') }}
          </p>
          <v-btn
            color="primary"
            variant="flat"
            size="small"
            class="mt-3"
            prepend-icon="mdi-refresh"
            :disabled="!canConnect"
            data-testid="rc-ended-by-host-reconnect"
            @click="startSession"
          >
            {{ t('remote.session.endedByHost.reconnect') }}
          </v-btn>
        </template>
        <template v-else>
          <v-icon size="96" color="grey-lighten-1">mdi-desktop-classic</v-icon>
          <p class="text-body-1 mt-2">
            Click <strong>Connect</strong> to start a remote-control session.
          </p>
        </template>
        <!-- FR-102 P9b — after a session of 30 s or more, at most once a day:
             a thumb and optional reason chips, dismissible, never a dialog.
             Mounted here and in the error ending below — two branches of this
             one v-if chain, so at most one ever renders (locked by
             `rcRatingMount.spec.ts`). -->
        <session-rating-prompt
          v-if="ratingPending"
          :status="ratingStatus"
          class="mt-3"
          @submit="submitRating"
          @dismiss="dismissRating"
        />
        <p v-if="agent && !agent.is_online" class="text-caption text-medium-emphasis">
          This agent is currently offline. The session will fail until the agent
          reconnects.
        </p>
        <!-- Not offered right after the person at the device ended the session:
             their Disconnect is an explicit "stop", and the next step offered is
             Reconnect, which asks them again. Break-glass stays available from a
             fresh page, with its reason, audit and owner notice (operator,
             2026-10-10). -->
        <v-btn
          v-if="rc.endedBy.value !== 'host'"
          variant="text"
          size="small"
          color="warning"
          class="mt-3"
          prepend-icon="mdi-shield-key-outline"
          :disabled="!canConnect"
          data-testid="rc-force-control"
          @click="forceDialogOpen = true"
        >
          <!-- FR-116 D6 — the label cannot wrap, and whole it ran 2 px past a
               360 px screen; the dialog behind it says what break-glass is. -->
          Force control<span class="d-none d-sm-inline">&nbsp;(admin break-glass)</span>
        </v-btn>

        <!-- Phase 5 — admin break-glass. Starts the session skipping the device's
             consent; only works for a tenant administrator (server-validated) and
             is recorded in the audit log. -->
        <v-dialog v-model="forceDialogOpen" max-width="460">
        <v-card>
          <v-card-title>Force control (break-glass)</v-card-title>
          <v-card-text>
            <p class="text-body-2 mb-3">
              This starts the session <strong>without</strong> the device's consent.
              It only works if you're a tenant administrator, and it's recorded in the
              audit log. Enter a reason:
            </p>
            <v-textarea
              v-model="forceReason"
              label="Reason (required)"
              rows="2"
              auto-grow
              autofocus
              variant="outlined"
              density="compact"
              hide-details
            />
          </v-card-text>
          <v-card-actions>
            <v-spacer />
            <v-btn variant="text" @click="forceDialogOpen = false">Cancel</v-btn>
            <v-btn
              color="warning"
              variant="flat"
              :disabled="!forceReason.trim()"
              @click="confirmForce"
            >
              Force control
            </v-btn>
          </v-card-actions>
        </v-card>
        </v-dialog>
      </div>

      <!-- FR-93 P5j — the computer said it was going to sleep, and this viewer
           is redialling it. Before, every attempt read "Requesting session…" or
           "Connection lost" for as long as the computer slept. -->
      <div
        v-else-if="asleepWhileRedialling"
        class="empty-state"
        data-testid="rc-host-asleep"
      >
        <v-icon size="72" color="info">mdi-sleep</v-icon>
        <p class="text-body-1 mt-3">{{ mediaWaitingCopy('host_sleep').title }}</p>
        <p v-if="asleepWhileRedialling.hint" class="text-body-2 text-medium-emphasis mt-2 mx-auto no-media-hint">
          {{ asleepWhileRedialling.hint }}
        </p>
        <p class="text-caption text-medium-emphasis mt-2">
          <template v-if="rc.phase.value === 'reconnecting'">
            Reconnecting by itself once it is back (attempt {{ rc.reconnectAttempt.value }})…
          </template>
          <template v-else>{{ phaseLabel }}</template>
        </p>
        <v-btn variant="tonal" size="small" class="mt-3" @click="leave()">
          Cancel
        </v-btn>
      </div>

      <div
        v-else-if="['requesting', 'awaiting_consent', 'negotiating'].includes(rc.phase.value)"
        class="empty-state"
      >
        <v-progress-circular indeterminate size="64" />
        <p class="text-body-1 mt-4">{{ phaseLabel }}</p>
      </div>

      <!-- S3 — previously the 'reconnecting' and 'error' phases fell
           through every v-else-if and rendered a BLANK stage. -->
      <div v-else-if="rc.phase.value === 'reconnecting'" class="empty-state">
        <v-progress-circular indeterminate size="64" color="warning" />
        <p class="text-body-1 mt-4">
          Connection lost — reconnecting (attempt {{ rc.reconnectAttempt.value }})…
        </p>
        <p class="text-caption text-medium-emphasis">
          The session re-creates itself automatically. This can take a few
          seconds while the device comes back.
        </p>
        <p v-if="agent && !agent.is_online" class="text-caption text-warning">
          The device currently reports offline — retries continue until it
          returns.
        </p>
        <v-btn variant="tonal" size="small" class="mt-3" @click="leave()">
          Cancel
        </v-btn>
      </div>

      <div v-else-if="rc.phase.value === 'error'" class="empty-state">
        <v-icon size="96" color="error">mdi-connection</v-icon>
        <p class="text-body-1 mt-2">The session could not continue.</p>
        <p v-if="rc.error.value" class="text-caption text-medium-emphasis">
          {{ rc.error.value }}
        </p>
        <!-- FR-102 P9b — a failed attempt of 30 s or more is worth asking
             about too ("couldn't connect" is a chip). The other branch of the
             chain above; never both. -->
        <session-rating-prompt
          v-if="ratingPending"
          :status="ratingStatus"
          class="mt-3"
          @submit="submitRating"
          @dismiss="dismissRating"
        />
        <v-btn
          color="primary"
          variant="flat"
          size="small"
          class="mt-3"
          prepend-icon="mdi-refresh"
          :disabled="!canConnect"
          @click="startSession"
        >
          Try again
        </v-btn>
        <!-- FR-100 P2a — the device answered with another key than the one
             this browser knows. Trusting it is the person's call, made here
             and nowhere else: it pins that one key, and the next answer must
             still prove it. -->
        <v-btn
          v-if="rc.peerAuth.value?.verdict.kind === 'key-changed'"
          color="warning"
          variant="tonal"
          size="small"
          class="mt-3"
          prepend-icon="mdi-key-change"
          :disabled="!canConnect"
          data-testid="rc-peer-auth-trust"
          @click="trustNewKeyAndConnect"
        >
          Trust the new key and connect
        </v-btn>
      </div>

      <div
        v-else-if="rc.phase.value === 'connected'"
        ref="stageEl"
        class="video-frame"
        :class="[`scale-${rc.scaleMode.value}`, { 'drag-over': isDragOver }]"
        :style="{ cursor: remoteCursorCss ?? 'none', touchAction: stageTouchActionCss }"
        tabindex="0"
        @scroll.passive="onStageScroll"
        @pointermove="onStagePointerMove"
        @pointerleave="cursorVisible = false"
        @pointerenter="cursorVisible = true"
        @dragenter.prevent.stop="onStageDragEnter"
        @dragover.prevent.stop="onStageDragOver"
        @dragleave.prevent.stop="onStageDragLeave"
        @drop.prevent.stop="onStageDrop"
      >
        <!-- Classic render path: <video> bound to the remote MediaStream.
             Used unless the viewer opted into the WebCodecs path AND
             the browser supports it. We still render the <video>
             element in WebCodecs mode but hide it — input + cursor
             math hang off `rc.mediaIntrinsicW/H` which the composable
             keeps in sync either way. -->
        <video
          v-show="!isWebCodecsRender && !isVp9_444Render && !isHevcRender"
          ref="videoEl"
          autoplay
          playsinline
          muted
          class="remote-video"
          :class="`scale-${rc.scaleMode.value}`"
          :style="videoScaleStyle"
        />
        <!-- Opt-in host-audio sink. Separate element (NOT the muted
             <video> above, which may carry no track at all when video
             travels over the DataChannel/canvas path). The watcher
             binds `rc.remoteAudioStream` here; `autoplay` handles the
             common case, and the unmute button below covers browsers
             that block autoplay-with-sound. Kept out of the layout. -->
        <audio
          ref="audioEl"
          autoplay
          style="display: none;"
        />
        <!-- Low-latency render path: canvas fed by the Worker-driven
             VideoDecoder. transferControlToOffscreen() happens once
             per session in the composable; this element is the main-
             thread handle we bind the canvas ref on. Same scale
             classes + style as the video so the existing layout +
             cursor overlays keep working. -->
        <canvas
          v-if="isWebCodecsRender"
          :ref="bindWebcodecsCanvas"
          class="remote-video webcodecs-canvas"
          :class="`scale-${rc.scaleMode.value}`"
          :style="videoScaleStyle"
        />
        <!-- Phase Y.4 render path: canvas fed by the VP9-444 worker
             over a `video-bytes` DataChannel (no WebRTC video track,
             no RTCRtpScriptTransform). Mounts when the composable's
             `vp9_444Active` flag flips true (DC opened + worker
             initialised). The composable's watcher transfers control
             of this canvas to the worker via `transferControlToOffscreen`,
             replacing the synthetic OffscreenCanvas it started with.
             Same scale classes + style as the video for layout
             parity. -->
        <canvas
          v-if="isVp9_444Render"
          :ref="bindVp9_444Canvas"
          class="remote-video vp9-444-canvas"
          :class="`scale-${rc.scaleMode.value}`"
          :style="videoScaleStyle"
        />
        <!-- rc.80 render path: canvas fed by the HEVC worker over the
             same `video-bytes` DataChannel (no WebRTC video track).
             Mounts when the composable's `hevcActive` flag flips
             true. Same `transferControlToOffscreen` wiring as the
             VP9-444 path — the composable's watcher swaps the
             synthetic OffscreenCanvas the worker started with for
             this visible element. -->
        <canvas
          v-if="isHevcRender"
          :ref="bindHevcCanvas"
          class="remote-video hevc-canvas"
          :class="`scale-${rc.scaleMode.value}`"
          :style="videoScaleStyle"
        />
        <!-- Live stats readout (codec + bitrate + fps + resolution) moved
             OUT of the video canvas into the toolbar (2026-07-21) — over the
             video it covered a maximized remote window's caption/close
             buttons. See the `.stats-readout` block in the toolbar above. -->
        <!-- FR-80 — the host told us it cannot capture. This takes the place
             of the generic "waiting for a video track" text, because that
             text describes a different failure and reading it while the real
             cause sits in the host's log is how an operator loses an hour. -->
        <div v-if="rc.mediaUnavailable.value" class="no-media-overlay">
          <v-icon size="72" color="warning">mdi-monitor-off</v-icon>
          <p class="text-body-1 mt-3">This device cannot capture its screen.</p>
          <p v-if="rc.mediaUnavailable.value.hint" class="text-body-2 text-medium-emphasis mt-2 mx-auto no-media-hint">
            {{ rc.mediaUnavailable.value.hint }}
          </p>
          <p class="text-caption text-medium-emphasis mt-2">
            Reported by the device as
            <code>{{ rc.mediaUnavailable.value.code }}</code>.
            <span v-if="rc.mediaUnavailable.value.detail">{{ rc.mediaUnavailable.value.detail }}</span>
          </p>
          <p class="text-caption text-medium-emphasis mt-1">
            Remote shell, file transfer and the other channels are unaffected.
          </p>
        </div>
        <!-- FR-93 P2d-2 — the host is asking the person at its screen to share
             it. Before this the canvas stayed blank and the viewer re-created
             the session every 10 s, so the session the person answered for was
             rarely the one on screen. -->
        <div v-else-if="rc.mediaWaiting.value" class="no-media-overlay" data-testid="rc-media-waiting">
          <v-icon size="72" color="info">mdi-timer-sand</v-icon>
          <!-- FR-93 P5b — worded by what the host waits for: a dialog, or
               (screen_unlock) GNOME's lock screen, where no request ends. -->
          <p class="text-body-1 mt-3">{{ mediaWaitingCopy(rc.mediaWaiting.value.for).title }}</p>
          <p v-if="rc.mediaWaiting.value.hint" class="text-body-2 text-medium-emphasis mt-2 mx-auto no-media-hint">
            {{ rc.mediaWaiting.value.hint }}
          </p>
          <p v-if="mediaWaitingCopy(rc.mediaWaiting.value.for).showsDeadline" class="text-caption text-medium-emphasis mt-2">
            If nobody answers, the request ends at {{ mediaWaitingEnds }}.
          </p>
        </div>
        <div v-else-if="!rc.hasMedia.value" class="no-media-overlay">
          <v-icon size="72" color="grey-lighten-1">mdi-video-off</v-icon>
          <p class="text-body-1 mt-3">Connected — waiting for agent to publish a video track.</p>
          <p class="text-caption text-medium-emphasis mt-1">
            The agent needs to be built with the media feature
            (<code>--features media</code>) to send video.
            Input events flow as soon as the input channel is open.
          </p>
        </div>
        <!-- Remote cursor overlay: canvas painted with the real OS
             cursor bitmap received over the `cursor` data channel
             (1E.3). Position is translated from agent-source pixels
             into viewer-local pixels using the same letterbox
             correction the input coords use. If no shape bitmap has
             arrived yet, fall back to the initials badge. -->
        <canvas
          v-if="remoteCursorVisible"
          ref="cursorCanvas"
          class="remote-cursor-canvas"
          :width="remoteCursorSize.w"
          :height="remoteCursorSize.h"
          :style="{ transform: `translate(${remoteCursorX}px, ${remoteCursorY}px)` }"
        />
        <!-- Synthetic cursor with the controller's initials. Hidden
             native cursor over the surface (cursor: none) so this is
             the only pointer indicator; floats at the last
             pointermove position. Shows when the remote cursor
             hasn't advertised yet or to mark additional controllers
             in multi-watcher sessions. -->
        <div
          v-if="!remoteCursorVisible && !remoteCursorCss && cursorVisible && controllerInitials"
          class="cursor-badge"
          :style="{ transform: `translate(${cursorX}px, ${cursorY}px)` }"
        >
          <div class="cursor-arrow" />
          <div class="cursor-chip">{{ controllerInitials }}</div>
        </div>
        <!-- P6 — ghost cursors: other sessions' pointers (agent
             rebroadcast, normalized coords → the same letterbox math as
             the OS cursor). Name-tagged; fade out 5 s after the peer's
             pointer goes still. pointer-events: none — never eats input. -->
        <div
          v-for="g in ghostCursors"
          :key="g.sid"
          class="ghost-cursor"
          :style="{ transform: `translate(${g.left}px, ${g.top}px)` }"
        >
          <div class="cursor-arrow" />
          <div class="cursor-chip ghost-chip">{{ g.name }}</div>
        </div>
        <!-- FR-111 P3 — the on-screen controls. Inside the stage, which is
             the fullscreen element, so they stay in fullscreen. A touch on a
             control stays with it; a touch anywhere else reaches the stage. -->
        <TouchControls
          v-if="touchControlsPreset"
          :preset="touchControlsPreset"
          :sink="rc.touchControlsSink"
          :scroll-x="stageScroll.x"
          :scroll-y="stageScroll.y"
          :ctrl-is-cmd="rc.hostIsMac.value && rc.ctrlAsCmd.value"
        />
        <!-- Keyboard-lock affordances. Plain divs INSIDE the fullscreen
             element (.video-frame) — Vuetify snackbars teleport to
             <body>, which is invisible in fullscreen. pointer-events:
             none so they never eat clicks meant for the remote. -->
        <div v-if="shortcutOverlayVisible" class="kb-lock-toast">
          <v-icon size="small" class="mr-2">mdi-keyboard-variant</v-icon>
          Shortcuts now go to the remote host — hold Esc to exit fullscreen.
          Ctrl+Alt+End sends Ctrl+Alt+Del.
        </div>
        <div
          v-else-if="isFullscreen && rc.keyboardLockActive.value"
          class="kb-lock-pill"
          title="System shortcuts (Alt+Tab, Win, Ctrl+W) go to the remote host. Hold Esc to exit fullscreen."
        >
          <v-icon size="x-small" class="mr-1">mdi-keyboard-variant</v-icon>
          <span>remote keys</span>
        </div>
        <!-- FR-109 — relative mode is on and the pointer is hidden: say how
             to get it back. Under Keyboard Lock Esc reaches the host, so the
             browser wants it held. -->
        <div
          v-if="rc.relativeMouse.value"
          class="relative-mouse-hint"
          data-testid="rc-relative-mouse-hint"
        >
          <v-icon size="x-small" class="mr-1">mdi-cursor-move</v-icon>
          <span>{{ (rc.relativeMouseAuto.value ? 'The host hid its cursor, so the mouse is relative' : 'Relative mouse')
            + (rc.keyboardLockActive.value ? ': hold Esc to release it' : ': Esc releases it') }}</span>
        </div>
        <!-- FR-111 decision 4 — two fingers are panning a zoomed picture, so
             say why the host did not scroll. -->
        <div
          v-if="touchPanHint"
          class="relative-mouse-hint"
          data-testid="rc-touch-pan-hint"
        >
          <v-icon size="x-small" class="mr-1">mdi-gesture-swipe</v-icon>
          <span>Two fingers move the zoomed picture; zoom out to scroll the host</span>
        </div>
      </div>
    </div>
    </v-card>
    <!-- Custom-resolution dialog. Opened when the operator picks the
         "Custom…" option in the Resolution dropdown; submits an
         rc:resolution {mode:'custom'} message on confirm. -->
    <v-dialog v-model="customResolutionDialog" max-width="480">
      <v-card>
        <v-card-title>Custom remote resolution</v-card-title>
        <v-card-text>
          <!-- rc.35 — native-source hint. Surfaces the agent's actual
               panel resolution so the operator knows the upper bound
               before picking a preset. Empty until the first frame
               has arrived, in which case we show a placeholder
               explanation instead. -->
          <div class="text-caption text-medium-emphasis mb-3">
            <template v-if="nativeSourceLabel">
              Agent native source: <strong>{{ nativeSourceLabel }}</strong>.
              Values above this are capped to native — the capture
              backend cannot upscale.
            </template>
            <template v-else>
              Agent's native dimensions haven't been observed yet — they
              show up after the first decoded frame. Values larger than
              the agent's panel resolution will be silently capped.
            </template>
          </div>
          <div class="d-flex align-center mb-3">
            <v-text-field
              v-model.number="customResolutionW"
              type="number"
              min="160"
              max="7680"
              step="10"
              density="compact"
              hide-details
              variant="outlined"
              label="Width"
              class="mr-2"
            />
            <span class="text-medium-emphasis mr-2">×</span>
            <v-text-field
              v-model.number="customResolutionH"
              type="number"
              min="120"
              max="4320"
              step="10"
              density="compact"
              hide-details
              variant="outlined"
              label="Height"
            />
          </div>
          <!-- rc.35 — presets that exceed the agent native source get
               a 'warning' color + 'capped' suffix; presets at-or-under
               render normally. Click still applies (operator might
               want the preset value committed even if capped). -->
          <v-chip-group column>
            <v-chip
              v-for="p in customResolutionPresets"
              :key="`${p.w}x${p.h}`"
              size="small"
              :variant="presetExceedsNative(p.w, p.h) ? 'tonal' : 'outlined'"
              :color="presetExceedsNative(p.w, p.h) ? 'warning' : undefined"
              :prepend-icon="presetExceedsNative(p.w, p.h) ? 'mdi-alert-circle-outline' : undefined"
              @click="pickCustomResolutionPreset(p.w, p.h)"
            >
              {{ p.w }} × {{ p.h }}{{ p.note ? ` — ${p.note}` : '' }}{{ presetExceedsNative(p.w, p.h) ? ' (capped)' : '' }}
            </v-chip>
          </v-chip-group>
          <!-- Live warning when the operator types dims exceeding the
               native source. Read from the form inputs, not the
               applied rc.resolution, so it updates as the operator
               types. -->
          <div
            v-if="presetExceedsNative(customResolutionW, customResolutionH) && nativeSourceLabel"
            class="text-caption mt-2"
            style="color: rgb(var(--v-theme-warning));"
          >
            <v-icon size="small" class="mr-1">mdi-alert-circle-outline</v-icon>
            {{ customResolutionW }} × {{ customResolutionH }} exceeds native
            {{ nativeSourceLabel }}. The agent will cap at native — applying
            this value is equivalent to picking "Original resolution".
          </div>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="customResolutionDialog = false">Cancel</v-btn>
          <v-btn
            color="primary"
            variant="flat"
            :disabled="!customResolutionValid"
            @click="confirmCustomResolution"
          >
            Apply
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <!-- ============================================================
         rc.199 — unified Settings panel. ONE responsive surface for
         every viewport (fullscreen on phones, a centred card on
         desktop), opened by the toolbar gear. Replaces the duplicated
         desktop Row 2 + the mobile bottom-sheet. Frequent actions
         (fullscreen, Ctrl-Alt-Del, clipboard, disconnect, the stats
         badge) stay on the toolbar; everything configurable lives here,
         grouped: Video (host encode) / Display (viewer) / Session.
         ============================================================ -->
    <v-dialog v-model="settingsOpen" :fullscreen="mobile" :max-width="mobile ? undefined : 560" scrollable>
      <v-card class="rc-settings-card">
        <v-toolbar density="comfortable" color="surface">
          <v-icon class="ml-3">mdi-tune-variant</v-icon>
          <v-toolbar-title>Viewer settings</v-toolbar-title>
          <v-spacer />
          <v-btn icon variant="text" title="Close" aria-label="Close settings" @click="settingsOpen = false">
            <v-icon>mdi-close</v-icon>
          </v-btn>
        </v-toolbar>
        <!-- FR-26 — four tabs instead of one long scroll. The dialog is
             fullscreen on a phone, where ~8 stacked buttons plus three
             sections meant the Session tools were below two screenfuls. -->
        <!-- show-arrows: Vuetify hides the slide arrows below 1280 px unless
             asked, and four icon tabs need ~480 px — the Session tab sat 6 px
             into view on a 360 px phone. -->
        <v-tabs v-model="settingsTab" density="comfortable" color="primary" grow show-arrows>
          <v-tab value="video" prepend-icon="mdi-video-outline">Video</v-tab>
          <v-tab value="display" prepend-icon="mdi-monitor-screenshot">Display</v-tab>
          <v-tab value="metrics" prepend-icon="mdi-speedometer">Metrics</v-tab>
          <v-tab value="session" prepend-icon="mdi-tools">Session</v-tab>
        </v-tabs>
        <v-divider />
        <v-card-text class="pa-3 pa-md-4">
          <v-tabs-window v-model="settingsTab">
          <v-tabs-window-item value="video">
          <!-- A. VIDEO — host-side capture/encode; applies on next Connect -->
          <div class="d-flex align-center ga-2 mb-3">
            <v-icon size="small" color="primary">mdi-video-outline</v-icon>
            <span class="text-subtitle-2 font-weight-medium">Video</span>
            <v-chip size="x-small" variant="tonal" color="info" label>applies on next Connect</v-chip>
          </div>
          <!-- FR-77 — the codec picker is TWO independent axes, codec × colour
               detail (chroma format). Validity is a matrix: an entry that cannot
               pair with the other dropdown's value is greyed with the reason, and
               "Auto" on either axis lets the Priority dial decide. -->
          <div class="d-flex flex-column flex-sm-row ga-2 mb-4">
            <v-select
              v-model="pickerCodec"
              :items="codecOptions"
              item-title="title"
              item-value="value"
              density="comfortable"
              variant="outlined"
              hide-details="auto"
              prepend-inner-icon="mdi-video-outline"
              :label="t('remote.codec.label')"
              class="flex-grow-1"
              data-testid="rc-picker-codec"
            />
            <v-select
              v-model="pickerChroma"
              :items="chromaOptions"
              item-title="title"
              item-value="value"
              density="comfortable"
              variant="outlined"
              hide-details="auto"
              prepend-inner-icon="mdi-palette-outline"
              :label="t('remote.codec.chromaLabel')"
              class="flex-grow-1"
              data-testid="rc-picker-chroma"
            />
          </div>
          <v-select
            v-model="resolutionPresetValue"
            :items="resolutionOptions"
            density="comfortable"
            variant="outlined"
            hide-details="auto"
            prepend-inner-icon="mdi-monitor-screenshot"
            label="Resolution"
            :hint="resolutionSettingHint"
            persistent-hint
            class="mb-4"
          />
          <div class="text-caption text-medium-emphasis mb-1 ml-1">Priority</div>
          <v-btn-toggle
            v-model="priority"
            mandatory
            divided
            color="primary"
            variant="outlined"
            density="comfortable"
            class="mb-1 d-flex w-100"
          >
            <v-btn value="balanced" size="small" class="flex-grow-1">Balanced</v-btn>
            <v-btn value="sharper" size="small" class="flex-grow-1">Sharper</v-btn>
            <v-btn value="smoother" size="small" class="flex-grow-1">Smoother</v-btn>
          </v-btn-toggle>
          <div class="text-caption text-medium-emphasis mb-2 ml-1">{{ priorityHint }}</div>
          <!-- FR-119 P1 — the frame rate, offered only by an agent that can be
               asked (`fps-high` in its video caps). It answers in rc:video-info:
               what the stream runs at, and why not when it refused an ask. -->
          <v-select
            v-if="frameRateOffered"
            v-model="frameRatePick"
            :items="frameRateItems"
            item-title="title"
            item-value="value"
            density="comfortable"
            variant="outlined"
            hide-details="auto"
            prepend-inner-icon="mdi-speedometer"
            label="Frame rate"
            :hint="frameRateHint"
            persistent-hint
            class="mt-3 mb-2"
            data-testid="rc-picker-fps"
          />

          </v-tabs-window-item>

          <v-tabs-window-item value="display">
          <!-- B. DISPLAY — viewer-side scaling + sharpening; live -->
          <div class="d-flex align-center ga-2 mb-3">
            <v-icon size="small" color="primary">mdi-fit-to-screen-outline</v-icon>
            <span class="text-subtitle-2 font-weight-medium">Display</span>
            <v-chip size="x-small" variant="tonal" color="success" label>live</v-chip>
          </div>
          <v-select
            v-model="scaleMode"
            :items="scaleOptions"
            density="comfortable"
            variant="outlined"
            hide-details="auto"
            prepend-inner-icon="mdi-image-size-select-actual"
            label="Fit in my window"
            :hint="displayScaleSettingHint"
            persistent-hint
            class="mb-4"
          />
          <v-text-field
            v-if="scaleMode === 'custom'"
            v-model.number="scalePercent"
            type="number"
            min="5"
            max="1000"
            step="5"
            density="comfortable"
            variant="outlined"
            hide-details
            suffix="%"
            label="Custom zoom"
            class="mb-4"
          />
          <v-btn
            block
            variant="tonal"
            :color="displayMatchOn ? 'primary' : undefined"
            :disabled="!agentSupportsDisplayMatch"
            prepend-icon="mdi-monitor-screenshot"
            :title="displayMatchTooltip"
            @click="toggleDisplayMatch"
          >
            1:1 Match host display — {{ displayMatchOn ? 'ON' : 'OFF' }}
          </v-btn>
          <div
            v-if="displayMatchSaid"
            class="text-caption text-medium-emphasis mt-1 ml-1"
            data-testid="rc-display-match-said"
          >
            {{ displayMatchSaid }}
          </div>
          <div class="text-caption text-medium-emphasis mb-1 ml-1 mt-4">Text sharpening (FSR)</div>
          <v-btn-toggle
            v-model="sharpen"
            mandatory
            divided
            color="primary"
            variant="outlined"
            density="comfortable"
            class="mb-1 d-flex w-100"
          >
            <v-btn value="auto" size="small" class="flex-grow-1">Auto</v-btn>
            <v-btn value="on" size="small" class="flex-grow-1">On</v-btn>
            <v-btn value="off" size="small" class="flex-grow-1">Off</v-btn>
          </v-btn-toggle>
          <div class="text-caption text-medium-emphasis mb-2 ml-1">{{ sharpenHint }}</div>
          <v-checkbox
            v-model="hideDeviceName"
            density="compact"
            hide-details="auto"
            class="mt-2"
            label="Hide device name when a display name is set"
            messages="The same setting as on the Devices page"
          />

          </v-tabs-window-item>

          <v-tabs-window-item value="metrics">
          <!-- FR-26 — one checkbox per pill in the toolbar readout. All on
               except `paint`: the per-hop numbers answer a question you only
               ask while chasing an fps ceiling. -->
          <div class="d-flex align-center ga-2 mb-1">
            <v-icon size="small" color="primary">mdi-speedometer</v-icon>
            <span class="text-subtitle-2 font-weight-medium">Quality metrics</span>
          </div>
          <!-- The toolbar readout is md and up (d-none d-md-flex), so on a phone
               the values under each item below are the only readout. -->
          <div class="text-caption text-medium-emphasis mb-2 ml-1">
            Shown in the toolbar while a session is connected, on wider screens;
            the live value is under each item here.
          </div>
          <v-checkbox
            v-model="metrics.codec"
            density="compact"
            hide-details="auto"
            label="Codec, transport and decoder"
            :messages="statsCodecLabel || 'e.g. AV1 4:2:0 HW (av1_qsv) · direct · dec HW · FSR'"
          />
          <v-checkbox
            v-model="metrics.bitrate"
            density="compact"
            hide-details="auto"
            label="Bitrate"
            :messages="statsBitrateLabel || 'e.g. 1.8 Mbps'"
          />
          <v-checkbox
            v-model="metrics.fps"
            density="compact"
            hide-details="auto"
            label="Frame rate"
            :messages="statsFpsLabel || 'e.g. 13 fps'"
          />
          <v-checkbox
            v-model="metrics.resolution"
            density="compact"
            hide-details="auto"
            label="Resolution"
            :messages="statsResolutionLabel || 'e.g. 2880×1800'"
          />
          <v-checkbox
            v-model="metrics.scale"
            density="compact"
            hide-details="auto"
            label="Display scale (1:1 check)"
            :messages="statsScaleLabel || 'e.g. shown at 1.05× — 1:1 pixels when the host renders at your window size'"
          />
          <v-checkbox
            v-model="metrics.age"
            density="compact"
            hide-details="auto"
            label="Frame age (end to end)"
            :messages="statsAgeLabel || 'e.g. ~4 ms — needs agent 0.4.9+'"
          />
          <v-checkbox
            v-model="metrics.paint"
            density="compact"
            hide-details="auto"
            label="Pipeline diagnostics"
            messages="paint / forward / decode milliseconds — for chasing an fps ceiling"
          />
          </v-tabs-window-item>

          <v-tabs-window-item value="session">
          <!-- C. SESSION — host audio + connected-only tools -->
          <div class="d-flex align-center ga-2 mb-3">
            <v-icon size="small" color="primary">mdi-cog-outline</v-icon>
            <span class="text-subtitle-2 font-weight-medium">Session</span>
          </div>
          <v-btn
            block
            variant="tonal"
            :color="audioOn ? 'primary' : undefined"
            :disabled="sessionLive || !agentSupportsAudio"
            :prepend-icon="audioOn ? 'mdi-volume-high' : 'mdi-volume-off'"
            :title="audioTooltip"
            class="mb-2"
            @click="toggleAudio"
          >
            Receive host audio — {{ audioOn ? 'ON' : 'OFF' }}
          </v-btn>
          <!-- loopback-TURN corp-relay assist (browser half; default-OFF).
               Surfaces the localStorage opt-in as a one-click toggle so the
               UDP-blocked-corp field test doesn't need DevTools. The agent
               half is default-ON (hosts the TURN whenever an overlay IP
               exists); this flag is what makes the browser probe + inject it. -->
          <v-btn
            block
            variant="tonal"
            :color="localRelayOn ? 'primary' : undefined"
            :disabled="sessionLive"
            :prepend-icon="localRelayOn ? 'mdi-lan-connect' : 'mdi-lan-disconnect'"
            :title="localRelayTooltip"
            class="mb-2"
            @click="toggleLocalRelay"
          >
            Corp relay assist — {{ localRelayOn ? 'ON' : 'OFF' }}
          </v-btn>
          <!-- Clipboard auto-sync (v2). Live-effective (not gated on
               sessionLive) — the composable subscribes/unsubscribes on
               flip. Old agents: local→remote still auto-pushes; the
               remote→local half needs the events cap (tooltip says so).
               Absent when the grant has no CLIPBOARD: there is no
               channel for it to sync over (dropClipboardChannel). -->
          <v-btn
            v-if="rc.clipboardGranted.value"
            block
            variant="tonal"
            :color="clipboardAutoSyncOn ? 'primary' : undefined"
            :prepend-icon="
              clipboardAutoSyncOn ? 'mdi-clipboard-flow' : 'mdi-clipboard-off-outline'
            "
            :disabled="!!clipboardRefusal"
            :title="clipboardRefusal ?? clipboardAutoSyncTooltip"
            class="mb-2"
            data-testid="rc-clipboard-autosync"
            @click="toggleClipboardAutoSync"
          >
            Clipboard auto-sync — {{ clipboardAutoSyncOn ? 'ON' : 'OFF' }}
          </v-btn>
          <!-- FR-13 (#789): mac hosts only — Ctrl chords translate to Cmd
               (copy/paste work); switch OFF to send literal Ctrl for
               terminal work (SIGINT etc). -->
          <v-btn
            v-if="rc.hostIsMac.value"
            block
            variant="tonal"
            :color="rc.ctrlAsCmd.value ? 'primary' : undefined"
            prepend-icon="mdi-apple-keyboard-command"
            title="ON: your Ctrl acts as the Mac's Cmd (Ctrl+C copies). OFF: literal Ctrl reaches the host (Ctrl+C is SIGINT in a terminal)."
            class="mb-2"
            @click="rc.ctrlAsCmd.value = !rc.ctrlAsCmd.value"
          >
            Ctrl acts as Cmd — {{ rc.ctrlAsCmd.value ? 'ON' : 'OFF' }}
          </v-btn>
          <!-- rc.227 — manual remote-layout picker. Caps-gated ('set') AND
               self-gated on a received rc:layout (needs the installed
               list). Bound to REPORTED state: a lost/refused switch snaps
               visibly back — the user just clicks again. -->
          <v-select
            v-if="agentLayoutCaps.includes('set') && rc.remoteLayout.value"
            :model-value="rc.remoteLayout.value.activeHkl"
            :items="remoteLayoutItems"
            item-title="title"
            item-value="value"
            density="comfortable"
            variant="outlined"
            hide-details="auto"
            prepend-inner-icon="mdi-keyboard-settings-outline"
            label="Remote keyboard layout"
            hint="Switches the HOST's active layout (like pressing Alt+Shift there). Typing usually auto-switches; use this if an app doesn't follow."
            persistent-hint
            class="mb-2"
            @update:model-value="onRemoteLayoutPick"
          />
          <template v-if="rc.phase.value === 'connected'">
            <v-btn
              block
              variant="tonal"
              prepend-icon="mdi-upload"
              :loading="uploadBusy"
              :disabled="!!filesRefusal"
              :title="filesRefusal ?? undefined"
              class="mb-2"
              data-testid="rc-files-upload"
              @click="fileInput?.click()"
            >
              Upload file → remote
            </v-btn>
            <v-btn
              block
              variant="tonal"
              prepend-icon="mdi-folder-open"
              :disabled="!agentSupportsBrowse || !!filesRefusal"
              :title="
                filesRefusal ??
                (agentSupportsBrowse
                  ? 'Browse remote files (download)'
                  : isLegacyFileDc
                    ? 'Browse needs agent 0.3.0+ — upgrade host agent'
                    : 'Browse disabled by host config')
              "
              class="mb-2"
              data-testid="rc-files-browse"
              @click="filesDrawer = true; settingsOpen = false"
            >
              Browse remote files
            </v-btn>
            <!-- FR-56 AC10 — never disabled: a host that cannot serve the
                 feature says WHY in the dialog (`unavailable.reason`), and a
                 greyed button with no tooltip was the one place that reason
                 could not reach. The entry shows for `list` (a desktop was
                 there at hello time) and for `status` (the agent will answer
                 honestly either way). -->
            <v-btn
              v-if="agentSupportsApps"
              block
              variant="tonal"
              prepend-icon="mdi-apps"
              :title="
                agentAppsCaps.includes('list')
                  ? 'List, focus or launch apps on the controlled host'
                  : 'Remote apps were not available when this agent announced itself — open to see why'
              "
              class="mb-2"
              @click="openAppsDialog(); settingsOpen = false"
            >
              Remote apps
            </v-btn>
            <v-btn
              block
              variant="tonal"
              prepend-icon="mdi-file-document-outline"
              class="mb-2"
              @click="openAgentLogDialog(); settingsOpen = false"
            >
              Agent logs
            </v-btn>
          </template>
          </v-tabs-window-item>
          </v-tabs-window>
        </v-card-text>
      </v-card>
    </v-dialog>


    <!-- rc.23 — agent log viewer. Opens via the mdi-file-document-outline
         toolbar button; shows the tail of the agent's rolling log file
         in a scrolling pre-block. Refresh button re-fetches. Auto-fetches
         on open with 500 lines (default) — enough to capture the run-up
         to a typical upload failure on the field-test host without flooding the DC. -->
    <!-- Apps dialog (shared by the desktop toolbar + mobile sheet). Lists
         windows on the remote virtual desktop; click one to focus (or
         re-attach a detached tmux session), or launch a new allowlisted
         app under "Launch new". -->
    <v-dialog v-model="appsDialog" max-width="480" scrollable>
      <v-card>
        <v-toolbar density="compact" color="primary">
          <v-icon class="ml-3">mdi-apps</v-icon>
          <v-toolbar-title class="text-body-1">Apps</v-toolbar-title>
          <v-spacer />
          <v-btn
            icon
            size="small"
            :loading="rc.appsLoading.value"
            title="Refresh"
            @click="refreshAppsSafe"
          >
            <v-icon>mdi-refresh</v-icon>
          </v-btn>
          <v-btn icon size="small" title="Close" @click="appsDialog = false">
            <v-icon>mdi-close</v-icon>
          </v-btn>
        </v-toolbar>
        <v-alert
          v-if="rc.appsError.value"
          type="warning"
          density="compact"
          variant="tonal"
          class="ma-2"
        >
          {{ rc.appsError.value }}
        </v-alert>
        <v-list density="compact" max-height="420" class="overflow-y-auto">
          <v-list-subheader>Open windows</v-list-subheader>
          <v-list-item
            v-for="w in rc.remoteWindows.value"
            :key="w.window_id"
            :active="w.focused"
            @click="onFocusWindow(w)"
          >
            <template #prepend>
              <v-icon>{{ w.session ? 'mdi-console' : 'mdi-window-restore' }}</v-icon>
            </template>
            <v-list-item-title>{{ w.title }}</v-list-item-title>
            <v-list-item-subtitle v-if="w.session">tmux: {{ w.session }}</v-list-item-subtitle>
            <template #append>
              <v-chip v-if="w.focused" size="x-small" color="primary" variant="flat">
                focused
              </v-chip>
            </template>
          </v-list-item>
          <!-- FR-56 AC10 — not when the agent REFUSED: "No windows reported"
               under a refusal reads as a quiet desktop, and the alert above
               already carries the reason. -->
          <v-list-item
            v-if="
              rc.remoteWindows.value.length === 0 &&
              !rc.appsLoading.value &&
              rc.appsSupported.value !== false
            "
            class="text-medium-emphasis"
            title="No windows reported"
          />
          <!-- FR-56 P2 — say what this list could NOT see. On a Wayland host
               the agent enumerates Xwayland windows and is blind to native
               Wayland ones, so a short list looks exactly like a quiet
               desktop. Rendered right under the list (and under the empty
               state, where the misreading actually happens) rather than in a
               tooltip, because the whole point is that it is not hidden. -->
          <v-list-item v-if="rc.appsCoverage.value?.unlisted" class="pt-0">
            <v-alert
              type="info"
              density="compact"
              variant="tonal"
              class="text-caption"
            >
              Not listed — {{ rc.appsCoverage.value.unlisted }}
            </v-alert>
          </v-list-item>
          <!-- FR-56 P5 — a reachable desktop does not make the buttons work.
               Measured on a GNOME Wayland host with no tmux: the panel said
               supported, offered the button, and failed only once somebody
               clicked it. `warning` rather than `info` because unlike the
               unlisted-source note above, this one predicts a FAILURE. -->
          <v-list-item
            v-if="rc.appsCoverage.value?.missing_tools?.length"
            class="pt-0"
          >
            <v-alert
              type="warning"
              density="compact"
              variant="tonal"
              class="text-caption"
            >
              <div
                v-for="t in rc.appsCoverage.value.missing_tools"
                :key="t.tool"
              >
                <strong>{{ t.tool }}</strong> is not installed on the agent
                host — {{ t.blocks }} ({{ t.install }})
              </div>
            </v-alert>
          </v-list-item>
          <template v-if="rc.launchableApps.value.length">
            <v-divider />
            <v-list-subheader>Launch new</v-list-subheader>
            <v-list-item
              v-for="a in rc.launchableApps.value"
              :key="a.key"
              @click="onLaunchApp(a)"
            >
              <template #prepend>
                <v-icon>mdi-plus-box-outline</v-icon>
              </template>
              <v-list-item-title>{{ a.label }}</v-list-item-title>
            </v-list-item>
          </template>
        </v-list>
      </v-card>
    </v-dialog>

    <v-dialog v-model="agentLogDialog" max-width="980" scrollable>
      <v-card>
        <v-toolbar density="compact" color="primary">
          <v-icon class="ml-4">mdi-file-document-outline</v-icon>
          <v-toolbar-title>
            Agent log
            <span
              v-if="rc.agentLogs.value?.path"
              class="ml-2 text-caption text-truncate"
              :title="rc.agentLogs.value.path"
            >
              ({{ rc.agentLogs.value.path }})
            </span>
          </v-toolbar-title>
          <v-spacer />
          <v-select
            v-model="agentLogLines"
            :items="[100, 200, 500, 1000, 2000, 5000]"
            density="compact"
            hide-details
            variant="outlined"
            class="ml-2"
            style="max-width: 120px;"
            label="Lines"
            @update:model-value="refreshAgentLog"
          />
          <v-btn
            icon
            variant="text"
            :loading="rc.agentLogsLoading.value"
            title="Refresh"
            @click="refreshAgentLog"
          >
            <v-icon>mdi-refresh</v-icon>
          </v-btn>
          <v-btn
            icon
            variant="text"
            title="Copy to clipboard"
            :disabled="!rc.agentLogs.value?.lines?.length"
            @click="copyAgentLog"
          >
            <v-icon>mdi-content-copy</v-icon>
          </v-btn>
          <v-btn
            icon
            variant="text"
            title="Close"
            @click="agentLogDialog = false"
          >
            <v-icon>mdi-close</v-icon>
          </v-btn>
        </v-toolbar>
        <v-card-text class="pa-0" style="max-height: 70vh; overflow: auto;">
          <div
            v-if="rc.agentLogs.value?.ok === false"
            class="pa-3 text-error text-caption"
          >
            {{ rc.agentLogs.value.error || 'rc:logs-fetch failed' }}
          </div>
          <div
            v-else-if="!rc.agentLogs.value?.lines?.length && !rc.agentLogsLoading.value"
            class="pa-3 text-medium-emphasis text-caption"
          >
            No log lines yet. Click Refresh to fetch.
          </div>
          <pre
            v-else
            ref="agentLogPreEl"
            class="agent-log-pre"
          >{{ (rc.agentLogs.value?.lines || []).join('\n') }}</pre>
          <div
            v-if="rc.agentLogs.value?.truncated"
            class="pa-2 text-caption text-medium-emphasis"
          >
            Showing the last {{ rc.agentLogs.value?.lines?.length || 0 }} lines —
            older entries omitted. Increase line count to see more.
          </div>
        </v-card-text>
      </v-card>
    </v-dialog>

    <!-- Files browser drawer (Phase 3 of file-DC v2). Opens via the
         mdi-folder-open toolbar button. Lets the operator navigate
         the host's filesystem and download files. Folder download
         lights up in Phase 4. Multi-select via checkboxes; Ctrl+C
         to copy-as-download (Phase 5). -->
    <v-navigation-drawer
      v-model="filesDrawer"
      location="right"
      :width="xs ? displayWidth : 420"
      temporary
      class="files-drawer"
      :class="{ 'drawer-drag-over': isDrawerDragOver }"
      tabindex="0"
      @dragenter.prevent.stop="onDrawerDragEnter"
      @dragover.prevent.stop="onDrawerDragOver"
      @dragleave.prevent.stop="onDrawerDragLeave"
      @drop.prevent.stop="onDrawerDrop"
    >
      <v-toolbar density="compact" color="primary">
        <v-icon class="ml-4">mdi-folder-open</v-icon>
        <v-toolbar-title>Remote files</v-toolbar-title>
        <v-spacer />
        <v-btn icon variant="text" :disabled="dirLoading" title="Refresh" @click="navigateTo(currentDirPath)">
          <v-icon>mdi-refresh</v-icon>
        </v-btn>
        <v-btn icon variant="text" title="Close" @click="filesDrawer = false">
          <v-icon>mdi-close</v-icon>
        </v-btn>
      </v-toolbar>
      <div class="px-3 pt-2 pb-1 d-flex align-center" style="gap: 4px">
        <v-btn
          icon
          variant="text"
          size="small"
          :disabled="isRootsView || dirLoading"
          title="Parent directory"
          @click="navigateTo(currentParent || '')"
        >
          <v-icon>mdi-arrow-up</v-icon>
        </v-btn>
        <v-btn
          icon
          variant="text"
          size="small"
          :disabled="dirLoading"
          title="Upload staging folder (rc.22 ESET-evasive staging — partials live here mid-upload)"
          @click="navigateTo(STAGING_PATH)"
        >
          <v-icon>mdi-package-variant-closed</v-icon>
        </v-btn>
        <v-btn
          icon
          variant="text"
          size="small"
          :disabled="dirLoading"
          title="Drives / roots"
          @click="navigateTo('')"
        >
          <v-icon>mdi-monitor</v-icon>
        </v-btn>
        <!-- FR-116 P5b — a touch screen has nothing to drop onto the drawer:
             this uploads INTO the folder on screen, by the same path as a
             drop or a paste. -->
        <v-btn
          v-if="filesTouchOnly"
          icon
          variant="text"
          size="small"
          :disabled="dirLoading || drawerUploadDestPath() === undefined"
          title="Upload here"
          aria-label="Upload here"
          data-testid="files-upload-here"
          @click="drawerFileInput?.click()"
        >
          <v-icon>mdi-upload</v-icon>
        </v-btn>
        <input ref="drawerFileInput" type="file" multiple hidden @change="onDrawerFilePicked" />
        <v-text-field
          v-model="dirPathInput"
          density="compact"
          hide-details
          variant="outlined"
          placeholder="Path (Enter to go)"
          @keyup.enter="navigateTo(dirPathInput)"
        />
      </div>
      <v-divider />
      <div v-if="dirError" class="pa-3 text-error text-caption">
        {{ dirError }}
      </div>
      <v-progress-linear v-if="dirLoading" indeterminate />
      <v-list density="compact" class="pa-0">
        <v-list-item
          v-for="entry in dirEntries"
          :key="entry.name"
          :class="{ 'files-entry-selected': selectedDirEntries.has(entry.name) }"
          @click="onEntryClick(entry, $event)"
          @dblclick="onEntryDblClick(entry)"
        >
          <template #prepend>
            <v-icon :color="entry.is_dir ? 'amber-darken-2' : 'grey-darken-1'">
              {{ entry.is_dir ? 'mdi-folder' : 'mdi-file-outline' }}
            </v-icon>
          </template>
          <v-list-item-title>{{ entry.name }}</v-list-item-title>
          <v-list-item-subtitle v-if="!entry.is_dir">
            {{ formatFileSize(entry.size) }}
          </v-list-item-subtitle>
          <template #append>
            <!-- FR-116 P5b — into a folder by a tap: a double-tap is not a
                 dependable double-click on a touch screen, and a single tap
                 selects (as a click does). -->
            <v-btn
              v-if="entry.is_dir && filesTouchOnly"
              icon
              size="x-small"
              variant="text"
              :title="`Open ${entry.name}`"
              :aria-label="`Open ${entry.name}`"
              data-testid="files-open-folder"
              @click.stop="onEntryDblClick(entry)"
            >
              <v-icon>mdi-chevron-right</v-icon>
            </v-btn>
            <v-btn
              icon
              size="x-small"
              variant="text"
              :disabled="entry.is_dir ? !agentSupportsFolderDownload : !agentSupportsDownload"
              :title="
                entry.is_dir
                  ? agentSupportsFolderDownload
                    ? `Download ${entry.name} as zip (Chrome/Edge only)`
                    : 'Folder download needs agent 0.3.0+'
                  : agentSupportsDownload
                    ? `Download ${entry.name}`
                    : 'Download needs agent 0.3.0+'
              "
              @click.stop="downloadEntry(entry)"
            >
              <v-icon>{{ entry.is_dir ? 'mdi-folder-zip' : 'mdi-download' }}</v-icon>
            </v-btn>
          </template>
        </v-list-item>
        <v-list-item v-if="!dirLoading && dirEntries.length === 0 && !dirError">
          <v-list-item-subtitle class="text-disabled">
            (empty directory)
          </v-list-item-subtitle>
        </v-list-item>
      </v-list>
    </v-navigation-drawer>
    <!-- Mobile virtual keyboard (Plan 4 phase 1). Mounted at the
         bottom of the page so its `position: fixed` toolbar
         overlays anything else. The component itself is invisible
         (1×1 px transparent textarea) when `open=false`, so this
         render is essentially free in the off state. The `key` /
         `keyText` events are forwarded to the existing input DC
         pipeline via the composable's `sendKey` / `sendKeyText`
         helpers — the agent's enigo backend types Unicode natively
         (no browser-side HID mapping needed for letter input). -->
    <MobileKeyboard
      :open="mobileKeyboardOpen"
      @close="mobileKeyboardOpen = false"
      @key-text="rc.sendKeyText"
      @key="rc.sendKey"
    />
  </v-container>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount, watch, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { takeExternalSession } from '@/composables/useExternalLogin'
import { useAgentStore, type Agent } from '@/stores/agents'
import { useAuthStore } from '@/stores/auth'
import { useWsStore } from '@/stores/ws'
import { peerAuthBadge } from '@/utils/peerAuth'
import {
  useRemoteControl,
  nextDirPath,
  isKeyboardLockSupported,
  diagHudEnabled,
  storedMetricToggles,
  displayScale,
  persistMetricToggles,
  remoteCursorCssFor,
  type RcScaleMode,
  type RcResolutionSetting,
  type RcPriority,
  resolutionCapAnnotation,
  resolutionOverrideHint,
  codecLabelFromDecoderConfig,
  captureArmLabel,
  mediaWaitingCopy,
  idleSecondsLeft,
  hostLockedChipTitle,
} from '@/composables/useRemoteControl'
import {
  PICKER_CHROMAS,
  PICKER_CODECS,
  cellAvailability,
  cellsFromCaps,
  choiceFromPicker,
  chromaSelectable,
  codecSelectable,
  pickerFromChoice,
  rememberedCellFailures,
  type Availability,
  type PickerChroma,
  type PickerCodec,
} from '@/composables/videoCells'
import { useI18n } from 'vue-i18n'
import { useSnackbar } from '@/composables/useSnackbar'
import {
  describeRecordReason,
  showsRecordRefusal,
  type RemoteRecordingItem,
} from '@/composables/useRemoteRecording'
import { describePrivacyReason, showsPrivacyRefusal } from '@/composables/usePrivacyMode'
import { agentOffersHighRefresh, frameRateSummary, type FrameRate } from '@/composables/frameRate'
import { featureRefusal, summarizeRefusals } from '@/composables/useSessionFeatures'
import { useDisplay } from 'vuetify'
import MobileKeyboard from '@/components/remote/MobileKeyboard.vue'
import KeepBusyMenu from '@/components/remote/KeepBusyMenu.vue'
import TouchControls from '@/components/remote/TouchControls.vue'
import TouchPresetEditor from '@/components/remote/TouchPresetEditor.vue'
import { readMyPresets, writeMyPresets } from '@/composables/touchPresetEdit'
import { useTenantStore } from '@/stores/tenant'
import { canManageOrgSettings } from '@/utils/permissions'
import type { KeepBusyPattern } from '@/composables/keepBusy'
import { displayMatchSummary } from '@/composables/displayMatch'
import { agentSupportsRelativeMouse, relativeMouseSwitchedOff } from '@/composables/relativeMouse'
import { agentSendsSas } from '@/composables/ctrlAltDel'
import { pictureOverflows, stageTouchAction } from '@/composables/touchInput'
import {
  BUILTIN_PRESETS,
  CONTROLS_STORAGE_PREFIX,
  orgPresets,
  presetById,
  readControlsPreset,
  type TouchPreset,
} from '@/composables/touchControls'
import { secondaryDeviceName, useHideDeviceName } from '@/composables/useHideDeviceName'
import { asSentence } from '@/utils/sentence'
import { hostOffers, hostReason, hostSpeaks } from '@/utils/hostUnavailable'
import { useCapabilitiesStore } from '@/stores/capabilities'
import { api } from '@/api/client'
import SessionRatingPrompt from '@/components/remote/SessionRatingPrompt.vue'
import {
  createRatingTracker,
  markPrompted,
  ratingPath,
  readLastPromptDay,
  shouldOfferRating,
  storageOrNull,
  utcDay,
  type Rating,
  type RatingReason,
} from '@/composables/rcSessionRating'

const route = useRoute()
const router = useRouter()
const tenantId = computed(() => route.params.tenantId as string)
const agentId = computed(() => route.params.agentId as string)

// FR-52 P4e — the EXTERNAL viewer: someone outside the device's organization,
// on a session their `/connect` login opened. Fixed at setup, never reactive:
// the composable is built for one mode and must not switch under a session.
// There is no tenant and no agent row to load — an outsider can read neither —
// so the agent stays null and the viewer runs on its baseline capabilities.
const isExternal = route.name === 'connect-session'
const externalCode = typeof route.query.code === 'string' ? route.query.code : ''

const agentStore = useAgentStore()
const authStore = useAuthStore()
const wsStore = useWsStore()
const agent = ref<Agent | null>(null)
// The header's machine-name subtitle — the Devices grid's preference, per
// user + org, so hiding it there hides it here too.
const hideDeviceName = useHideDeviceName(() => `${authStore.user?.id ?? 'anon'}:${tenantId.value}`)
// rc.19: pass the agent ref so useRemoteControl can read
// `capabilities.files.includes("resume")` and opt into the
// resumable upload pump. Agent doc is populated on mount;
// useRemoteControl's `supportsResume` computed reactively
// flips when the load lands.
// FR-100 P2a — the user id is what the device's signature over its answer
// names, so the page asks for one only once it knows who is signed in.
const rc = useRemoteControl(agent, {
  external: isExternal,
  userId: () => authStore.user?.id ?? null,
})
const { t } = useI18n()
const { showSuccess, showError, showSnackbar } = useSnackbar()
// rc.199 — Vuetify viewport helper; drives the Settings dialog's
// fullscreen-on-phone behaviour so one panel serves every viewport.
const { mobile, xs, width: displayWidth } = useDisplay()
// rc.199 — the single grouped Settings panel (gear button opens it at every
// viewport, replacing the desktop inline Row 2 + the mobile bottom-sheet).
const settingsOpen = ref(false)
// FR-93 P1 — the input-reach warning the operator closed, by identity: the
// next session's verdict is a new object, so it shows again.
const dismissedInputReach = ref<object | null>(null)
const clipboardBusy = ref(false)

// FR-85 P3c — recording the remote screen (docs/recording.md §10). The file is
// made and kept on the device; this starts and stops it and downloads it.
const rec = rc.recording
const recAudio = ref(false)
const recRunning = computed(() => rec.state.value === 'recording')
// #1760 — a box the device says cannot be ticked is unticked too, so what
// the start asks for is what the box shows.
watch(rec.audioUnavailable, (why) => {
  if (why) recAudio.value = false
})
// FR-99 P1c — privacy mode. The control's title says what it does and, after a
// refusal, why it was refused; the device's word decides whether it shows on.
const privacyTitle = computed(() => {
  if (rc.privacy.on.value) {
    // FR-99 P4 — what the curtain did to the device's speakers, when it says.
    const sound =
      rc.privacy.hostMuted.value === true
        ? ' Its speakers are muted too.'
        : rc.privacy.hostMuted.value === false
          ? " Its speakers couldn't be muted."
          : ''
    return `Privacy mode is on: the person at the device sees a notice instead of the screen.${sound} Click to turn it off.`
  }
  const why = describePrivacyReason(rc.privacy.reason.value)
  return why
    ? `Privacy mode is off: ${why}`
    : "Privacy mode: cover the device's screen while you work"
})
// A refusal, or the curtain coming down unasked (the owner switched privacy
// mode off), is said out loud: the icon alone changes too quietly.
watch(
  () => [rc.privacy.reason.value, rc.privacy.on.value] as const,
  ([why, on]) => {
    if (why && !on && why !== 'session_ended') {
      showError(`Privacy mode: ${describePrivacyReason(why)}`)
    }
  },
)
// FR-101 P2c — what the session policy took out of this session, per control:
// the reason in words, or null when the feature is there. Each greyed control
// carries its own reason in its title.
const filesRefusal = computed(() => featureRefusal(rc.featuresRefused.value, 'files'))
// FR-97 P0c — the device's own "not here" (`AgentCaps.unavailable`) greys the
// same controls. The session's refusal speaks first: it is about this session,
// the device's about the host.
const clipboardRefusal = computed(
  () =>
    featureRefusal(rc.featuresRefused.value, 'clipboard') ??
    hostReason(agent.value?.capabilities, 'clipboard'),
)
const audioRefusal = computed(() => featureRefusal(rc.featuresRefused.value, 'audio'))
// FR-97 P0c — the button types three ordinary keys. A Mac gives the chord no
// meaning (`not-applicable`, so no button); Windows and Linux say what the
// keys reach there. FR-97 P4a — a Windows host that can send the real secure
// attention sequence advertises `sas`, and the button sends that instead.
const sasOffered = computed(() => hostOffers(agent.value?.capabilities, 'sas'))
const sasTitle = computed(() => {
  const base = 'Send Ctrl+Alt+Del (Ctrl+Alt+End over the viewer does the same).'
  if (agentSendsSas(agent.value?.capabilities?.input)) {
    return `${base} The host sends the real one, which reaches the Windows lock and sign-in screens.`
  }
  const why = hostReason(agent.value?.capabilities, 'sas')
  return why ? `${base} ${why}` : base
})
// Said once as the session starts, so nobody has to find out by clicking.
watch(
  () => rc.featuresRefused.value,
  (refused) => {
    const summary = summarizeRefusals(refused)
    if (summary) showSnackbar(summary, 'info', 8000)
  },
)
// FR-97 P3c-1 — the device says this session carries no sound, and why. Said
// once as it arrives; the audio control keeps the reason in its title.
watch(
  () => rc.audioUnavailable.value,
  (reason) => {
    if (reason) showSnackbar(reason.hint || 'This host sends no sound in this session.', 'warning', 10000)
  },
)
// FR-85 P3b-3 — a deliberate Disconnect ends a recording first: to the device
// a hang-up and the reconnect ladder's retry look the same, and a retry is
// what it keeps a recording running for.
async function leave() {
  await rec.stopBeforeLeaving()
  rc.disconnect()
}
function fmtClock(ms: number): string {
  const s = Math.floor(Math.max(0, ms) / 1000)
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const ss = String(s % 60).padStart(2, '0')
  return h > 0 ? `${h}:${String(m).padStart(2, '0')}:${ss}` : `${m}:${ss}`
}
async function onDownloadRecording(it: RemoteRecordingItem) {
  try {
    // Straight from the click: the save dialog must open inside the gesture.
    await rec.downloadRecording(it.name, it.bytes)
  } catch (e) {
    const code = e instanceof Error ? e.message : String(e)
    // Closing the save dialog is a choice, not an error to report.
    if (/abort/i.test(code)) return
    showError(`Download failed: ${describeRecordReason(code)}`)
  }
}

// Push the controller's local clipboard to the agent's OS clipboard.
// Driven by a toolbar button so the `navigator.clipboard.readText()`
// call happens in a user-gesture context (Chrome throws otherwise).
// Short-lived busy spinner during the round-trip; toast on
// success/failure. Fire-and-forget — the agent doesn't ack writes.
async function onSendClipboard() {
  if (clipboardBusy.value) return
  // FR-101 P2c — the session policy took the clipboard out of this session.
  if (clipboardRefusal.value) {
    showError(clipboardRefusal.value)
    return
  }
  clipboardBusy.value = true
  try {
    const ok = await rc.sendClipboardToAgent()
    if (ok) {
      showSuccess('Clipboard sent to remote')
    } else {
      showError('Could not read your clipboard (permission denied?)')
    }
  } finally {
    clipboardBusy.value = false
  }
}

// Pull the agent's clipboard and copy it into the controller's local
// clipboard. v2 agents answer with text OR an image (rich read —
// `accept:["text","image"]`); old agents text only. The button click
// anchors the `navigator.clipboard.write*` user-gesture permission.
async function onGetClipboard() {
  if (clipboardBusy.value) return
  // FR-101 P2c — likewise.
  if (clipboardRefusal.value) {
    showError(clipboardRefusal.value)
    return
  }
  clipboardBusy.value = true
  try {
    const content = await rc.getAgentClipboardRich()
    try {
      if (content.kind === 'native') {
        // v2.2 — full fidelity: write RTF (embedded images) to this
        // machine's clipboard via the local bridge. Fall back to the
        // html/text alternates if the bridge write fails.
        const ok = await rc.writeLocalNativeClipboard(content)
        if (ok) {
          showSuccess('Copied remote clipboard (full fidelity — RTF with images)')
        } else if (content.html) {
          await globalThis.navigator.clipboard.write([
            new ClipboardItem({
              'text/html': new Blob([content.html], { type: 'text/html' }),
              'text/plain': new Blob([content.text], { type: 'text/plain' }),
            }),
          ])
          showSuccess(`Copied remote clipboard (formatted, ${content.text.length} chars)`)
        } else {
          await globalThis.navigator.clipboard.writeText(content.text)
          showSuccess(`Copied remote clipboard (${content.text.length} chars)`)
        }
      } else if (content.kind === 'image') {
        await globalThis.navigator.clipboard.write([
          new ClipboardItem({ 'image/png': content.blob }),
        ])
        showSuccess(`Copied remote image (${content.w}×${content.h})`)
      } else if (content.kind === 'html') {
        // v2.1 — both formats: rich paste targets take the html,
        // plain editors the text alt.
        await globalThis.navigator.clipboard.write([
          new ClipboardItem({
            'text/html': new Blob([content.html], { type: 'text/html' }),
            'text/plain': new Blob([content.text], { type: 'text/plain' }),
          }),
        ])
        showSuccess(`Copied remote clipboard (formatted, ${content.text.length} chars)`)
      } else {
        await globalThis.navigator.clipboard.writeText(content.text)
        showSuccess(
          content.text.length > 0
            ? `Copied remote clipboard (${content.text.length} chars)`
            : 'Remote clipboard is empty',
        )
      }
    } catch (e) {
      showError(`Could not write to your clipboard: ${(e as Error).message}`)
    }
  } catch (e) {
    showError(`Remote clipboard read failed: ${(e as Error).message}`)
  } finally {
    clipboardBusy.value = false
  }
}

// Template refs. Declared before the computeds / watches below that
// reference them — Vue 3 <script setup> executes top-to-bottom, and
// `watch` evaluates its source getter eagerly during setup to wire
// reactivity. Reading `cursorCanvas.value` in a watch source while
// `cursorCanvas` is still in the temporal dead zone manifests as the
// minified TDZ crash "Cannot access 'Z' before initialization" at
// setup time, which kills the whole RemoteControl page before it
// can paint. Keep template refs at the top of setup to avoid this.
const videoEl = ref<HTMLVideoElement | null>(null)
// Hidden sink for the opt-in host-audio track. Bound to
// `rc.remoteAudioStream` by the watcher below. Kept separate from
// `videoEl` (which is muted + may carry no track under the DC video
// paths).
const audioEl = ref<HTMLAudioElement | null>(null)
const stageEl = ref<HTMLElement | null>(null)
const cursorCanvas = ref<HTMLCanvasElement | null>(null)
const fileInput = ref<HTMLInputElement | null>(null)
// Whether the on-screen soft keyboard is currently surfaced (Plan 4
// phase 1). Toggled from the toolbar button; the MobileKeyboard
// component focuses its hidden textarea on open, which causes iOS /
// Android to bring up their soft keyboard. Reset on disconnect via
// the watcher below.
const mobileKeyboardOpen = ref(false)
watch(
  () => rc.phase.value,
  (phase) => {
    // Auto-close the keyboard when the session ends so a new
    // connect attempt doesn't inherit the stale toggle state.
    if (phase !== 'connected') mobileKeyboardOpen.value = false
  },
)
const uploadBusy = ref(false)
// Visual cue when a draggable item is hovering the stage. Toggled on
// dragenter/dragover (true) + drop/dragleave (false). The
// `.prevent.stop` modifiers on the v-on bindings are what actually
// suppress the browser's default open-image-in-new-tab; the ref
// just drives the dashed-border CSS state.
const isDragOver = ref(false)

// Drop a file onto the stage to upload it to the remote host.
// Browsers default to opening dragged images / files in a new tab —
// `preventDefault` on every drag event in the chain (enter, over,
// drop) is what suppresses that.
function onStageDragEnter(ev: DragEvent) {
  if (!ev.dataTransfer || !hasFileDrag(ev.dataTransfer)) return
  isDragOver.value = true
}
function onStageDragOver(ev: DragEvent) {
  if (!ev.dataTransfer || !hasFileDrag(ev.dataTransfer)) return
  ev.dataTransfer.dropEffect = 'copy'
  isDragOver.value = true
}
function onStageDragLeave(ev: DragEvent) {
  // `dragleave` fires when crossing into child elements too. Use the
  // related-target test to ignore child traversals — only flip the
  // cue off when the pointer leaves the stage entirely.
  const stage = stageEl.value
  const next = ev.relatedTarget as Node | null
  if (stage && next && stage.contains(next)) return
  isDragOver.value = false
}
async function onStageDrop(ev: DragEvent) {
  isDragOver.value = false
  if (!ev.dataTransfer) return
  // FR-101 P2c — the session policy took file transfer out of this session:
  // say why, rather than starting an upload the device refuses.
  if (filesRefusal.value) {
    showError(filesRefusal.value)
    return
  }
  // Iterate `items` (NOT `files`) so we can use `webkitGetAsEntry()`
  // to detect + recursively walk dropped folders. File-DC v2.1
  // (0.3.0+): folder uploads extend `files:begin` with a `rel_path`
  // field; the agent recreates the directory structure under
  // Downloads/<root>. Old agents (<0.3.0) ignore unknown JSON fields
  // and use the basename — graceful degradation to flat upload.
  type UploadInput = File | { file: File; relPath: string }
  const flatFiles: File[] = []
  const folderWalks: Promise<{ file: File; relPath: string }[]>[] = []
  const items = ev.dataTransfer.items
  if (items && items.length > 0) {
    for (let i = 0; i < items.length; i++) {
      const item = items[i]
      if (item.kind !== 'file') continue
      const entry = (item as DataTransferItem & {
        webkitGetAsEntry?: () => FileSystemEntry | null
      }).webkitGetAsEntry?.()
      if (entry && entry.isDirectory) {
        folderWalks.push(rc.walkFolderEntry(entry, entry.name))
      } else {
        const f = item.getAsFile()
        if (f) flatFiles.push(f)
      }
    }
  } else if (ev.dataTransfer.files) {
    // Browser without items API (very old, pre-Chrome 21) — flat
    // upload only. Folder support requires the items API.
    for (let i = 0; i < ev.dataTransfer.files.length; i++) {
      flatFiles.push(ev.dataTransfer.files[i])
    }
  }
  const uploadList: UploadInput[] = [...flatFiles]
  if (folderWalks.length > 0) {
    try {
      const walked = await Promise.all(folderWalks)
      for (const folder of walked) uploadList.push(...folder)
    } catch (e) {
      showError(`Folder walk failed: ${(e as Error).message}`)
    }
  }
  if (uploadList.length > 0) void uploadMany(uploadList)
}
function hasFileDrag(dt: DataTransfer): boolean {
  // `types` is the only field populated during dragenter / dragover
  // for security reasons (the actual file list isn't readable until
  // drop). 'Files' is the documented marker for an OS file drag.
  for (let i = 0; i < dt.types.length; i++) {
    if (dt.types[i] === 'Files') return true
  }
  return false
}

// Stream the user-picked file(s) to the remote's Downloads folder
// via the `files` DC. 64 KiB chunks with backpressure on
// `RTCDataChannel.bufferedAmount` so large files don't OOM the tab.
// `multiple` on the input lets the operator queue several at once.
async function onFilePicked(ev: Event) {
  const input = ev.target as HTMLInputElement | null
  const list = input?.files
  if (!list || list.length === 0) return
  const files: File[] = []
  for (let i = 0; i < list.length; i++) files.push(list[i])
  try {
    await uploadMany(files)
  } finally {
    if (input) input.value = '' // allow re-selecting the same file(s)
  }
}

// --- staging quick-access ---
//
// A SENTINEL, not a path. The agent resolves it against its own layout
// (`files::STAGING_SENTINEL` -> `machine_global_dir().join("staging")`,
// falling back to the machine-global root while no update is in flight).
//
// FR-21 P4: this was a hardcoded
// RETIRED-NAME-RECORD: quotes the defective literal this fix removed; the old
// spelling is the evidence, not a stale reference. docs/fr/FR-21
// `C:\ProgramData\meshharbor\meshharbor-agent\staging`, which was right only on
// hosts carrying the pre-rename tree — `machine_global_dir()` resolves the
// `meshharbor` segment on a fresh install. Confirmed broken on a real
// SYSTEM-mode Windows host, where that parent directory does not exist.
//
// Sending a token instead of a path also retires the Vue-template /
// HTML-attribute / JS-string escaping stack that produced the doubled
// backslashes behind the old "canonicalising C:..." error.
const STAGING_PATH = '<staging>'

// --- rc.23 agent log viewer state ---
//
// `agentLogDialog` drives the v-dialog open/close binding. `agentLogLines`
// is the line count to request (operator-tunable from a dropdown in the
// toolbar). `agentLogPreEl` is the <pre> element ref — we auto-scroll
// to the bottom on every refresh so the newest entries are visible
// without manual scrolling.
const agentLogDialog = ref(false)
// rc.23 hotfix #4 — default 200 (was 500). Aligns with the
// composable default; keeps the reply payload well under
// webrtc-rs's SCTP max_message_size (~64 KiB).
const agentLogLines = ref(200)
const agentLogPreEl = ref<HTMLElement | null>(null)

// rc.NEXT — remote app selection & launch (virtual-desktop hosts).
const appsDialog = ref(false)
function refreshAppsSafe() {
  void rc
    .refreshApps()
    .catch((e) => showError(`Apps: ${e instanceof Error ? e.message : String(e)}`))
}
function openAppsDialog() {
  appsDialog.value = true
  refreshAppsSafe()
}
async function onFocusWindow(w: { window_id: string }) {
  try {
    const r = await rc.focusWindow(w.window_id)
    if (!r.ok) showError(r.error ?? 'Focus failed')
  } catch (e) {
    showError(`Focus failed: ${e instanceof Error ? e.message : String(e)}`)
  }
}
async function onLaunchApp(a: { key: string; label: string }) {
  try {
    const r = await rc.launchApp(a.key)
    if (r.ok) {
      showSuccess(`Launched ${a.label}`)
      void rc.refreshApps().catch(() => {})
    } else {
      showError(r.error ?? 'Launch failed')
    }
  } catch (e) {
    showError(`Launch failed: ${e instanceof Error ? e.message : String(e)}`)
  }
}

async function openAgentLogDialog() {
  agentLogDialog.value = true
  // Auto-fetch on open so the operator doesn't have to click Refresh
  // for the first view. Subsequent dialog re-opens still reuse the
  // last fetch unless the operator hits Refresh — keeps the surface
  // calm.
  if (!rc.agentLogs.value) {
    await refreshAgentLog()
  } else {
    // Scroll to bottom on re-open in case the user resized.
    await nextTick()
    scrollAgentLogToBottom()
  }
}

async function refreshAgentLog() {
  try {
    await rc.fetchAgentLogs(agentLogLines.value)
    await nextTick()
    scrollAgentLogToBottom()
  } catch (e) {
    showError(`Failed to fetch agent log: ${e instanceof Error ? e.message : String(e)}`)
  }
}

function scrollAgentLogToBottom() {
  const el = agentLogPreEl.value
  if (el) el.scrollTop = el.scrollHeight
}

async function copyAgentLog() {
  const lines = rc.agentLogs.value?.lines
  if (!lines || lines.length === 0) return
  try {
    await navigator.clipboard.writeText(lines.join('\n'))
    showSuccess('Agent log copied to clipboard')
  } catch (e) {
    showError(`Copy failed: ${e instanceof Error ? e.message : String(e)}`)
  }
}

// --- Files browser drawer state (Phase 3 of file-DC v2) ---
const filesDrawer = ref(false)
const dirLoading = ref(false)
const dirError = ref<string | null>(null)
const dirEntries = ref<{ name: string; is_dir: boolean; size: number | null; mtime_unix: number | null }[]>([])
const currentDirPath = ref('')
const currentParent = ref<string | null>(null)
// Distinct from `currentParent === null`. The agent's roots listing
// returns `parent: null`, but so does any *real* path whose
// `Path::parent()` is None — e.g. on Windows, `canonicalize("C:\\")`
// returns `\\?\C:\` whose parent is None. Without this flag the
// drawer treated `\\?\C:\` as a roots view and dbl-clicking `dev`
// shipped just `"dev"` to the agent, which failed with
// "canonicalising dev". Field repro 2026-05-09.
const isRootsView = ref(false)
const dirPathInput = ref('')
const selectedDirEntries = ref<Set<string>>(new Set())
let lastSelectedDirIndex: number | null = null

async function navigateTo(path: string) {
  dirLoading.value = true
  dirError.value = null
  selectedDirEntries.value = new Set()
  lastSelectedDirIndex = null
  const requestingRoots = path === '' || path === '~' || path === '/'
  try {
    const listing = await rc.listDir(path)
    currentDirPath.value = listing.path
    currentParent.value = listing.parent
    isRootsView.value = requestingRoots
    dirPathInput.value = listing.path
    dirEntries.value = listing.entries
  } catch (e) {
    dirError.value = (e as Error).message
    dirEntries.value = []
  } finally {
    dirLoading.value = false
  }
}

// Auto-load roots view the first time the drawer opens.
watch(filesDrawer, (open) => {
  if (open && dirEntries.value.length === 0 && !dirLoading.value) {
    void navigateTo('')
  }
})

function onEntryClick(
  entry: { name: string; is_dir: boolean },
  // Vuetify's `<v-list-item @click>` fires BOTH on mouse click and
  // on keyboard activation (Enter / Space — accessibility), so the
  // handler receives `MouseEvent | KeyboardEvent`. Both event types
  // expose `shiftKey` / `ctrlKey` / `metaKey` so the modifier-key
  // logic below works uniformly.
  ev: MouseEvent | KeyboardEvent
) {
  // Ctrl/Cmd+click toggles selection; Shift+click extends; plain
  // click selects only this entry. Multi-select is what makes
  // Ctrl+C-as-download work cleanly across multiple entries.
  const idx = dirEntries.value.findIndex((e) => e.name === entry.name)
  if (ev.shiftKey && lastSelectedDirIndex !== null) {
    const lo = Math.min(lastSelectedDirIndex, idx)
    const hi = Math.max(lastSelectedDirIndex, idx)
    const range = new Set(selectedDirEntries.value)
    for (let i = lo; i <= hi; i++) range.add(dirEntries.value[i].name)
    selectedDirEntries.value = range
  } else if (ev.ctrlKey || ev.metaKey) {
    const next = new Set(selectedDirEntries.value)
    if (next.has(entry.name)) next.delete(entry.name)
    else next.add(entry.name)
    selectedDirEntries.value = next
    lastSelectedDirIndex = idx
  } else {
    selectedDirEntries.value = new Set([entry.name])
    lastSelectedDirIndex = idx
  }
}

function onEntryDblClick(entry: { name: string; is_dir: boolean }) {
  // Path-construction logic lives in `nextDirPath` (pure helper in
  // useRemoteControl.ts) so its two regression-prone invariants —
  // (1) roots-view dispatches `entry.name` directly, (2) inside
  // `\\?\C:\` whose Path::parent() is None, drive deeper using
  // explicit `isRootsView` flag not `currentParent === null` proxy
  // — are locked by Vitest.
  const target = nextDirPath(entry, currentDirPath.value, isRootsView.value)
  if (target === null) return
  void navigateTo(target)
}

function formatFileSize(bytes: number | null): string {
  if (bytes === null || bytes === undefined) return ''
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

async function downloadEntry(entry: { name: string; is_dir: boolean }) {
  // Reuse `nextDirPath`'s separator logic via a small wrapper:
  // for file entries the helper returns null (it's "next dir to
  // navigate to", not "next host path"), so flip is_dir=true and
  // remember to use the original is_dir for the download branch.
  // The roots-view case doesn't apply here — the drawer only shows
  // a download button on entries below the roots view.
  const fullPath = nextDirPath(
    { name: entry.name, is_dir: true },
    currentDirPath.value,
    isRootsView.value,
  )
  if (fullPath === null) return
  try {
    if (entry.is_dir) {
      const r = await rc.downloadFolder(fullPath, `${entry.name}.zip`)
      showSuccess(`Downloaded ${r.name} (${formatFileSize(r.bytes)})`)
    } else {
      const r = await rc.downloadFile(fullPath, entry.name)
      showSuccess(`Downloaded ${r.name} (${formatFileSize(r.bytes)})`)
    }
  } catch (e) {
    showError(`Download failed: ${(e as Error).message}`)
  }
}

// Window-level paste handler for the drawer. The original rc.14
// design used `@paste` on the drawer element, but `paste` events
// only fire on the focused element — so unless the operator clicked
// into the drawer first, the handler never ran (Field repro rc.15
// 2026-05-07). Moving to window scope makes the handler robust to
// focus state. The viewer's separate composable-side onPaste fires
// first; it only acts when `pendingCtrlV` is set (Ctrl+V over the
// viewer specifically), so this drawer handler kicks in for every
// other paste-with-files when the drawer is open.
function onWindowPasteForDrawer(ev: ClipboardEvent) {
  if (!filesDrawer.value) return
  const dt = ev.clipboardData
  if (!dt || !dt.files || dt.files.length === 0) return
  // Don't intercept paste into form inputs (e.g. the path-input
  // field at the top of the drawer).
  const target = ev.target as Element | null
  if (target) {
    const tag = target.tagName
    if (tag === 'INPUT' || tag === 'TEXTAREA') return
    if ((target as HTMLElement).isContentEditable) return
  }
  ev.preventDefault()
  ev.stopPropagation()
  const files: File[] = []
  for (let i = 0; i < dt.files.length; i++) files.push(dt.files[i])
  // Drawer-scope paste honours the current dir as the upload target
  // (file-DC v2.2 path-targeted upload). When the drawer is at the
  // roots view (currentDirPath = "Drives" / "/"), we skip dest_path
  // — those aren't real directories the agent can write into.
  void uploadMany(files, drawerUploadDestPath())
}

// File-DC v2.2 path-targeted upload — drop a file/folder onto the
// drawer to upload INTO the current host directory instead of the
// default Downloads/. Visual cue (`drawer-drag-over` class on the
// drawer root) shows the operator they're aiming at the drawer's
// current dir. Drops on the viewer keep going to Downloads.
const isDrawerDragOver = ref(false)
/** FR-116 P5b — the drawer's touch affordances (open a folder by a tap,
 *  upload here) are for screens whose pointer cannot hover: a phone or a
 *  tablet, where a double-click and a drop are not dependable. Not
 *  `touchModeOffered`, which also holds on a touchscreen LAPTOP — that one
 *  has a mouse, so its drawer keeps the desktop's. */
const filesTouchOnly = (() => {
  try {
    return globalThis.matchMedia?.('(hover: none)').matches === true
  } catch {
    return false
  }
})()
const drawerFileInput = ref<HTMLInputElement | null>(null)

// FR-116 P5b — "Upload here": the same refusal and the same destination as a
// drop on the drawer or a paste into it.
async function onDrawerFilePicked(ev: Event) {
  const input = ev.target as HTMLInputElement | null
  const list = input?.files
  if (!list || list.length === 0) return
  try {
    if (filesRefusal.value) {
      showError(filesRefusal.value)
      return
    }
    const files: File[] = []
    for (let i = 0; i < list.length; i++) files.push(list[i])
    await uploadMany(files, drawerUploadDestPath())
  } finally {
    if (input) input.value = '' // allow re-picking the same file(s)
  }
}

function drawerUploadDestPath(): string | undefined {
  // Only return a dest_path when the drawer is on a real directory
  // (not the roots view which shows drive letters). Root labels are
  // localisation-dependent ("Drives" / "/") so we look for a path
  // that contains a separator AND isn't one of the known sentinels.
  const p = currentDirPath.value
  if (!p || p === 'Drives' || p === '/') return undefined
  return p
}
function onDrawerDragEnter(ev: DragEvent) {
  if (!ev.dataTransfer || !hasFileDrag(ev.dataTransfer)) return
  isDrawerDragOver.value = true
}
function onDrawerDragOver(ev: DragEvent) {
  if (!ev.dataTransfer || !hasFileDrag(ev.dataTransfer)) return
  ev.dataTransfer.dropEffect = 'copy'
  isDrawerDragOver.value = true
}
function onDrawerDragLeave(ev: DragEvent) {
  // dragleave fires on child traversal too; only flip the cue off
  // when the pointer leaves the drawer entirely.
  const drawer = (ev.currentTarget as HTMLElement) ?? null
  const next = ev.relatedTarget as Node | null
  if (drawer && next && drawer.contains(next)) return
  isDrawerDragOver.value = false
}
async function onDrawerDrop(ev: DragEvent) {
  isDrawerDragOver.value = false
  if (!ev.dataTransfer) return
  // FR-101 P2c — likewise.
  if (filesRefusal.value) {
    showError(filesRefusal.value)
    return
  }
  // Mirror the viewer's onStageDrop logic (files + walked folders),
  // but route through `uploadMany` with the drawer's current dir as
  // the dest_path option.
  type UploadInput = File | { file: File; relPath: string }
  const flatFiles: File[] = []
  const folderWalks: Promise<{ file: File; relPath: string }[]>[] = []
  const items = ev.dataTransfer.items
  if (items && items.length > 0) {
    for (let i = 0; i < items.length; i++) {
      const item = items[i]
      if (item.kind !== 'file') continue
      const entry = (item as DataTransferItem & {
        webkitGetAsEntry?: () => FileSystemEntry | null
      }).webkitGetAsEntry?.()
      if (entry && entry.isDirectory) {
        folderWalks.push(rc.walkFolderEntry(entry, entry.name))
      } else {
        const f = item.getAsFile()
        if (f) flatFiles.push(f)
      }
    }
  } else if (ev.dataTransfer.files) {
    for (let i = 0; i < ev.dataTransfer.files.length; i++) {
      flatFiles.push(ev.dataTransfer.files[i])
    }
  }
  const uploadList: UploadInput[] = [...flatFiles]
  if (folderWalks.length > 0) {
    try {
      const walked = await Promise.all(folderWalks)
      for (const folder of walked) uploadList.push(...folder)
    } catch (e) {
      showError(`Folder walk failed: ${(e as Error).message}`)
    }
  }
  if (uploadList.length > 0) void uploadMany(uploadList, drawerUploadDestPath())
}

// Window-level Ctrl+C / Cmd+C — copy selected drawer entries as
// downloads. Same focus-robustness reasoning as the paste handler:
// rc.14's `@keydown` on the drawer only fired when focus was inside
// the drawer; field repro rc.15 2026-05-07 confirmed the handler
// often missed because focus stayed on document.body. Moving to
// window scope with a drawer-open + selection-non-empty gate makes
// it work regardless of where focus landed.
function onWindowKeyDownForDrawer(ev: KeyboardEvent) {
  if (!filesDrawer.value) return
  if (ev.code !== 'KeyC') return
  if (!(ev.ctrlKey || ev.metaKey)) return
  // Skip if focus is in the path-input field or any other text
  // input — let native copy work there.
  const target = ev.target as Element | null
  if (target) {
    const tag = target.tagName
    if (tag === 'INPUT' || tag === 'TEXTAREA') return
    if ((target as HTMLElement).isContentEditable) return
  }
  if (selectedDirEntries.value.size === 0) return
  ev.preventDefault()
  ev.stopPropagation()
  // Snapshot — selectedDirEntries can mutate during the await chain.
  const entries = Array.from(selectedDirEntries.value)
    .map((name) => dirEntries.value.find((e) => e.name === name))
    .filter((e): e is NonNullable<typeof e> => !!e)
  void downloadEntries(entries)
}

async function downloadEntries(
  entries: { name: string; is_dir: boolean }[]
) {
  let success = 0
  let failed = 0
  for (const entry of entries) {
    try {
      await downloadEntry(entry)
      success++
    } catch (e) {
      failed++
      void e
    }
  }
  if (entries.length > 1) {
    if (failed === 0) {
      showSuccess(`Downloaded ${success} entries`)
    } else if (success === 0) {
      showError(`All ${failed} downloads failed`)
    } else {
      showError(`Downloaded ${success}/${entries.length} — ${failed} failed`)
    }
  }
}

async function uploadMany(
  items: (File | { file: File; relPath: string })[],
  destPath?: string
) {
  if (items.length === 0) return
  uploadBusy.value = true
  try {
    const results = await rc.uploadFiles(items, destPath ? { destPath } : undefined)
    const ok = results.filter((r) => r.ok).length
    const failed = results.filter((r) => !r.ok)
    if (failed.length === 0) {
      showSuccess(
        ok === 1
          ? `Uploaded ${results[0].name}`
          : `Uploaded ${ok} files`
      )
    } else if (ok === 0) {
      const first = failed[0] as { name: string; error: string }
      showError(
        failed.length === 1
          ? `Upload failed: ${first.error}`
          : `${failed.length} uploads failed (first: ${first.name} — ${first.error})`
      )
    } else {
      const first = failed[0] as { name: string; error: string }
      showError(
        `Uploaded ${ok}/${items.length} — ${failed.length} failed (e.g. ${first.name}: ${first.error})`
      )
    }
  } finally {
    uploadBusy.value = false
  }
}

// Quality preference: v-select emits immediately on change. We proxy
// through a computed so the composable stays the source of truth
// (persists + pushes to agent). The v-select's inner value is
// whatever the composable already holds, so reloads show the
// restored preference without an extra effect.
// Scale mode + custom percent. Proxy through a computed so the
// composable stays the source of truth (persists across reloads).
const scaleOptions = [
  { title: 'Adaptive', value: 'adaptive' },
  { title: 'Original', value: 'original' },
  { title: 'Custom…', value: 'custom' },
] as const
const scaleMode = computed<RcScaleMode>({
  get: () => rc.scaleMode.value,
  set: (v: RcScaleMode) => rc.setScaleMode(v),
})
const scalePercent = computed<number>({
  get: () => rc.scaleCustomPercent.value,
  set: (v: number) => rc.setScaleCustomPercent(v),
})

// Intrinsic remote-frame dimensions. The composable is the source of
// truth — it's fed by `<video>.onresize` in classic mode and by the
// WebCodecs worker's `first-frame` message in the low-latency path.
// That way any consumer downstream (scale style, coord math, cursor
// overlay) reads one set of refs regardless of render path.
const videoIntrinsicW = rc.mediaIntrinsicW
const videoIntrinsicH = rc.mediaIntrinsicH

// Render-path toggle. The composable persists the preference across
// reloads; `webcodecsSupported` is true only when the browser exposes
// both RTCRtpScriptTransform + VideoDecoder (Chrome 94+). The
// `isWebCodecsRender` computed drives template rendering — it's only
// true when the session is actively using the WebCodecs path (the
// user opted in AND the browser supports it). We read `rc.renderPath`
// directly so the UI state matches what the next Connect would do.
// Which element the viewer actually mounts — driven by the runtime
// `webcodecsActive` flag that the composable flips to true ONLY when
// the RTCRtpScriptTransform is successfully installed for this
// session. A user preference of `renderPath === 'webcodecs'` on a
// session where we fall back (HEVC, browser without the API,
// transferControlToOffscreen throwing) flips to `<video>` transparently
// instead of mounting an empty canvas.
const isWebCodecsRender = computed<boolean>(() => rc.webcodecsActive.value)

// FR-77 — what the AGENT can encode is read through the ONE cell derivation
// (`cellsFromCaps`: the agent's `video_cells`, or the legacy fields for an
// older agent) inside `cellAvail` below; the per-codec computeds this used to
// carry are gone with the single-axis picker.
// Opt-in "receive host audio" toggle. Same "takes effect on next
// Connect" shape as the transport toggles above (the recvonly audio
// transceiver + `audio_enabled` request flag are fixed at offer time),
// so we DISABLE it while a session is live rather than let a mid-
// session flip look like it did nothing. `audioOn` reads the
// composable's persisted `audioEnabled` ref so the button reflects
// what the next Connect would do.
const audioOn = computed<boolean>(() => rc.audioEnabled.value)
// A session is "live" from request through connected/reconnecting.
// Only the terminal idle/closed/error states allow flipping the audio
// preference (matching when a Connect button is available).
const sessionLive = computed<boolean>(
  () => rc.phase.value !== 'idle' && rc.phase.value !== 'closed' && rc.phase.value !== 'error',
)
// Best-effort caps gating: the agent advertises its audio codecs in
// `AgentCaps.audio` (mirrored onto `Agent.capabilities.audio` server-
// side and returned by GET /tenant/{id}/agent). When the list is
// present but doesn't contain 'opus', the agent can't stream audio, so
// we disable the toggle with an explanatory tooltip — mirroring how
// Crystal-Clear disables on `!vp9_444Supported`. When caps haven't
// loaded yet (agent === null) we DON'T block: the toggle stays enabled
// and the agent ignores `audio_enabled` if it can't honour it (graceful
// no-op). An empty/absent list on an already-loaded agent means "no
// audio feature" → disabled.
const agentAudioCaps = computed<string[] | undefined>(() => agent.value?.capabilities?.audio)
const agentSupportsAudio = computed<boolean>(() => {
  // Unknown (caps not loaded) → optimistically allow.
  if (!agent.value) return true
  return (agentAudioCaps.value ?? []).includes('opus')
})
const audioTooltip = computed<string>(() => {
  // FR-101 P2c — the session policy took audio out of this session, whatever
  // the toggle says.
  if (sessionLive.value && audioRefusal.value) return audioRefusal.value
  // FR-97 P3c-1 — the device's own word on this session's silence.
  const silent = rc.audioUnavailable.value
  if (sessionLive.value && silent) {
    const said = silent.hint || 'This host sends no sound in this session.'
    return silent.detail ? `${said} (${silent.detail})` : said
  }
  if (!agentSupportsAudio.value) {
    // FR-97 P0c — the device says why, where it knows (no capture backend on
    // its OS); an older agent leaves only the build to blame.
    return (
      hostReason(agent.value?.capabilities, 'audio') ??
      'This agent does not advertise audio support (needs an agent built with the audio feature) — receive-audio unavailable'
    )
  }
  if (sessionLive.value) {
    return audioOn.value
      ? 'Host audio ON — disconnect to change (takes effect on next Connect)'
      : 'Host audio OFF — disconnect to change (takes effect on next Connect)'
  }
  return audioOn.value
    ? 'Receive host audio ON — the host\'s system/desktop audio plays here. Takes effect on next Connect.'
    : 'Receive host audio OFF — click to hear the host\'s system/desktop audio on next Connect.'
})
function toggleAudio() {
  rc.setAudioEnabled(!audioOn.value)
}

// loopback-TURN corp-relay assist (browser half). Mirrors the audio
// toggle's next-Connect semantics: the probe + ICE injection happen in
// connect(), so a mid-session flip would look like it did nothing —
// disable while live. Reads the composable's persisted opt-in
// (localStorage `meshharbor-rc-local-relay`).
const localRelayOn = computed<boolean>(() => rc.localRelayEnabled.value)
const localRelayTooltip = computed<string>(() => {
  if (sessionLive.value) {
    return 'Corp relay assist — disconnect to change (takes effect on next Connect)'
  }
  return localRelayOn.value
    ? 'Corp relay assist ON — when a direct path can\'t form (UDP-blocked corporate network), relay through this device\'s local agent over the overlay instead of the capped far relay. Takes effect on next Connect.'
    : 'Corp relay assist OFF — click to relay through this device\'s local agent when direct fails (needs an enrolled agent with an overlay on this machine). Takes effect on next Connect.'
})
function toggleLocalRelay() {
  rc.setLocalRelayEnabled(!localRelayOn.value)
}

// ── Clipboard auto-sync (v2) — Settings toggle + blocked-permission hint ──
// Live-effective (no reconnect needed): the composable's watcher
// subscribes/unsubscribes + starts/stops the local triggers on flip.
const clipboardAutoSyncOn = computed<boolean>(() => rc.clipboardAutoSyncEnabled.value)
const clipboardAutoSyncTooltip = computed<string>(() => {
  if (!clipboardAutoSyncOn.value) {
    return 'Clipboard auto-sync OFF — use the toolbar buttons to send/get the clipboard manually.'
  }
  // FR-97 P0c — a host whose watcher does not report copied images says so,
  // so the tooltip stops promising them.
  const images = hostReason(agent.value?.capabilities, 'clipboard-image-events')
  const base = images
    ? `Clipboard auto-sync ON — text you copy on either side, and images you copy here, sync automatically while this tab is focused. ${images} Turn off to use the manual toolbar buttons only.`
    : 'Clipboard auto-sync ON — text and images you copy on either side sync automatically while this tab is focused. Turn off to use the manual toolbar buttons only.'
  return rc.supportsClipboardEvents.value
    ? base
    : base +
        ' This agent is older — remote→local auto-sync needs an agent upgrade; local→remote still syncs.'
})
function toggleClipboardAutoSync() {
  rc.setClipboardAutoSyncEnabled(!clipboardAutoSyncOn.value)
}
// One-shot hint when Chrome denies clipboard-read for the auto-sync
// engine (the latch only fires on a REAL permission denial, not focus
// races). Manual buttons keep working — their reads are gesture-anchored.
watch(
  () => rc.clipboardSyncBlocked.value,
  (blocked) => {
    if (blocked) {
      showError(
        'Clipboard auto-sync needs clipboard permission — click the clipboard icon in Chrome\'s address bar, or use the manual toolbar buttons.',
      )
    }
  },
)

// ── rc.227 — remote keyboard-layout chip + manual picker ──
const agentLayoutCaps = computed<string[]>(() => agent.value?.capabilities?.layout ?? [])
// FR-92 — the agent can run keep busy here and its owner allows it. Equality,
// never a prefix match. An org deny keeps the word: the menu then shows the
// control disabled with the device's own reason.
const agentSupportsKeepBusy = computed<boolean>(
  () => agent.value?.capabilities?.input?.includes('keep-busy') ?? false,
)
// FR-109 — relative mouse, offered only to an agent that advertises
// `mouse-rel` (equality: an older agent cannot parse `mouse_rel`), and only
// while this browser has not switched it off.
const relativeMouseOffered = computed<boolean>(() => {
  let storage: Storage | null = null
  try {
    storage = globalThis.localStorage
  } catch {
    /* blocked site data: not switched off */
  }
  return agentSupportsRelativeMouse(agent.value?.capabilities?.input)
    && !relativeMouseSwitchedOff(storage)
})
watch(relativeMouseOffered, (offered) => rc.setRelativeMouseAllowed(offered), { immediate: true })
// FR-111 — every touch on the picture belongs to the viewer. Without
// `touch-action: none` a touch browser takes a drag over as a pan, and the
// press already on the host is never let go. `meshharbor-rc-touch=legacy` gives
// the stage back to the browser; read once, like the other kill switches.
const stageTouchActionCss = (() => {
  let storage: Storage | null = null
  try {
    storage = globalThis.localStorage
  } catch {
    /* blocked site data: not switched off */
  }
  return stageTouchAction(storage)
})()
/** FR-111 P2 — the touch-mode control, only where a finger can reach the
 *  stage and the gestures are on (not under the `legacy` switch). */
const touchModeOffered = (() => {
  if (stageTouchActionCss !== 'none') return false
  try {
    return (
      (globalThis.navigator?.maxTouchPoints ?? 0) > 0 ||
      globalThis.matchMedia?.('(pointer: coarse)').matches === true
    )
  } catch {
    return false
  }
})()
/** FR-111 P3 — the on-screen controls: off, or a built-in preset, chosen per
 *  device and remembered in this browser. Offered where the touch mode is. */
const touchControlsId = ref<string | null>(null)
watch(agentId, (id) => {
  let storage: Storage | null = null
  try {
    storage = globalThis.localStorage
  } catch {
    /* blocked site data: off */
  }
  touchControlsId.value = id ? readControlsPreset(storage, id) : null
}, { immediate: true })
/** FR-111 P4 — the org's presets, offered beside the built-ins: fetched once
 *  the session connects on a device that offers the controls at all. */
const orgTouchList = computed(() => orgPresets(agentStore.orgTouchPresets))
watch(
  () => rc.phase.value === 'connected' && touchModeOffered,
  (offer) => {
    if (offer) void agentStore.fetchOrgTouchPresets(tenantId.value)
  },
  { immediate: true },
)
/** FR-111 P4b-2 — a member's own layouts, kept in this browser (open
 *  decision 6), per user. */
const myTouchPresets = ref<TouchPreset[]>([])
function myPresetsStorage(): Storage | null {
  try {
    return globalThis.localStorage
  } catch {
    return null
  }
}
watch(
  () => authStore.user?.id ?? null,
  (uid) => {
    myTouchPresets.value = uid ? readMyPresets(myPresetsStorage(), uid) : []
  },
  { immediate: true },
)
/** Every preset beside the built-ins: the org's, then this member's own. */
const extraTouchPresets = computed(() => [...orgTouchList.value, ...myTouchPresets.value])
const touchControlsPreset = computed(() =>
  touchModeOffered ? presetById(touchControlsId.value, extraTouchPresets.value) : null,
)
function setTouchControls(id: string | null) {
  touchControlsId.value = presetById(id, extraTouchPresets.value)?.id ?? null
  try {
    globalThis.localStorage.setItem(CONTROLS_STORAGE_PREFIX + agentId.value, touchControlsId.value ?? 'off')
  } catch {
    /* blocked site data: this tab only */
  }
}

/** FR-111 P4b-2 — the layout editor. While it is open the keyboard types into
 *  it, never into the host (`keyboardPaused`). */
const touchEditorOpen = ref(false)
const canPublishTouch = ref(false)
watch(touchEditorOpen, async (open) => {
  rc.keyboardPaused.value = open
  if (!open) return
  try {
    const tenants = useTenantStore()
    await tenants.ensureMyMembership(tenantId.value)
    canPublishTouch.value = canManageOrgSettings(tenants.myPermissions, tenants.isOwner)
  } catch {
    canPublishTouch.value = false
  }
})
onBeforeUnmount(() => {
  rc.keyboardPaused.value = false
})
function saveMyTouchPreset(p: TouchPreset) {
  const uid = authStore.user?.id
  if (!uid) return
  const next = myTouchPresets.value.some((m) => m.id === p.id)
    ? myTouchPresets.value.map((m) => (m.id === p.id ? p : m))
    : [...myTouchPresets.value, p]
  myTouchPresets.value = next
  writeMyPresets(myPresetsStorage(), uid, next)
}
function deleteMyTouchPreset(id: string) {
  const uid = authStore.user?.id
  if (!uid) return
  myTouchPresets.value = myTouchPresets.value.filter((m) => m.id !== id)
  writeMyPresets(myPresetsStorage(), uid, myTouchPresets.value)
  if (touchControlsId.value === id) setTouchControls(null)
}
function publishTouchPreset(body: { name: string; controls: unknown[] }, serverId: string | null) {
  return agentStore.saveOrgTouchPreset(tenantId.value, body, serverId)
}
function deleteOrgTouchPreset(serverId: string) {
  return agentStore.deleteOrgTouchPreset(tenantId.value, serverId)
}
/** The stage's scroll offsets, so the overlay stays over the part of the
 *  stage on screen when a zoomed picture scrolls. */
const stageScroll = ref({ x: 0, y: 0 })
function onStageScroll(ev: Event) {
  const el = ev.currentTarget as HTMLElement
  stageScroll.value = { x: el.scrollLeft, y: el.scrollTop }
}
// No scroll event fires when a reconnect mounts a fresh stage or a zoom mode
// that does not scroll takes over, so read the offsets again then.
watch([stageEl, () => rc.scaleMode.value], () => {
  void nextTick(() => {
    const el = stageEl.value
    stageScroll.value = { x: el?.scrollLeft ?? 0, y: el?.scrollTop ?? 0 }
  })
})
/** FR-111 — a pinch zooms the viewer's own picture (nothing reaches the host),
 *  around the point between the fingers, so what they were over stays under
 *  them. It switches to Custom zoom, starting from the size the picture is
 *  shown at, and the stage (which scrolls in Custom zoom) follows the point. */
function onPinchZoom(factor: number, cx: number, cy: number) {
  const el = stageEl.value as HTMLElement | null
  const w = videoIntrinsicW.value
  if (!el || !Number.isFinite(w) || w <= 0) return
  const shown = Array.from(el.querySelectorAll<HTMLElement>('.remote-video'))
    .map((m) => m.getBoundingClientRect())
    .find((r) => r.width > 0)
  if (!shown) return
  const from = rc.scaleMode.value === 'custom' ? rc.scaleCustomPercent.value : (shown.width / w) * 100
  if (rc.scaleMode.value !== 'custom') rc.setScaleMode('custom')
  rc.setScaleCustomPercent(from * factor)
  const ratio = rc.scaleCustomPercent.value / from
  const stage = el.getBoundingClientRect()
  const ox = cx - stage.left
  const oy = cy - stage.top
  const px = el.scrollLeft + ox
  const py = el.scrollTop + oy
  void nextTick(() => {
    el.scrollLeft = px * ratio - ox
    el.scrollTop = py * ratio - oy
  })
}
/** FR-111 decision 4 (operator, 2026-10-17) — while the picture is larger than
 *  the stage (zoomed past it; the stage scrolls in Custom zoom), two fingers
 *  moving together pan it instead of scrolling the host, and a one-line hint
 *  says so. Once it fits, they scroll the host again. */
const touchPanHint = ref(false)
let touchPanHintTimer: ReturnType<typeof setTimeout> | null = null
function onTwoFingerScroll(dx: number, dy: number): boolean {
  const el = stageEl.value as HTMLElement | null
  if (!el || !pictureOverflows(el)) return false
  el.scrollLeft += dx
  el.scrollTop += dy
  touchPanHint.value = true
  if (touchPanHintTimer) clearTimeout(touchPanHintTimer)
  touchPanHintTimer = setTimeout(() => {
    touchPanHint.value = false
  }, 2500)
  return true
}
/** FR-109 — the toolbar control: a click is the gesture Pointer Lock needs.
 *  Once locked the pointer is hidden, so leaving is Esc (the browser's own
 *  rule); a click while locked leaves too, for a lock the page still sees. */
async function onRelativeMouse() {
  if (rc.relativeMouse.value) {
    rc.exitRelativeMouse()
    return
  }
  await rc.enterRelativeMouse()
}
// FR-92 P8 — the org's default pattern, for a device this person has no
// remembered choice on. Read once per viewer open; any member may read it,
// and a failure means circle (the store never throws here).
const orgKeepBusyDefault = ref<KeepBusyPattern | null>(null)
/** Pretty layout label via Intl.DisplayNames ("bg-BG" → "Bulgarian
 *  (Bulgaria)" in the viewer's language); raw tag on failure (the
 *  agent falls back to a hex LANGID for layouts the OS can't name). */
function remoteLayoutLabel(tag: string): string {
  try {
    const name = new Intl.DisplayNames([navigator.language], { type: 'language' }).of(tag)
    return name && name !== tag ? `${name} (${tag})` : tag
  } catch {
    return tag
  }
}
const remoteLayoutItems = computed(() =>
  (rc.remoteLayout.value?.installed ?? []).map((e) => ({
    value: e.hkl,
    title: remoteLayoutLabel(e.tag),
  })),
)
function onRemoteLayoutPick(hkl: unknown) {
  if (typeof hkl === 'string' && hkl) rc.setRemoteLayout(hkl)
}

// ── rc.199 — unified Codec picker + Priority dial (Settings panel) ──
// The Codec picker folds the four transport toggles + the codec-override +
// VP9-chroma dropdowns into ONE choice. `rc.codecChoice` is a writable
// computed in the composable (derives the value from transport+chroma; the
// setter applies the full tuple through the existing setters), so this is a
// thin binding.
const codecChoice = rc.codecChoice
// Per-choice availability + one-line "why". Reuses the same support flags the
// old toggles gated on (`av1Supported`+`agentHasAv1`, `hevcSupported`,
// `vp9_444Supported`); an unsupported choice is disabled with the reason as a
// subtitle. `props` is spread onto the v-list-item Vuetify renders.
// FR-77 — the validity matrix behind the two dropdowns: the agent's cells
// (one derivation for new and old agents) crossed with this browser's decode
// probes and the decode failures remembered for this device. 4:2:0 cells stay
// optimistic until the device record arrives (the rc.190 contract — the agent
// falls back when it cannot honour a pick); every 4:4:4 cell demands proof
// from both ends, because a chroma mismatch is a black screen.
const cellAvail = computed<Availability>(() =>
  cellAvailability({
    cells: cellsFromCaps(agent.value?.capabilities),
    capsLoaded: !!agent.value?.capabilities,
    browser: {
      av1: rc.av1Supported.value,
      hevc: rc.hevcSupported.value,
      hevcRext: rc.hevcRextSupported.value,
      h264High444: rc.h264High444Supported.value,
      vp9: rc.vp9_444Supported.value,
    },
    failed: agent.value?.id
      ? rememberedCellFailures(agent.value.id, globalThis.navigator?.userAgent ?? '')
      : new Set<string>(),
  }),
)
/** The codec axis, written through to the stored choice with the chroma
 *  axis left as it is (and vice versa), so both persist per agent exactly as
 *  the single choice did. */
const pickerCodec = computed<PickerCodec>({
  get: () => pickerFromChoice(codecChoice.value).codec,
  set: (codec) => {
    codecChoice.value = choiceFromPicker(codec, pickerFromChoice(codecChoice.value).chroma)
  },
})
const pickerChroma = computed<PickerChroma>({
  get: () => pickerFromChoice(codecChoice.value).chroma,
  set: (chroma) => {
    codecChoice.value = choiceFromPicker(pickerFromChoice(codecChoice.value).codec, chroma)
  },
})
const codecOptions = computed(() =>
  PICKER_CODECS.map((codec) => {
    const v = codecSelectable(cellAvail.value, codec, pickerChroma.value)
    return {
      title: t(`remote.codec.codecs.${codec}`),
      value: codec,
      props: { disabled: !v.ok, subtitle: t(`remote.codec.reason.${v.reason}`) },
    }
  }),
)
const chromaOptions = computed(() =>
  PICKER_CHROMAS.map((chroma) => {
    const v = chromaSelectable(cellAvail.value, pickerCodec.value, chroma)
    return {
      title: t(`remote.codec.chromas.${chroma}`),
      value: chroma,
      props: { disabled: !v.ok, subtitle: t(`remote.codec.reason.${v.reason}`) },
    }
  }),
)

// Priority dial — the visible lever over the per-session relay resolution cap
// (sent LIVE via rc:priority). Replaces the old Quality dropdown, which only
// shadowed the agent's AIMD/REMB controller.
const priority = computed<RcPriority>({
  get: () => rc.priority.value,
  set: (v: RcPriority) => rc.setPriority(v),
})

// FR-119 P1 — the frame-rate picker, for an agent advertising `fps-high` only.
const frameRateOffered = computed(() => agentOffersHighRefresh(agent.value?.capabilities?.video))
const frameRateItems = computed(() =>
  rc.frameRateChoices.value.map((o) => ({
    title: `${o.fps} fps`,
    value: o.fps,
    props: { disabled: !o.enabled, subtitle: o.why ?? undefined },
  })),
)
const frameRatePick = computed<FrameRate>({
  get: () => rc.frameRate.value,
  set: (v: FrameRate) => rc.setFrameRate(v),
})
const frameRateHint = computed(
  () =>
    frameRateSummary(rc.frameRateAnswer.value) ??
    'Above 60 only where this device has shown it can sustain it',
)
const priorityOptions = [
  {
    title: 'Balanced',
    value: 'balanced',
    props: { subtitle: 'Default — caps resolution on slow / relay links to stay smooth' },
  },
  {
    title: 'Sharper',
    value: 'sharper',
    props: { subtitle: 'Full resolution even on a relay (crisp text; may stutter on a weak link)' },
  },
  {
    title: 'Smoother',
    value: 'smoother',
    props: { subtitle: 'Fewer pixels for higher frame-rate + lower latency' },
  },
] as const
const priorityHint = computed<string>(
  () => priorityOptions.find((o) => o.value === priority.value)?.props.subtitle ?? '',
)

// P7 — FSR text sharpening (viewer-side, live; see rc-fsr-render.ts). Auto
// engages the EASU+RCAS upscale only when the decoded stream is smaller
// than the window needs (the Smoother/relay rungs) — exactly when CSS
// bilinear used to smear remote text.
const sharpen = computed<'auto' | 'on' | 'off'>({
  get: () => rc.sharpenMode.value,
  set: (v) => rc.setSharpenMode(v),
})
const sharpenHint = computed<string>(() => {
  switch (sharpen.value) {
    case 'on':
      return 'Always sharpen (AMD FSR), even at 1:1 — maximum text crispness'
    case 'off':
      return 'Plain browser scaling (pre-P7 behaviour)'
    default:
      return 'Sharpen (AMD FSR) only when the stream is smaller than your window'
  }
})
// Native-source hint for the Resolution select (reused from the retired
// mobile sheet). Explains why a big custom target on a small-panel host
// doesn't change anything, and surfaces the agent's native dims.
const resolutionSettingHint = computed<string>(() => {
  const native = nativeSourceLabel.value
  if (!native) return 'Native dimensions surface after the first decoded frame'
  // FR-70 P1 — an overridden choice is never silent: when the agent caps
  // the stream below what was asked, the setting says what, why and what
  // lifts it, ahead of the native-dims note.
  const { w, h } = decodedDims.value
  const override = resolutionOverrideHint(rc.videoInfo.value, w, h)
  if (override) return `${override} Agent native ${native}.`
  return customTargetExceedsNative.value
    ? `Agent native ${native} — custom target exceeds this; capped at native`
    : `Agent native ${native}`
})

/** Bind callback for the webcodecs canvas ref. Vue calls this with
 *  the element (or null on unmount) — we forward to the composable's
 *  writable canvas ref so `pc.ontrack` can see it. */
function bindWebcodecsCanvas(el: Element | unknown) {
  rc.webcodecsCanvasEl.value = (el as HTMLCanvasElement | null) ?? null
}

// Phase Y.4 view-side render gate. Flips true when the composable
// has opened the `video-bytes` DC AND spun up the VP9-444 worker
// (Y.3 sets `vp9_444Active` in `startVp9_444Path()`). Drives the
// template `<canvas>` swap below — the legacy `<video>` element
// stays hidden in this mode because the agent doesn't ship a
// WebRTC video track when the negotiated transport is
// `data-channel-vp9-444`.
const isVp9_444Render = computed<boolean>(() => rc.vp9_444Active.value)
/** Bind callback for the VP9-444 canvas. The composable's watcher
 *  on `vp9_444CanvasEl` transfers OffscreenCanvas control to the
 *  worker as soon as we set the ref, replacing the synthetic
 *  OffscreenCanvas the worker started with so decoded frames land
 *  on the visible element. */
function bindVp9_444Canvas(el: Element | unknown) {
  rc.vp9_444CanvasEl.value = (el as HTMLCanvasElement | null) ?? null
}

// rc.80 — HEVC over DataChannel render gate. Flips true when the
// composable's `media_pump_hevc_dc` peer-side counterpart has opened
// the DC + spun up the HEVC worker. Drives the template's HEVC
// canvas mount.
const isHevcRender = computed<boolean>(() => rc.hevcActive.value)

// P1 — per-hop diagnostics pill (opt-in localStorage meshharbor-rc-diag-hud=1).
// Read once at mount: flipping the flag is a reload-scoped A/B, matching the
// other meshharbor-rc-* diagnosis knobs.
// FR-26 - per-pill visibility, persisted per user. `paint` inherits the
// legacy meshharbor-rc-diag-hud flag on first read (see storedMetricToggles).
const settingsTab = ref<'video' | 'display' | 'metrics' | 'session'>('video')
const metrics = ref(storedMetricToggles())
watch(metrics, (m) => persistMetricToggles(m), { deep: true })
const showDiagHud = computed(() => metrics.value.paint)
const diagLabel = computed(() => {
  const d = rc.decodeDiag.value
  if (!d) return ''
  const hop = (w: { avgMs: number; maxMs: number } | null) =>
    w ? `${w.avgMs}/${w.maxMs}` : '–'
  // P7 — active render path + actual backing size (e.g. "fsr@2048x1280"),
  // for field-verifying the FSR sizing policy.
  const r = rc.renderInfo.value
  const render = r ? ` · ${r.mode}@${r.w}x${r.h}` : ''
  // FR-1 P7 — age avg/max + the probe's own RTT, for splitting "old
  // frames" into network-vs-pipeline at a glance.
  const age = d.age ? ` · age ${hop(d.age)}` : ''
  const rtt = d.probeRttMs !== null ? ` · rtt ${Math.round(d.probeRttMs)}` : ''
  return (
    `paint ${hop(d.paint)} · fwd ${hop(d.fwd)} · dec ${hop(d.decode)}${age}${rtt}`
    + ` · gap ${d.outGapMaxMs} · q ${d.queue} · drop ${d.droppedTotal}`
    + ` · long ${d.longTasksPerSec}/${d.longTaskMsPerSec}ms · ${d.ctxMode}${render}`
  )
})
/** Bind callback for the HEVC canvas. Same `transferControlToOffscreen`
 *  pattern as the VP9-444 canvas — composable's `hevcCanvasEl`
 *  watcher fires once the ref lands. */
function bindHevcCanvas(el: Element | unknown) {
  rc.hevcCanvasEl.value = (el as HTMLCanvasElement | null) ?? null
}

// Fullscreen toggle. Drives the stage element into/out of the browser's
// Fullscreen API. `isFullscreen` tracks the real DOM state via the
// fullscreenchange event so ESC (which the browser handles natively)
// updates the icon without us polling.
//
// `fullscreenEnabled` gates the toolbar button: iOS Safari only supports
// `webkitEnterFullscreen` on `<video>` elements, NOT on arbitrary divs,
// and won't show overlay canvases (cursor / stats / no-media-overlay)
// because they aren't part of the <video>. Rather than render a button
// that does nothing, we hide it on browsers where the API isn't usable.
// `document.fullscreenEnabled` is the standard property; reads false on
// iPhone Safari, true on Chrome/Firefox/Safari desktop, true in Chromium
// Android (where it works on divs).
const fullscreenEnabled = computed<boolean>(() => {
  if (typeof document === 'undefined') return false
  return document.fullscreenEnabled === true
})
const isFullscreen = ref(false)
// Advertise the keyboard-lock upgrade on Chromium; other browsers get
// the plain label (fullscreen still works, shortcuts stay local).
const fullscreenButtonTooltip = computed<string>(() =>
  isKeyboardLockSupported()
    ? 'Fullscreen — system shortcuts (Alt+Tab, Win, Ctrl+W) go to the remote'
    : 'Fullscreen',
)
function toggleFullscreen() {
  const el = stageEl.value
  if (!el) return
  if (document.fullscreenElement) {
    void document.exitFullscreen().catch(() => { /* user cancelled; ignore */ })
  } else {
    void el.requestFullscreen().catch(() => { /* user gesture / API missing; ignore */ })
  }
}
// Keyboard-lock affordances: a 4 s toast on entering locked
// fullscreen + a persistent subtle pill while locked. Both live
// INSIDE .video-frame (the fullscreen element) — Vuetify snackbars
// teleport to <body>, which is invisible in fullscreen.
const shortcutOverlayVisible = ref(false)
let shortcutOverlayTimer: ReturnType<typeof setTimeout> | null = null
function onFullscreenChange() {
  isFullscreen.value = document.fullscreenElement !== null
  if (isFullscreen.value) {
    // Engage Keyboard Lock so Alt+Tab / Win / Ctrl+W go to the
    // REMOTE. Not awaited inline — a hung lock() promise must degrade
    // to legacy behavior, never block the fullscreen transition.
    void rc.enableKeyboardLock().then((ok) => {
      if (!ok) return
      shortcutOverlayVisible.value = true
      if (shortcutOverlayTimer) clearTimeout(shortcutOverlayTimer)
      shortcutOverlayTimer = setTimeout(() => {
        shortcutOverlayVisible.value = false
      }, 4000)
    })
  } else {
    rc.disableKeyboardLock()
    shortcutOverlayVisible.value = false
    if (shortcutOverlayTimer) {
      clearTimeout(shortcutOverlayTimer)
      shortcutOverlayTimer = null
    }
  }
}

// Inline style for the <video> element. In `original` and `custom`
// modes we set explicit pixel dims so the outer `.video-frame` can
// detect overflow and show scrollbars; the `<video>` element's
// `width: auto` default is unreliable inside a flex container. In
// `adaptive` mode the CSS class handles sizing (100%/100% +
// object-fit: contain).
const videoScaleStyle = computed<Record<string, string> | undefined>(() => {
  const w = videoIntrinsicW.value
  const h = videoIntrinsicH.value
  if (!Number.isFinite(w) || !Number.isFinite(h) || w <= 0 || h <= 0) return undefined
  if (rc.scaleMode.value === 'custom') {
    const pct = rc.scaleCustomPercent.value / 100
    return { width: `${w * pct}px`, height: `${h * pct}px` }
  }
  if (rc.scaleMode.value === 'original') {
    return { width: `${w}px`, height: `${h}px` }
  }
  return undefined
})

// -----------------------------------------------------------------
// Remote resolution (Phase 2 of the viewer-controls sprint)
// -----------------------------------------------------------------

// The v-select value is a discriminator string — not the full
// RcResolutionSetting — because v-select items need primitive values
// for equality. `original` / `fit` map directly; `custom` maps to
// `custom:<w>x<h>` for display and opens a dialog when picked so the
// operator can edit dims.
const resolutionOptions = computed(() => {
  const opts: { title: string; value: string }[] = [
    { title: 'Original resolution', value: 'original' },
    { title: 'Fit to local viewport', value: 'fit' },
  ]
  if (rc.resolution.value.mode === 'custom') {
    const w = rc.resolution.value.width ?? 0
    const h = rc.resolution.value.height ?? 0
    // rc.35 — annotate when the operator-picked custom dims exceed
    // the agent's native source (apply_target_resolution refuses to
    // upscale; would just look the same as 'original').
    const suffix = presetExceedsNative(w, h) ? ' (capped at native)' : ''
    opts.push({ title: `Custom: ${w} × ${h}${suffix}`, value: 'custom-current' })
  }
  opts.push({ title: 'Custom…', value: 'custom-edit' })
  return opts
})

const resolutionPresetValue = computed<string>({
  get: () => {
    if (rc.resolution.value.mode === 'original') return 'original'
    if (rc.resolution.value.mode === 'fit') return 'fit'
    return 'custom-current'
  },
  set: (v) => {
    if (v === 'original') {
      rc.setResolution({ mode: 'original' })
    } else if (v === 'fit') {
      applyFitResolution()
    } else if (v === 'custom-edit') {
      // Seed the dialog from the current values (or the stage's
      // dimensions if we have none yet) so the user isn't starting
      // from a blank field.
      const cur = rc.resolution.value
      customResolutionW.value = cur.width ?? 1920
      customResolutionH.value = cur.height ?? 1080
      customResolutionDialog.value = true
    }
    // 'custom-current' is a noop — it's only used as the v-select's
    // "display the existing custom dims" slot.
  },
})

const resolutionButtonTitle = computed(() => {
  const s = rc.resolution.value
  const native = nativeSourceLabel.value
  const nativeHint = native ? ` — agent native ${native}` : ''
  if (s.mode === 'original') return `Agent streams at native monitor resolution${nativeHint}`
  if (s.mode === 'fit') {
    return `Agent downscales to fit local viewport (currently ${s.width ?? '?'} × ${s.height ?? '?'})${nativeHint}`
  }
  const capped = customTargetExceedsNative.value
    ? ` — exceeds native ${native}, will be capped at native (no upscale)`
    : nativeHint
  return `Custom: ${s.width ?? '?'} × ${s.height ?? '?'}${capped}`
})

/** rc.35 — agent's native source dims, surfaced for the resolution UI
 *  so the operator can see why a 4K custom target on a 1080p-panel
 *  host doesn't change anything.
 *
 *  The agent's OWN report (`rc:video-info` native_w/h = its panel) is the
 *  truth and is preferred. The decoded-stream dims below it are the ENCODE
 *  BOX whenever a resolution cap engages — since the capture backend scales
 *  server-side, labelling those "Agent native" told the operator their
 *  3024×1964 panel was 1926×1252 (field 2026-08-26). Stream dims remain the
 *  fallback for agents that never send video-info (legacy track + libvpx
 *  paths), where they keep their old, then-accurate meaning. Zero before
 *  the first frame / report. */
const nativeSourceW = computed<number>(() => {
  const vi = rc.videoInfo.value
  if ((vi?.native_w ?? 0) > 0) return vi!.native_w
  if (rc.hevcActive.value && rc.hevcStats.value.width > 0) {
    return rc.hevcStats.value.width
  }
  if (rc.vp9_444Active.value && rc.vp9_444Stats.value.width > 0) {
    return rc.vp9_444Stats.value.width
  }
  return rc.mediaIntrinsicW.value || 0
})
const nativeSourceH = computed<number>(() => {
  const vi = rc.videoInfo.value
  if ((vi?.native_h ?? 0) > 0) return vi!.native_h
  if (rc.hevcActive.value && rc.hevcStats.value.height > 0) {
    return rc.hevcStats.value.height
  }
  if (rc.vp9_444Active.value && rc.vp9_444Stats.value.height > 0) {
    return rc.vp9_444Stats.value.height
  }
  return rc.mediaIntrinsicH.value || 0
})
const nativeSourceLabel = computed<string>(() => {
  const w = nativeSourceW.value
  const h = nativeSourceH.value
  if (!w || !h) return ''
  return `${w}×${h}`
})
/** Returns true iff (w, h) exceeds the agent's native source on
 *  either axis. Used both by the dropdown's custom-current title
 *  annotation and the per-preset chip styling inside the custom
 *  dialog. False until the first frame lands and native is known. */
function presetExceedsNative(w: number, h: number): boolean {
  const nw = nativeSourceW.value
  const nh = nativeSourceH.value
  if (!nw || !nh) return false
  return w > nw || h > nh
}
const customTargetExceedsNative = computed<boolean>(() => {
  const r = rc.resolution.value
  if (r.mode !== 'custom') return false
  return presetExceedsNative(r.width ?? 0, r.height ?? 0)
})

const customResolutionDialog = ref(false)
const customResolutionW = ref(1920)
const customResolutionH = ref(1080)
const customResolutionPresets: Array<{ w: number; h: number; note?: string }> = [
  { w: 1280, h: 720, note: '720p' },
  { w: 1920, h: 1080, note: '1080p' },
  { w: 1920, h: 1200, note: 'WUXGA' },
  { w: 2560, h: 1440, note: '1440p' },
  { w: 2560, h: 1600, note: 'WQXGA' },
  { w: 3840, h: 2160, note: '4K UHD' },
]
const customResolutionValid = computed(() => {
  const w = customResolutionW.value
  const h = customResolutionH.value
  return (
    Number.isFinite(w) && Number.isFinite(h) &&
    w >= 160 && w <= 7680 &&
    h >= 120 && h <= 4320
  )
})
function pickCustomResolutionPreset(w: number, h: number) {
  customResolutionW.value = w
  customResolutionH.value = h
}
function confirmCustomResolution() {
  if (!customResolutionValid.value) return
  const setting: RcResolutionSetting = {
    mode: 'custom',
    width: Math.round(customResolutionW.value),
    height: Math.round(customResolutionH.value),
  }
  rc.setResolution(setting)
  customResolutionDialog.value = false
}

/** Apply Fit mode using the current stage dimensions × devicePixelRatio
 *  — captures "what fits in my browser right now at its native pixel
 *  density". Also re-emitted on stage resize via `ResizeObserver`
 *  below, debounced 250 ms so drag-resize doesn't churn the encoder. */
function applyFitResolution() {
  const el = stageEl.value
  if (!el) return
  const rect = el.getBoundingClientRect()
  const dpr = window.devicePixelRatio || 1
  // Floor to even numbers — MF HEVC encoder requires even dims and
  // fail-closes to NoopEncoder otherwise (permanent black screen
  // until reconnect). The agent also rounds defensively, but
  // emitting clean numbers here avoids the log churn. Clamp mins
  // to 160×90 so weird <= 1 layouts don't flood with tiny requests.
  const w = Math.max(160, Math.round(rect.width * dpr) & ~1)
  const h = Math.max(90, Math.round(rect.height * dpr) & ~1)
  rc.setResolution({ mode: 'fit', width: w, height: h })
}

// rc.191 — "Match remote display" toggle. When ON, the agent switches the
// HOST's display to the largest mode fitting this viewer's stage (and
// restores it on disconnect/toggle-off) — the RDP-style fix that makes the
// pixel chain 1:1 so remote text is rendered AT the viewed size instead of
// downscaled into mush. Opt-in (changing a host's display mode is
// invasive), persisted per-agent, Windows hosts only (v1).
const DISPLAY_MATCH_STORAGE_PREFIX = 'meshharbor-rc-display-match.v2:'
const displayMatchOn = ref(false)
// FR-97 P3e-2 — the device's own word, not its OS: a host whose display
// cannot be switched says so (`AgentCaps.unavailable['display-match']`), with
// why. Until P3e-2 this gated on Windows, which hid a Linux virtual desktop
// that could switch, and now hides nothing that can. An agent from before
// FR-97 P0c carries no `unavailable` map at all, and keeps rc.191's gate.
const displayMatchUnavailable = computed<string | null>(() =>
  hostReason(agent.value?.capabilities, 'display-match'),
)
const agentSupportsDisplayMatch = computed<boolean>(() => {
  if (!hostSpeaks(agent.value?.capabilities)) {
    return (agent.value?.os ?? '').toLowerCase().startsWith('win')
  }
  return displayMatchUnavailable.value === null
})
/** FR-108 — what the device answered this session's request, in one line;
 *  null when it said nothing (an agent before FR-108, or no request yet). */
const displayMatchSaid = computed<string | null>(() =>
  displayMatchOn.value ? displayMatchSummary(rc.displayMatchState.value) : null,
)
const displayMatchTooltip = computed<string>(() => {
  if (!agentSupportsDisplayMatch.value) {
    return displayMatchUnavailable.value
      ? `Match remote display — ${displayMatchUnavailable.value}`
      : 'Match remote display — this agent is too old to say whether its display can be switched'
  }
  // FR-108 — the device decides (its owner's setting, and whether someone is
  // using the screen); say what it answered when it has.
  if (displayMatchSaid.value) {
    return `Match remote display ON — ${displayMatchSaid.value}. Click to turn it off.`
  }
  return displayMatchOn.value
    ? 'Match remote display ON — the host switched its display mode to fit this window (restored on disconnect). Sharpest text.'
    : 'Match remote display OFF — click to switch the HOST\'s display mode to fit this window (1:1 pixels, sharpest text). Restored on disconnect.'
})
function readStoredDisplayMatch(agentId: string): boolean {
  // 2026-08-02 operator default: ON for agents without a stored choice
  // (pairs with the resolution=Original default — 1:1 pixels, sharpest
  // text). Explicit OFF is stored as '0' (persist below writes both
  // states) so it survives the ON default; pre-change rows that toggled
  // OFF via the old removeItem semantics flip to ON once.
  try {
    return globalThis.localStorage?.getItem(DISPLAY_MATCH_STORAGE_PREFIX + agentId) !== '0'
  } catch {
    return true
  }
}
function persistDisplayMatch(agentId: string, on: boolean) {
  try {
    globalThis.localStorage?.setItem(DISPLAY_MATCH_STORAGE_PREFIX + agentId, on ? '1' : '0')
  } catch {
    /* best-effort */
  }
}
/** Send the display-match request for the CURRENT stage size. */
function sendDisplayMatchNow() {
  const el = stageEl.value
  if (!el) return
  const rect = el.getBoundingClientRect()
  const dpr = window.devicePixelRatio || 1
  rc.sendDisplayMatch({
    width: Math.max(160, Math.round(rect.width * dpr)),
    height: Math.max(90, Math.round(rect.height * dpr)),
  })
}
function toggleDisplayMatch() {
  displayMatchOn.value = !displayMatchOn.value
  persistDisplayMatch(agentId.value, displayMatchOn.value)
  if (rc.phase.value === 'connected') {
    if (displayMatchOn.value) sendDisplayMatchNow()
    else rc.sendDisplayMatch(null)
  }
}
// Restore the per-agent preference (route param is stable per mount).
watch(
  agentId,
  (id) => {
    if (id) displayMatchOn.value = readStoredDisplayMatch(id)
  },
  { immediate: true },
)

// ResizeObserver on the stage so Fit mode tracks viewport changes.
// Debounced — drag-resize fires dozens of events per second and each
// rc:resolution change rebuilds the encoder on the agent side.
let fitResizeTimer: ReturnType<typeof setTimeout> | null = null
let fitResizeObserver: ResizeObserver | null = null
// #1435 — the element the observer is bound to. The stage is a `v-else-if`
// branch, so it is a NEW element every time the phase re-enters `connected`
// (and once more when the first render replaces the placeholder in a fresh
// tab); an observer that survived on the previous element watched a node no
// longer in the document and Fit mode silently stopped following resizes
// until the mode was re-selected. Start is idempotent per ELEMENT, not per
// call: a different stage re-targets the observer.
let fitObservedEl: HTMLElement | null = null
// FR-74 P4 — the stage's CSS box, for the display-scale pill. Fed by the
// same ResizeObserver as Fit mode (every resize, whatever the resolution
// mode), so the scale follows window drags and browser zoom without a
// second observer.
const stageCss = ref({ w: 0, h: 0 })
function measureStage(el: HTMLElement) {
  stageCss.value = { w: el.clientWidth, h: el.clientHeight }
}
function startFitResizeObserver() {
  const el = stageEl.value
  if (!el || !('ResizeObserver' in window)) return
  if (fitResizeObserver && fitObservedEl === el) return
  stopFitResizeObserver()
  fitResizeObserver = new ResizeObserver(() => {
    if (fitObservedEl) measureStage(fitObservedEl)
    if (rc.resolution.value.mode !== 'fit') return
    if (fitResizeTimer) clearTimeout(fitResizeTimer)
    fitResizeTimer = setTimeout(() => {
      applyFitResolution()
    }, 250)
  })
  fitResizeObserver.observe(el)
  fitObservedEl = el
  measureStage(el)
}
function stopFitResizeObserver() {
  if (fitResizeTimer) {
    clearTimeout(fitResizeTimer)
    fitResizeTimer = null
  }
  if (fitResizeObserver) {
    fitResizeObserver.disconnect()
    fitResizeObserver = null
  }
  fitObservedEl = null
}
// #1435 — and re-arm from the DOM side too: the template ref is assigned in
// the render's post-flush, after the phase watcher (pre-flush) has already
// seen `connected` with a null stage. Watching the element itself, post-flush,
// makes the attach independent of that ordering.
watch(
  stageEl,
  (el) => {
    if (el && rc.phase.value === 'connected') {
      startFitResizeObserver()
      if (rc.resolution.value.mode === 'fit') applyFitResolution()
    }
  },
  { flush: 'post' },
)

// Stats readout formatters. Pure computeds — the composable already
// polls getStats() every 500 ms and updates rc.stats.value.
//
// The codec label is enriched with HW/SW based on the agent's
// advertised AgentCaps.hw_encoders (2A.2 wired). This makes the
// pill informative ("H.265 HW") rather than ambiguous ("H265").
const statsCodecLabel = computed(() => {
  // rc.87 — when the agent reported its REAL encoder via
  // `rc:video-info`, use that (the honest source of truth). Format:
  // "VP9 4:2:0 HW (vp9_qsv)" / "H.265 4:2:0 HW (hevc_nvenc)". This
  // replaces the hardcoded "VP9 4:4:4 SW" that lied when the agent
  // actually ran vp9_qsv HW at 4:2:0.
  const vi = rc.videoInfo.value
  if (vi && (rc.vp9_444Active.value || rc.hevcActive.value)) {
    const codecName = vi.codec.toLowerCase() === 'h265'
      ? 'H.265'
      : vi.codec.toLowerCase() === 'h264'
        ? 'H.264'
        : vi.codec.toLowerCase() === 'vp9'
          ? 'VP9'
          : vi.codec.toUpperCase()
    const chromaName = vi.chroma === 'yuv444' ? '4:4:4' : vi.chroma === 'yuv420' ? '4:2:0' : ''
    const hw = vi.hardware ? 'HW' : 'SW'
    const enc = vi.encoder ? ` (${vi.encoder})` : ''
    // Relay-escape — show WHICH ICE path this session took ("relay" =
    // TURN-relayed → bitrate-clamped + extra RTT; "direct" = P2P). The
    // agent re-sends video-info when the path changes mid-session, so
    // this suffix flips live. Empty from agents older than the field.
    // FR-33 P3 — when the agent can NAME the relay's cause (a VPN captures
    // its host's LAN and this viewer sits inside that prefix), say so on
    // the pill: the whole point is that a relay on a same-LAN pair is never
    // again hunted as an encoder regression.
    const path =
      vi.transport === 'relay'
        ? vi.transport_reason === 'lan-captured'
          ? " · relay · VPN captures the host's LAN"
          : ' · relay'
        : vi.transport === 'direct'
          ? ' · direct'
          : ''
    // rc.190 — the VIEWER half of the HW×HW story: whether THIS browser
    // decodes the session's codec on fixed-function silicon
    // (MediaCapabilities smooth+powerEfficient at transport-pick time).
    // The agent-side `hw` above covers encode; a weak viewer grinding a
    // codec in software is now visible instead of a mystery.
    const dec =
      rc.viewerDecodeHw.value === true
        ? ' · dec HW'
        : rc.viewerDecodeHw.value === false
          ? ' · dec SW'
          : ''
    // P5 — the agent's shared-floor pipeline: >1 viewers on this encoded
    // stream means rate/dials are floor-merged across them, so a lower
    // fps/resolution than expected is explainable from the badge.
    const shared = (vi.viewers ?? 1) > 1 ? ` · shared ×${vi.viewers}` : ''
    // P7 — flag the active FSR sharpening pass (exact mode + backing size
    // live in the diag HUD; the pill stays binary for glanceability).
    const fsr = rc.renderInfo.value && rc.renderInfo.value.mode !== '2d' ? ' · FSR' : ''
    return [codecName, chromaName, hw].filter(Boolean).join(' ') + enc + path + dec + shared + fsr
  }
  // FR-80 — no video-info yet. Name the codec the viewer's own DECODER was
  // configured with, and claim nothing else: no chroma, no HW/SW, because
  // the agent has not told us either.
  //
  // ⚠️ This block used to return `VP9 <chroma>` for ANY active DataChannel
  // worker, and that worker serves VP9, AV1 and H.264 alike. A session whose
  // host could not capture never sends video-info, so an H.264 session
  // reported "VP9 4:4:4" and the operator went looking at the codec picker
  // instead of the capture failure (field, 2026-09-08). A pill must not name
  // a codec nobody told it.
  if (rc.vp9_444Active.value || rc.hevcActive.value) {
    return codecLabelFromDecoderConfig(rc.dcDecoderCodec.value)
  }
  const raw = rc.stats.value.codec
  if (!raw) return ''
  const lower = raw.toLowerCase()
  // Prettify well-known names. H264 → H.264, H265 → H.265; others
  // pass through uppercased.
  const display = lower
    .replace(/^h(\d{3})$/, (_m, n) => `H.${n}`)
    .toUpperCase()
  // Guess HW/SW from the agent's caps if available; default to SW
  // (the safe assumption — reporting HW when uncertain would
  // mislead the operator about latency expectations).
  const enc = agent.value?.capabilities?.hw_encoders ?? []
  const hasHw = enc.some(
    (e) => e.toLowerCase().includes(lower) && e.toLowerCase().includes('-hw'),
  )
  return `${display} ${hasHw ? 'HW' : 'SW'}`
})
const statsBitrateLabel = computed(() => {
  // VP9-444 + rc.80 HEVC read from the worker-emitted stats since
  // there's no RTP track means getStats() has nothing for video.
  const bps = rc.hevcActive.value
    ? rc.hevcStats.value.bitrateBps
    : rc.vp9_444Active.value
      ? rc.vp9_444Stats.value.bitrateBps
      : rc.stats.value.bitrate_bps
  if (bps <= 0) return '— bps'
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`
  return `${Math.round(bps / 1_000)} kbps`
})
/** FR-1 P7 — end-to-end frame age at paint (avg over the last stats
 *  window), measured against the agent's clock via the rc:clock probe.
 *  Covers encode-output → send queue → network → decode → paint; the
 *  agent-side capture+encode (~10–15 ms) sits before the stamp. */
/** FR-93 P2 — which Linux arm captures this session, and whether anyone at
 *  the screen was asked. `''` (no pill) for Windows, macOS and older agents. */
const statsCaptureLabel = computed(() => captureArmLabel(rc.videoInfo.value))
const statsAgeLabel = computed(() => {
  const age = rc.decodeDiag.value?.age
  if (!age || age.n <= 0) return ''
  return `~${Math.round(age.avgMs)} ms`
})
const statsFpsLabel = computed(() => {
  const fps = rc.hevcActive.value
    ? rc.hevcStats.value.fps
    : rc.vp9_444Active.value
      ? rc.vp9_444Stats.value.fps
      : rc.stats.value.fps
  if (fps <= 0) return '— fps'
  return `${Math.round(fps)} fps`
})
/** rc.35 — source resolution pill. Shown on every render path that
 *  exposes intrinsic dims (VP9-444 worker emits them in `stats`;
 *  WebRTC/WebCodecs paths set `mediaIntrinsicW/H` from `first-frame`
 *  or `<video>.onresize`). Useful when verifying that rc:resolution
 *  / auto-downscale / DPI flips landed at the dims you expect. */
const statsResolutionLabel = computed(() => {
  const w = rc.hevcActive.value
    ? rc.hevcStats.value.width
    : rc.vp9_444Active.value
      ? rc.vp9_444Stats.value.width
      : rc.mediaIntrinsicW.value
  const h = rc.hevcActive.value
    ? rc.hevcStats.value.height
    : rc.vp9_444Active.value
      ? rc.vp9_444Stats.value.height
      : rc.mediaIntrinsicH.value
  if (!w || !h) return ''
  const base = `${w}×${h}`
  // rc.199 — the "why is Original blurry?" answer. The agent reports its
  // native panel dims in rc:video-info; when the stream is encoded below
  // them the pill names the cap in force. FR-70 P1: the NAME comes from the
  // agent's own rung reason (`cap_reason`), because the old transport-only
  // guess ("relay-limited — switch Priority to Sharper") was wrong exactly
  // where it mattered: the slow-link profile is resolved once at pump start
  // from the pair's REMEMBERED rate and no dial lifts it (operator's report,
  // 2026-09-04: "blurred at 1200×800 even though original resolution was
  // selected"). Pre-P1 agents still get the rc.199 relay-only guess.
  // User-chosen fit/custom downscales aren't flagged (the agent reports a
  // cap only while its effective target differs from the user's).
  return base + resolutionCapAnnotation(rc.videoInfo.value, w, h)
})
/** FR-70 P1 — the decoded frame size, for the Resolution setting's
 *  override hint (same source as the pill above). */
const decodedDims = computed(() => {
  const w = rc.hevcActive.value
    ? rc.hevcStats.value.width
    : rc.vp9_444Active.value
      ? rc.vp9_444Stats.value.width
      : rc.mediaIntrinsicW.value
  const h = rc.hevcActive.value
    ? rc.hevcStats.value.height
    : rc.vp9_444Active.value
      ? rc.vp9_444Stats.value.height
      : rc.mediaIntrinsicH.value
  return { w, h }
})
/** FR-74 P4 — screen pixels per remote pixel, from the decoded frame, the
 *  stage's CSS box, the scale mode and devicePixelRatio. `renderInfo` is
 *  read so the 1 s worker tick re-evaluates it (devicePixelRatio itself is
 *  not reactive; a zoom change also resizes the stage, which re-measures). */
const statsScale = computed(() => {
  const { w, h } = decodedDims.value
  const r = rc.renderInfo.value
  return displayScale({
    frameW: w,
    frameH: h,
    stageW: stageCss.value.w,
    stageH: stageCss.value.h,
    dpr: window.devicePixelRatio || 1,
    mode: rc.scaleMode.value,
    customPct: rc.scaleCustomPercent.value,
    sharpened: !!(r && r.mode !== '2d'),
  })
})
const statsScaleLabel = computed(() => statsScale.value.label)
const statsScaleHint = computed(() => statsScale.value.hint)
/** The Display tab's hint under "Fit in my window": the live scale and the
 *  way to 1:1 while connected; what the modes mean before that. */
const displayScaleSettingHint = computed<string>(() => {
  if (rc.phase.value === 'connected' && statsScale.value.scale !== null) {
    return `${statsScaleLabel.value} — ${statsScaleHint.value}`
  }
  return 'Adaptive fits the frame to this window; Original is 1:1 in CSS pixels (not on a scaled display); Custom sets the zoom'
})

// Remote cursor overlay (1E.3). Requires both a position and a
// matching shape bitmap; hides during paint if either is missing.
// When the agent tags the active cursor as a standard system cursor,
// render the viewer's real OS cursor via CSS (zero-latency, native)
// on `.video-frame` instead of the streamed bitmap. Null → app-custom
// cursor (or hidden) → fall back to the canvas overlay / badge.
const remoteCursorCss = computed(() => remoteCursorCssFor(rc.cursor.value))

const remoteCursorVisible = computed(() => {
  const pos = rc.cursor.value.pos
  if (!pos) return false
  // A known system cursor renders natively via remoteCursorCss, so
  // suppress the canvas bitmap overlay in that case.
  if (remoteCursorCss.value) return false
  return rc.cursor.value.shapes.has(pos.id)
})

const remoteCursorSize = computed(() => {
  const pos = rc.cursor.value.pos
  if (!pos) return { w: 0, h: 0 }
  const shape = rc.cursor.value.shapes.get(pos.id)
  if (!shape) return { w: 0, h: 0 }
  return { w: shape.bitmap.width, h: shape.bitmap.height }
})

// Translate agent-source pixels → viewer-local pixels using the
// same letterbox correction the pointer input uses, so the cursor
// lands at the exact spot on the video. `agent.value` comes from
// load step below and carries the agent's native resolution via
// its capability payload (the displays list); we fall back to the
// video element's intrinsic size otherwise.
const remoteCursorX = computed(() => {
  const pos = rc.cursor.value.pos
  if (!pos) return 0
  const shape = rc.cursor.value.shapes.get(pos.id)
  if (!shape) return 0
  const scale = cursorMapping()
  return scale.offsetX + pos.x * scale.sx - shape.hotspotX
})
const remoteCursorY = computed(() => {
  const pos = rc.cursor.value.pos
  if (!pos) return 0
  const shape = rc.cursor.value.shapes.get(pos.id)
  if (!shape) return 0
  const scale = cursorMapping()
  return scale.offsetY + pos.y * scale.sy - shape.hotspotY
})

/** Map an agent-source pixel coordinate to the logical coordinate
 *  space of `.video-frame` (which the cursor canvas + synthetic
 *  badge are positioned inside). Scale-mode aware:
 *
 *  - `adaptive`: `<video>` fills the frame with `object-fit: contain`.
 *    Use the original letterbox math to find the scale factor + any
 *    letterbox padding.
 *  - `original`: video at intrinsic 1:1, anchored to the frame's
 *    top-left (flex: flex-start). Scale = 1, no offsets. If the frame
 *    is scrolled the transform stays in logical space → visually
 *    tracks the content.
 *  - `custom`: scale = `scalePercent / 100`, no offsets (same flex
 *    anchor). */
function cursorMapping(): { sx: number; sy: number; offsetX: number; offsetY: number } {
  const stage = stageEl.value
  const video = videoEl.value
  // Source dimensions: in VP9-444 / WebCodecs render modes the
  // `<video>` is hidden + unfed (videoWidth=0), so the agent's encode
  // resolution we cached from the worker's `first-frame` message is
  // the only ground truth for source pixel size.
  const useIntrinsic = rc.vp9_444Active.value || rc.webcodecsActive.value || rc.hevcActive.value
  const srcW = useIntrinsic
    ? rc.mediaIntrinsicW.value
    : (video?.videoWidth ?? 0)
  const srcH = useIntrinsic
    ? rc.mediaIntrinsicH.value
    : (video?.videoHeight ?? 0)
  if (!stage || !srcW || !srcH) {
    return { sx: 1, sy: 1, offsetX: 0, offsetY: 0 }
  }
  if (rc.scaleMode.value === 'original') {
    return { sx: 1, sy: 1, offsetX: 0, offsetY: 0 }
  }
  if (rc.scaleMode.value === 'custom') {
    const pct = rc.scaleCustomPercent.value / 100
    return { sx: pct, sy: pct, offsetX: 0, offsetY: 0 }
  }
  // Adaptive: the video fills the frame with object-fit: contain,
  // producing letterbox bars on the axis where aspect ratios disagree.
  const fw = stage.clientWidth
  const fh = stage.clientHeight
  const vAR = srcW / srcH
  const fAR = fw / fh
  let visibleW: number
  let visibleH: number
  let offsetX: number
  let offsetY: number
  if (vAR > fAR) {
    visibleW = fw
    visibleH = fw / vAR
    offsetX = 0
    offsetY = (fh - visibleH) / 2
  } else {
    visibleW = fh * vAR
    visibleH = fh
    offsetX = (fw - visibleW) / 2
    offsetY = 0
  }
  return {
    sx: visibleW / srcW,
    sy: visibleH / srcH,
    offsetX,
    offsetY,
  }
}

// ── P6 — multi-user rail + ghost cursors ─────────────────────────
const multiUserState = computed(() => rc.controlState.value)
/** Whether THIS session holds the exclusive-mode floor. */
const iHoldTheFloor = computed(() => {
  const st = rc.controlState.value
  if (!st || st.mode !== 'exclusive') return true
  return st.holder != null && st.holder === rc.sessionId.value
})
/** FR-27 — the session waiting for the floor, if any. Null on a pre-FR-27
 *  agent, which is indistinguishable from "nothing pending" and renders the
 *  same: the whole block self-hides. */
const floorRequester = computed(() => rc.controlState.value?.pendingRequest ?? null)
/** …and whether that waiting session is US, so the request button can become
 *  a waiting state instead of looking like it did nothing. */
const iAmWaitingForTheFloor = computed(
  () => !!floorRequester.value && floorRequester.value.session === rc.sessionId.value,
)
/** 1 s ticker so still ghosts fade out (5 s) without a paint loop. */
const ghostNow = ref(Date.now())
let ghostTicker: ReturnType<typeof setInterval> | null = null
/** Other sessions' pointers mapped through the same letterbox math as
 *  the OS cursor. Ghost coords are NORMALIZED 0..1 of the source frame
 *  (`cursor:peer`), so source pixels = (x·srcW, y·srcH). */
const ghostCursors = computed(() => {
  const now = ghostNow.value
  const srcW = rc.mediaIntrinsicW.value
  const srcH = rc.mediaIntrinsicH.value
  if (!srcW || !srcH) return []
  const m = cursorMapping()
  return Object.entries(rc.peerCursors.value)
    .filter(([, g]) => now - g.ts < 5000)
    .map(([sid, g]) => ({
      sid,
      name: g.name || 'Viewer',
      left: m.offsetX + g.x * srcW * m.sx,
      top: m.offsetY + g.y * srcH * m.sy,
    }))
})

// Paint the current cursor shape onto the canvas every time the
// shape or pos changes. drawImage is cheap (O(cursor pixels), ≤32×32
// for classic cursors) so we don't need an explicit RAF loop.
watch(
  () => {
    const p = rc.cursor.value.pos
    return [p?.id ?? null, cursorCanvas.value] as const
  },
  ([id, canvas]) => {
    if (!canvas || id == null) return
    const shape = rc.cursor.value.shapes.get(id)
    if (!shape) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    ctx.clearRect(0, 0, canvas.width, canvas.height)
    ctx.drawImage(shape.bitmap, 0, 0)
  },
  { immediate: false },
)

let detachInput: (() => void) | null = null

// Synthetic cursor overlay. The native pointer is hidden over the video
// (cursor: none in CSS below) so this badge is the only pointer indicator.
// Initials come from the logged-in controller so it stays meaningful if
// multi-watcher sessions land later (today it's 1:1, but the label is
// already user-scoped).
const cursorX = ref(0)
const cursorY = ref(0)
const cursorVisible = ref(false)
const controllerInitials = computed(() => {
  const u = authStore.user
  const src = u?.display_name || u?.username || ''
  const parts = src.trim().split(/\s+/).filter(Boolean)
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase()
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase()
  return ''
})
function onStagePointerMove(ev: PointerEvent) {
  const host = stageEl.value
  if (!host) return
  const rect = host.getBoundingClientRect()
  // `transform: translate()` on the badge/canvas is in the logical
  // coordinate space of `.video-frame` — the space that includes
  // scroll offset. `ev.clientX - rect.left` gives viewport-relative
  // offset from the frame's *visible* left edge; add scrollLeft to
  // reach logical space so the overlay tracks the pointer after
  // scrolling in Original / Custom modes.
  cursorX.value = ev.clientX - rect.left + host.scrollLeft
  cursorY.value = ev.clientY - rect.top + host.scrollTop
}

const agentNotFound = ref(false)
watch(agentId, () => {
  agentNotFound.value = false
})
const canConnect = computed(
  () => !!agent.value || (!isExternal && !!agentId.value && !agentNotFound.value),
)
const statusColor = computed(() => (agent.value?.is_online ? 'success' : 'grey'))
const phaseColor = computed(() => {
  switch (rc.phase.value) {
    case 'connected': return rc.degraded.value ? 'warning' : 'success'
    case 'reconnecting': return 'warning'
    case 'error': return 'error'
    case 'closed': return 'grey'
    default: return 'info'
  }
})
// FR-93 P2d-2 — when the host's dialog gives up, as a time of day on this
// browser's clock (the deadline was set here, at receipt). A time rather than a
// countdown, so the overlay needs no timer of its own.
// FR-93 P5j — the sleep notice the composable keeps through a redial, while one
// is in flight, over the attempt's own phase. A request to a sleeping computer
// sits in awaiting_consent until it wakes, the server waiting for an answer the
// computer cannot give (the lab, 0.4.142: 38 s of "Waiting for the agent to
// allow the connection…"). An error, or a session that connects, ends it.
const asleepWhileRedialling = computed(() => {
  const w = rc.mediaWaiting.value
  if (w?.for !== 'host_sleep') return null
  return ['reconnecting', 'requesting', 'awaiting_consent', 'negotiating'].includes(rc.phase.value) ? w : null
})
const mediaWaitingEnds = computed(() => {
  const w = rc.mediaWaiting.value
  return w ? new Date(w.deadlineMs).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''
})
// FR-101 P4b-2b — the device's idle countdown. Unlike the overlay above, a
// warning of a minute at most reads as seconds, so it gets a ticker, running
// only while a warning stands.
const idleNowMs = ref(Date.now())
let idleTicker: ReturnType<typeof setInterval> | null = null
watch(
  () => rc.idleEndsAt.value,
  (at) => {
    if (at !== null && idleTicker === null) {
      idleNowMs.value = Date.now()
      idleTicker = setInterval(() => {
        idleNowMs.value = Date.now()
      }, 500)
    } else if (at === null && idleTicker !== null) {
      clearInterval(idleTicker)
      idleTicker = null
    }
  },
  { immediate: true },
)
onBeforeUnmount(() => {
  if (idleTicker !== null) clearInterval(idleTicker)
})
const idleLeft = computed(() => idleSecondsLeft(rc.idleEndsAt.value, idleNowMs.value))
// S3 — human wording for the sub-connected health states.
const degradedLabel = computed(() => {
  // FR-80 — when the host has told us it cannot capture, say THAT instead of
  // "video stalled". The stall is the symptom; the agent sent the cause, and
  // an operator reading "video stalled" has no idea the fix is a permission
  // on the far machine.
  if (rc.mediaUnavailable.value) return 'connected · no screen capture'
  // FR-93 P2d-2 — not "video stalled": the host said why there is no video yet
  // (P5b: in its own words, a dialog or a locked screen).
  if (rc.mediaWaiting.value) return `connected · ${mediaWaitingCopy(rc.mediaWaiting.value.for).status}`
  switch (rc.degraded.value) {
    case 'transport_unstable': return 'connected · unstable link'
    case 'media_stalled': return 'connected · video stalled'
    case 'signalling_offline': return 'connected · server link down'
    default: return 'connected'
  }
})
const phaseLabel = computed(() => {
  switch (rc.phase.value) {
    case 'requesting': return 'Requesting session…'
    case 'awaiting_consent': return rc.hostLocked.value
      ? 'That device is locked. Someone needs to unlock it on the machine, then approve the request there — you have 5 minutes.'
      : 'Waiting for the agent to allow the connection…'
    case 'negotiating': return 'Negotiating the peer connection…'
    default: return ''
  }
})

// Transfers panel helpers. Surfaces the `rc.transfers` ref that's
// been exposed since file-DC v2 Phase 1 but never rendered in the UI.
const transfersInFlightCount = computed(
  () =>
    rc.transfers.value.filter(
      (t) => t.status === 'running' || t.status === 'queued' || t.status === 'reconnecting'
    ).length
)
// Show in-flight first, then queued, then terminal (ordered by recency
// — terminals auto-prune 10 s after they enter the list, so the tail
// is short by construction). rc.19 'reconnecting' ranks between
// running and queued so the operator's eye finds the in-flight
// retry quickly.
const transfersOrdered = computed(() => {
  const order = (s: string) =>
    s === 'running'
      ? 0
      : s === 'reconnecting'
        ? 1
        : s === 'queued'
          ? 2
          : s === 'cancelled'
            ? 4
            : s === 'error'
              ? 5
              : 3
  return [...rc.transfers.value].sort((a, b) => order(a.status) - order(b.status))
})
function transferStatusColor(t: { status: string }): string {
  if (t.status === 'running') return 'primary'
  if (t.status === 'reconnecting') return 'warning'
  if (t.status === 'queued') return 'grey'
  if (t.status === 'complete') return 'success'
  if (t.status === 'error') return 'error'
  if (t.status === 'cancelled') return 'grey'
  return 'grey'
}
function transferStatusLabel(t: {
  status: string
  bytes: number
  total: number | null
  error?: string
}): string {
  if (t.status === 'queued') return 'Queued'
  if (t.status === 'reconnecting') {
    // rc.19: error field carries "attempt N/6" text from the
    // resume wrapper. Falls back to a generic label if missing.
    const detail = t.error ?? 'waiting for reconnect'
    return `Reconnecting — ${detail}`
  }
  if (t.status === 'running') {
    if (t.total === null) return `${formatFileSize(t.bytes)} (streaming)`
    const pct = t.total > 0 ? Math.round((t.bytes / t.total) * 100) : 0
    return `${pct}% — ${formatFileSize(t.bytes)} / ${formatFileSize(t.total)}`
  }
  if (t.status === 'complete') return `${formatFileSize(t.bytes)} — done`
  if (t.status === 'cancelled') return 'Cancelled'
  if (t.status === 'error') return t.error ? `Error: ${t.error}` : 'Error'
  return ''
}
function transferProgressPct(t: { bytes: number; total: number | null }): number {
  if (t.total === null || t.total <= 0) return 0
  return Math.min(100, Math.round((t.bytes / t.total) * 100))
}

// File-DC v2 capability gates (0.3.0+). The agent advertises a
// per-feature `files: ["upload","download","download-folder","browse"]`
// list in `rc:agent.hello`. Old agents (<0.3.0) leave the field empty;
// browsers fall back to the coarse `supports_file_transfer` bool which
// only marks upload availability. We grey out toolbar buttons when
// the capability isn't advertised so operators get instant "feature
// unavailable" feedback instead of waiting for a 5 s timeout on an
// unanswered request.
const agentFilesCaps = computed<string[]>(() => agent.value?.capabilities?.files ?? [])
const agentSupportsBrowse = computed(() => agentFilesCaps.value.includes('browse'))
// Remote app selection & launch (FR-56). `list` = the agent could manage a
// desktop when it announced itself; `status` (AC10) = the agent has a Remote
// Apps backend and answers rc:apps.list honestly — with the list, or with
// `unavailable: {code, reason}`. The entry shows for either and the DIALOG
// carries the truth, because the hello is a boot-time snapshot: `list`
// missing from it can mean nobody had logged in yet when the daemon started,
// and only the live reply can say.
const agentAppsCaps = computed<string[]>(() => agent.value?.capabilities?.apps ?? [])
const agentSupportsApps = computed(
  () => agentAppsCaps.value.includes('list') || agentAppsCaps.value.includes('status'),
)
const agentSupportsDownload = computed(() =>
  agentFilesCaps.value.includes('download') || agentFilesCaps.value.includes('download-folder')
)
const agentSupportsFolderDownload = computed(() =>
  agentFilesCaps.value.includes('download-folder')
)
// Old-agent flag: file-DC v1 (only upload) — coarse caps absent. Used
// to render a "agent doesn't support download — upgrade to 0.3.0+"
// hint when the operator opens the drawer.
const isLegacyFileDc = computed(() => agentFilesCaps.value.length === 0)

// #1631 — the device this view is for, wherever it lives: the cached page
// (the nav's live view over the store) first, else the single-device GET,
// which is the only way to reach a device beyond the 100-row page or a deep
// link opened before any listing ran. Throws on any error; the callers
// decide what to do with the snapshot they already hold.
async function resolveAgent(): Promise<Agent> {
  const cached = agentStore.agents.find((a) => a.id === agentId.value)
  if (cached) return cached
  return agentStore.fetchAgent(tenantId.value, agentId.value)
}

/** A server answer that says the device is not there for this caller
 *  (deleted, or another org's id): the honest state is "no device", not
 *  yesterday's snapshot. Anything else is transient and keeps the snapshot. */
function saysNoSuchDevice(e: unknown): boolean {
  const status = (e as { status?: unknown })?.status
  return status === 404 || status === 403
}

async function loadAgent() {
  // FR-52 P4e — an outsider has no tenant to list devices from.
  if (isExternal) return
  if (!agentStore.agents.length) {
    await agentStore.fetchAgents(tenantId.value)
  }
  try {
    agent.value = await resolveAgent()
    agentNotFound.value = false
  } catch (e) {
    if (saysNoSuchDevice(e)) {
      agent.value = null
      agentNotFound.value = true
    }
    /* else transient — keep the previous snapshot (null on a first load) */
  }
}

// S3 — keep the toolbar online-dot honest; P4 relaxed the cadence from
// 30 s to 5 min because `device:presence` WS pushes now patch the agents
// store in realtime — the poll is only the belt for a missed push (plus
// the immediate refetch when the session enters 'reconnecting'/'error':
// the operator's next question is "is the device even online?").
const AGENT_STATUS_POLL_MS = 300_000
let agentStatusTimer: ReturnType<typeof setInterval> | null = null
async function refreshAgentStatus() {
  if (isExternal) return
  try {
    // `fetchAgents` swallows its own errors into an EMPTY list, so the old
    // `find(...) || null` here nulled the device on every transient blip and
    // on every device beyond the cached page — the toolbar name vanished and
    // Connect went dead mid-session. Resolve through the single-device GET
    // instead and only replace the snapshot with an answer.
    await agentStore.fetchAgents(tenantId.value)
    agent.value = await resolveAgent()
    agentNotFound.value = false
  } catch (e) {
    if (saysNoSuchDevice(e)) {
      agent.value = null
      agentNotFound.value = true
    }
    /* else transient — keep the previous snapshot */
  }
}
watch(
  () => rc.phase.value,
  (p) => {
    if (p === 'reconnecting' || p === 'error') void refreshAgentStatus()
  },
)

// FR-102 P9b — the post-session rating. The tracker follows the attempt
// (request → terminal phase); every gate in `shouldOfferRating` fails toward
// not prompting; the day is recorded when the prompt is SHOWN, so a dismissal
// counts; a new Connect withdraws the prompt without posting anything. The
// server is the authority on who may rate what (a party, once per session,
// not before 30 s) — this only decides whether to ask.
const capabilitiesStore = useCapabilitiesStore()
const ratingTracker = createRatingTracker()
const ratingPending = ref<{ tenantId: string; sessionId: string } | null>(null)
const ratingStatus = ref<'ask' | 'sent'>('ask')
watch(
  () => rc.sessionId.value,
  (id) => ratingTracker.onSession(id),
)
watch(
  () => rc.phase.value,
  (next, prev) => {
    if (next === 'requesting') ratingPending.value = null
    const ended = ratingTracker.onPhase(prev, next)
    if (!ended || !ended.sessionId) return
    const storage = storageOrNull()
    const nowMs = Date.now()
    const offer = shouldOfferRating({
      enabled: capabilitiesStore.feature('session_feedback'),
      sessionId: ended.sessionId,
      requestedAtMs: ended.requestedAtMs,
      endedAtMs: nowMs,
      lastPromptDay: readLastPromptDay(storage),
      storageUsable: storage !== null,
    })
    if (!offer) return
    // The day could not be recorded → "once a day" could not be kept → no prompt.
    if (!markPrompted(storage, utcDay(nowMs))) return
    ratingStatus.value = 'ask'
    ratingPending.value = { tenantId: tenantId.value, sessionId: ended.sessionId }
  },
)
async function submitRating(rating: Rating, reasons: RatingReason[]) {
  const p = ratingPending.value
  if (!p) return
  ratingStatus.value = 'sent'
  try {
    await api.post(ratingPath(p.tenantId, p.sessionId), { rating, reasons })
  } catch (e) {
    // A refusal (already rated, the switch off) or a blip: the thanks line
    // stays, nothing else happens. The server has what it accepts.
    console.warn('[rc] session rating not stored', e)
  }
}
function dismissRating() {
  ratingPending.value = null
}

function startSession() {
  // FR-52 P4e — an external session starts from the login `/connect` handed
  // over, once. With none (a reload, or Connect after the session ended) the
  // only way in is the password again.
  if (isExternal) {
    const auth = takeExternalSession()
    if (!auth) {
      void router.replace({ name: 'connect', query: externalCode ? { code: externalCode } : {} })
      return
    }
    void rc.connectExternal(auth)
    return
  }
  const targetAgentId = agent.value?.id || (!isExternal ? agentId.value : '')
  if (!targetAgentId) return
  // Surface Chrome's clipboard-read permission prompt UNDER the
  // Connect click gesture (auto-sync's later background reads can't
  // prompt as nicely). Fire-and-forget throwaway read — the result
  // is discarded; a denial just leaves auto-sync to its blocked-latch
  // flow.
  if (rc.clipboardAutoSyncEnabled.value) {
    void globalThis.navigator.clipboard?.readText?.().catch(() => {})
  }
  // PR-1: thread the agent's org so the pre-flight keys the signalling
  // socket to the right pod even when this view is hosted cross-org.
  rc.connect(targetAgentId, undefined, false, tenantId.value)
}

// FR-100 P2a — the toolbar's word on the device's identity key, and the one
// way to accept a key that changed: the person's click, then a fresh attempt
// that must prove it.
const peerAuthBadgeShown = computed(() => peerAuthBadge(rc.peerAuth.value))
function trustNewKeyAndConnect() {
  if (rc.trustPeerAuthKey()) startSession()
}

// Phase 5 — admin break-glass. The reason is stashed on the composable and rides
// the next `rc:session.request`; the server honours it only for a validated
// administrator (a non-admin's request just falls back to normal consent).
const forceDialogOpen = ref(false)
const forceReason = ref('')
function confirmForce() {
  if (!forceReason.value.trim()) return
  rc.overrideReason.value = forceReason.value.trim()
  forceDialogOpen.value = false
  forceReason.value = ''
  startSession()
}

// When the remote stream becomes available, attach it to the video element.
// Race to watch out for: ontrack can fire during `phase === 'negotiating'`
// (before the <video> element is even mounted, since it lives inside a
// v-else-if="phase === 'connected'"). A single watcher on the stream would
// see videoEl.value = null at that moment and silently skip the assignment;
// when the element mounts later no watcher re-fires. Watch both refs and
// attach whenever both are present.
let rvfcHandle: number | null = null
// Keep our intrinsic-dimension refs in sync with the actual video
// element. `resize` fires on every resolution change from the agent
// (docking, DPI flip, rc:resolution control message in Phase 2);
// `loadedmetadata` covers the first-frame bootstrap. In WebCodecs
// mode the <video> element never receives decoded frames (the
// receiver transform swallows them), so `videoWidth` stays 0 — we
// skip writing zeros here to avoid clobbering the worker's first-
// frame dims. The worker's `first-frame` message is the authoritative
// source in that mode.
function refreshVideoDims(el: HTMLVideoElement) {
  if (isWebCodecsRender.value) return
  videoIntrinsicW.value = el.videoWidth || 0
  videoIntrinsicH.value = el.videoHeight || 0
}
watch(
  () => [rc.remoteStream.value, videoEl.value] as const,
  ([stream, el]) => {
    if (stream && el && el.srcObject !== stream) {
      el.srcObject = stream
      // Track intrinsic video size so `custom` scale mode can compute
      // pixel dimensions + the coordinate mapper can fall back cleanly.
      el.addEventListener('loadedmetadata', () => refreshVideoDims(el))
      el.addEventListener('resize', () => refreshVideoDims(el))
      refreshVideoDims(el)
      // requestVideoFrameCallback keeps the tab "hot" against
      // Chrome's background throttling AND gives us a cheap hook to
      // recover from the video element's paused-for-optimization
      // state that sometimes triggers on identical-frame runs (e.g.
      // long idle screens).
      const elWithRvfc = el as HTMLVideoElement & {
        requestVideoFrameCallback?: (cb: (now: number, metadata: unknown) => void) => number
      }
      const rvfc = elWithRvfc.requestVideoFrameCallback
      if (typeof rvfc === 'function') {
        const tick = () => {
          if (!videoEl.value) {
            rvfcHandle = null
            return
          }
          if (videoEl.value.paused) {
            videoEl.value.play().catch(() => { /* autoplay gating — ignore */ })
          }
          rvfcHandle = (videoEl.value as typeof elWithRvfc)
            .requestVideoFrameCallback!(tick)
        }
        rvfcHandle = rvfc.call(el, tick)
      }
    }
  },
  { immediate: true },
)

// Bind the opt-in host-audio stream to the hidden <audio> sink and try
// to play it. Same both-refs race as the video watcher — the <audio>
// element only exists inside the connected-stage v-else-if, so watch
// both the stream and the element ref. `<audio autoplay>` covers most
// cases, but Chrome/Safari block autoplay-WITH-SOUND without a prior
// user gesture on the page; on a rejected play() we flip
// `audioAutoplayBlocked` so the toolbar shows a one-click Unmute
// button (the click satisfies the gesture requirement → retry). When
// the stream clears (teardown), drop the element's srcObject.
watch(
  () => [rc.remoteAudioStream.value, audioEl.value] as const,
  ([stream, el]) => {
    if (!el) return
    if (!stream) {
      if (el.srcObject) el.srcObject = null
      return
    }
    if (el.srcObject !== stream) {
      el.srcObject = stream
    }
    el.muted = false
    el.play()
      .then(() => { rc.audioAutoplayBlocked.value = false })
      .catch(() => {
        // Autoplay-with-sound blocked — surface the Unmute affordance.
        rc.audioAutoplayBlocked.value = true
      })
  },
  { immediate: true },
)

// Unmute button click. The click itself is the user gesture the
// autoplay policy wants, so retry playback directly on the element,
// then let the composable clear its blocked flag.
function onUnmuteAudio() {
  const el = audioEl.value
  if (el) {
    el.muted = false
    el.play()
      .then(() => rc.resumeAudioPlayback())
      .catch(() => { /* still blocked — leave the button up */ })
  } else {
    rc.resumeAudioPlayback()
  }
}

// Once the connected stage mounts, wire input listeners to it. Detach
// when we leave the "connected" phase so keystrokes don't escape after
// a disconnect.
watch(
  () => [rc.phase.value, stageEl.value] as const,
  ([phase, el]) => {
    if (phase === 'connected' && el && !detachInput) {
      detachInput = rc.attachInput(el as HTMLElement, {
        onPinchZoom,
        onTwoFingerScroll,
        // Phase 5: when the operator hits Ctrl+V over the viewer
        // with files in their OS clipboard, route to the upload
        // pipeline. The composable suppresses the Ctrl+V keystroke
        // so the remote app doesn't see a stray paste.
        onFilesPasted: (files) => {
          if (files.length === 0) return
          showSuccess(
            files.length === 1
              ? `Uploading ${files[0].name}…`
              : `Uploading ${files.length} files…`
          )
          void uploadMany(files)
        },
        // rc.18: anchor focus on the viewer wrapper itself. The
        // composable's onPointerEnter blurs whatever was focused
        // (typically a left-panel nav-drawer item the operator
        // clicked before connecting) and `.focus()`-es this anchor
        // so subsequent Enter/Space keypresses don't fire the
        // nav-drawer item's keyboard activation.
        focusAnchor: el as HTMLElement,
        // rc.18: when Ctrl+C-auto-mirror succeeds, no snackbar
        // (the browser clipboard silently has what the remote
        // copied). When the browser refuses writeText (no user-
        // gesture chain), surface the text + a Copy button so the
        // operator can still get it.
        onClipboardMirrored: (text, ok) => {
          if (!ok && text) {
            showError(
              `Remote clipboard: "${text.slice(0, 60)}${text.length > 60 ? '…' : ''}" — browser blocked auto-paste`
            )
          }
        },
      })
      ;(el as HTMLElement).focus()
      // Start watching the stage for size changes so Fit mode
      // auto-updates the agent's target resolution.
      startFitResizeObserver()
      // If the restored preference was Fit (from localStorage) the
      // stored width/height are from the previous session — re-emit
      // with the current window size so the agent uses today's dims.
      if (rc.resolution.value.mode === 'fit') applyFitResolution()
      // rc.191 — re-assert the display-match preference each session (the
      // agent restores its display mode on every disconnect, so an ON
      // toggle must be re-sent per connect).
      if (displayMatchOn.value && agentSupportsDisplayMatch.value) {
        sendDisplayMatchNow()
      }
    } else if (phase !== 'connected' && detachInput) {
      detachInput()
      detachInput = null
      stopFitResizeObserver()
    }
  },
)

onMounted(() => {
  if (!isExternal && tenantId.value) {
    wsStore.setTenantAffinity(tenantId.value)
    if (wsStore.status === 'disconnected') {
      wsStore.connect()
    }
  }
  void loadAgent()
  void agentStore.fetchKeepBusyDefaultPattern(tenantId.value).then((p) => {
    orgKeepBusyDefault.value = p
  })
  agentStatusTimer = setInterval(() => void refreshAgentStatus(), AGENT_STATUS_POLL_MS)
  // FR-52 P4e — the login on `/connect` WAS the gesture: start at once.
  if (isExternal) startSession()
  // P6 — ghost-cursor staleness ticker (cheap; drives the 5 s fade).
  ghostTicker = setInterval(() => { ghostNow.value = Date.now() }, 1000)
  document.addEventListener('fullscreenchange', onFullscreenChange)
  // Drawer-scope Ctrl+V / Ctrl+C handlers attached at window-level
  // (not on the drawer element) so they fire regardless of which
  // element has focus — rc.14 had them on the drawer's @paste /
  // @keydown which only worked when the operator had clicked into
  // the drawer first.
  window.addEventListener('paste', onWindowPasteForDrawer)
  window.addEventListener('keydown', onWindowKeyDownForDrawer)
})
onBeforeUnmount(() => {
  if (agentStatusTimer !== null) {
    clearInterval(agentStatusTimer)
    agentStatusTimer = null
  }
  if (ghostTicker !== null) {
    clearInterval(ghostTicker)
    ghostTicker = null
  }
  if (detachInput) detachInput()
  stopFitResizeObserver()
  document.removeEventListener('fullscreenchange', onFullscreenChange)
  window.removeEventListener('paste', onWindowPasteForDrawer)
  window.removeEventListener('keydown', onWindowKeyDownForDrawer)
  // Defensive: exitFullscreen fires fullscreenchange → disable, but a
  // teardown that never sees that event must still release the lock.
  rc.disableKeyboardLock()
  if (shortcutOverlayTimer) {
    clearTimeout(shortcutOverlayTimer)
    shortcutOverlayTimer = null
  }
  // Exit fullscreen on unmount so navigating away doesn't leave the
  // browser in a weird fullscreen state.
  if (document.fullscreenElement) void document.exitFullscreen().catch(() => {})
  // Leaving the page is a deliberate end too; an unmount cannot wait for the
  // answer, so the Stop goes out first and the device's grace covers a loss.
  if (rec.state.value === 'recording') rec.stop()
  rc.disconnect()
})
</script>

<style scoped>
.remote-control-wrapper {
  height: 100%;
  display: flex;
  flex-direction: column;
}
/* Row 1 (primary toolbar): keep on a single line at every viewport
   so Back / title / Connect-Disconnect / Fullscreen never push off-
   screen. Vuetify's outer wrapper clips overflow by default; the
   `overflow-x: auto` on `__content` is a defensive fallback for
   borderline viewports where a long agent name + chips push past
   320px. The `flex-shrink: 1` on the title lets it ellipsis instead
   of forcing the end-of-row buttons off-screen. Field bug
   the field-test host mobile 2026-05-01 ('cannot fullscreen, button is gone'
   after Connect mounted +5 buttons in the single-row toolbar). */
.remote-control-wrapper :deep(.rc-toolbar-primary .v-toolbar__content) {
  overflow-x: auto;
}
/* FR-116 — below 960 px (a phone either way up, a portrait tablet) a
   connected session's toolbar holds more than the row. On a 360 px phone: ~600 px of
   tools in ~344 px. The title is `flex: 1 1 0`, so it was the first thing to
   go (0 px: no device name, no status dot), the status chips shrank to empty
   coloured stubs, and Disconnect started off-screen. Now Back, the device's
   name, Disconnect (and Fullscreen) and the session's state come FIRST (flex
   order) and keep their size; every other tool follows and the row scrolls
   as before. Disconnect goes before the chips so a long state never pushes
   it out of view. */
@media (max-width: 959.98px) {
  .remote-control-wrapper :deep(.rc-toolbar-primary .v-toolbar__content > *) {
    order: 10;
  }
  .remote-control-wrapper :deep(.rc-toolbar-primary .rc-tb-back) {
    order: 0;
  }
  .remote-control-wrapper :deep(.rc-toolbar-primary .v-toolbar-title) {
    order: 1;
    flex: 0 1 auto !important;
    min-width: 96px !important;
  }
  .remote-control-wrapper :deep(.rc-toolbar-primary .rc-tb-session) {
    order: 2;
    flex-shrink: 0;
  }
  .remote-control-wrapper :deep(.rc-toolbar-primary .rc-tb-fullscreen) {
    order: 3;
  }
  .remote-control-wrapper :deep(.rc-toolbar-primary .rc-tb-status) {
    order: 4;
    flex-shrink: 0;
  }
  .remote-control-wrapper :deep(.rc-toolbar-primary .v-chip) {
    flex-shrink: 0;
  }
}
.remote-control-wrapper :deep(.rc-toolbar-primary .v-toolbar-title) {
  flex-shrink: 1;
  min-width: 0;
}
/* The card wrapping `.remote-stage` provides Material elevation +
   rounded corners + theme-aware border. `overflow: hidden` clips
   the dark stage at the rounded corners; `min-height: 0` keeps
   the flex `min-height: 0` chain unbroken so `scale-original` mode
   at 4K doesn't push past the viewport. */
.remote-stage-card {
  overflow: hidden;
  min-height: 0;
  background: #0b0b0b;
}
.remote-stage {
  flex: 1;
  display: flex;
  align-items: stretch;
  justify-content: stretch;
  background: #0b0b0b;
  position: relative;
}
.rc-stage-alerts {
  position: absolute;
  inset: 0 0 auto 0;
  z-index: 31; /* above the stage's pills (30) */
  display: flex;
  flex-direction: column;
  pointer-events: none;
}
.rc-stage-alerts > * {
  pointer-events: auto;
}
.empty-state {
  margin: auto;
  text-align: center;
  padding: 32px;
  color: rgba(255, 255, 255, 0.7);
}
/* The stage is dark in every theme, but Vuetify's `text-medium-emphasis` is
   theme-relative (on-background at medium opacity, `!important`): in the light
   theme it painted the stage's secondary lines dark grey on #0b0b0b, unreadable
   (FR-27 P10's notice, measured 2026-10-09; the offline, reconnecting and
   no-media lines too). Inside the stage they stay light, like the rest. */
.remote-stage .text-medium-emphasis {
  color: rgba(255, 255, 255, 0.6) !important;
}
.video-frame {
  position: relative;
  width: 100%;
  height: 100%;
  /* `min-height: 0` is required for the flex parent (`.remote-stage`
     with `align-items: stretch`) to allow this child to actually
     shrink to the available space. Without it, a large intrinsic
     child (e.g. a 4K <video> in Original mode) could balloon the
     frame past the viewport — showing a cropped view instead of
     scrollbars. `min-width: 0` is the horizontal counterpart. */
  min-width: 0;
  min-height: 0;
  /* Hide the native OS pointer so the synthetic cursor below is the only
     thing the controller sees — matches collaborative-tool semantics. */
  cursor: none;
}
.video-frame.drag-over::after {
  content: 'Drop file to upload';
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.2rem;
  font-weight: 600;
  color: #fff;
  background: rgba(33, 150, 243, 0.25);
  border: 3px dashed rgba(33, 150, 243, 0.85);
  pointer-events: none;
  z-index: 10;
}
/* Files browser drawer: selected rows highlight so multi-select
   (Ctrl+click / Shift+click) feedback is visible at a glance. */
.files-drawer .files-entry-selected {
  background: rgba(33, 150, 243, 0.18);
}
/* Drawer drag-over (file-DC v2.2 path-targeted upload): tint the
   whole drawer when files are being dragged over it so the operator
   sees the drawer's current dir is the upload target — distinct
   from a viewer-level drop which goes to Downloads/. */
.files-drawer.drawer-drag-over::before {
  content: 'Drop to upload here';
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1rem;
  font-weight: 600;
  color: #fff;
  background: rgba(76, 175, 80, 0.25);
  border: 3px dashed rgba(76, 175, 80, 0.85);
  pointer-events: none;
  z-index: 100;
}
/* Transfers panel: long file names (folder uploads with deep paths)
   would push the row width and break the popover layout — clamp with
   ellipsis instead. The full name is in the row's `title` attribute
   for hover. */
.transfer-row .transfer-name {
  text-overflow: ellipsis;
  overflow: hidden;
  white-space: nowrap;
  max-width: 320px;
}
.transfer-row.transfer-cancelled .transfer-name,
.transfer-row.transfer-error .transfer-name {
  opacity: 0.7;
}
/* Scrollable frame for the scale modes where the video can overflow
   the viewport (original = 1:1 always if source > viewer, custom ≥
   100%). `block` display is intentional — a flex container would
   impose item-sizing rules and some browsers shrink the flex item
   even with `flex: none` when the container's overflow engages.
   Block + explicit child pixel dims (via :style) is the simplest
   path that reliably shows scrollbars. */
.video-frame.scale-original,
.video-frame.scale-custom {
  overflow: auto;
  display: block;
}
.remote-video {
  background: #000;
  display: block;
}
/* rc.35 — better-than-bilinear resampling hint for the canvas render
 * paths when the CSS-displayed size doesn't match the drawing-buffer
 * size (typical: 4K source on a sub-4K viewport in scale-adaptive).
 * Chrome 79+ picks a lanczos-like algorithm under `high-quality`;
 * browsers without the hint fall back silently to `auto` (bilinear).
 * For pixel-perfect 1:1 viewing, switch the scale mode to Original. */
.remote-video.webcodecs-canvas,
.remote-video.vp9-444-canvas,
.remote-video.hevc-canvas {
  image-rendering: high-quality;
}
.remote-video.scale-adaptive {
  width: 100%;
  height: 100%;
  /* rc.101 — belt-and-suspenders cap. A transferred-OffscreenCanvas
     placeholder can lay out at its backing-store intrinsic size
     (e.g. 2560×1600) instead of honouring `width/height: 100%` on some
     Chrome builds → the canvas overflowed its frame and was clipped on
     BOTH sides on the 16:10 NEO16 host (only fit once the remote res was
     dropped to 1280×720). `max-*: 100%` is relative to the containing
     block, so it constrains the element regardless; `object-fit: contain`
     then letterboxes the bitmap into the capped box. */
  max-width: 100%;
  max-height: 100%;
  object-fit: contain;
}
.remote-video.scale-original,
.remote-video.scale-custom {
  /* Explicit pixel dims come from the :style binding. object-fit:
     fill stretches to exactly the CSS-declared dimensions with no
     letterbox, which is what we want for 1:1 Original and the
     user-driven Custom scale. */
  object-fit: fill;
}
.remote-cursor-canvas {
  position: absolute;
  top: 0;
  left: 0;
  pointer-events: none;
  z-index: 2;
  image-rendering: pixelated;
  will-change: transform;
}
.cursor-badge {
  position: absolute;
  top: 0;
  left: 0;
  pointer-events: none;
  z-index: 2;
  /* translate is applied inline from (cursorX, cursorY). Offset the
     arrow tip to the exact pointer hotspot (top-left of the arrow). */
  will-change: transform;
}
.cursor-arrow {
  width: 0;
  height: 0;
  border-left: 14px solid #4fc3f7;
  border-top: 14px solid transparent;
  border-bottom: 14px solid transparent;
  filter: drop-shadow(0 1px 2px rgba(0, 0, 0, 0.45));
  transform: rotate(-20deg);
  transform-origin: 0 0;
}
/* P6 — ghost cursors: other viewers' pointers. Same anatomy as the
   synthetic cursor badge, tinted amber and input-transparent. */
.ghost-cursor {
  position: absolute;
  top: 0;
  left: 0;
  pointer-events: none;
  z-index: 5;
  opacity: 0.85;
  transition: transform 80ms linear;
}
.ghost-chip {
  background: #ffb74d;
  color: #3e2723;
}

.cursor-chip {
  position: absolute;
  top: 14px;
  left: 10px;
  background: #4fc3f7;
  color: #0b2530;
  font: 600 11px/1 system-ui, sans-serif;
  padding: 2px 6px;
  border-radius: 8px 8px 8px 2px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.4);
  letter-spacing: 0.5px;
  white-space: nowrap;
}
.no-media-overlay {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background: rgba(0, 0, 0, 0.6);
  color: #fff;
  text-align: center;
  padding: 24px;
}
/* FR-80 — the capture-failure hint is a sentence, not a label: hold it to a
   readable measure instead of letting it span a 4K canvas. */
.no-media-hint {
  max-width: 52ch;
}
/* Keyboard-lock affordances (locked fullscreen). Inside .video-frame
   so they survive fullscreen; never intercept pointer events. */
.kb-lock-toast {
  position: absolute;
  top: 16px;
  left: 50%;
  transform: translateX(-50%);
  display: flex;
  align-items: center;
  max-width: min(90%, 640px);
  background: rgba(0, 0, 0, 0.75);
  color: rgba(255, 255, 255, 0.95);
  font-size: 13px;
  line-height: 1.35;
  padding: 8px 14px;
  border-radius: 999px;
  pointer-events: none;
  z-index: 30;
}
.kb-lock-pill {
  position: absolute;
  top: 8px;
  right: 8px;
  display: flex;
  align-items: center;
  background: rgba(0, 0, 0, 0.45);
  color: rgba(255, 255, 255, 0.85);
  font: 500 11px/1 ui-monospace, "SF Mono", Menlo, monospace;
  padding: 4px 8px;
  border-radius: 999px;
  opacity: 0.45;
  pointer-events: none;
  z-index: 30;
}
/* FR-109 — bottom centre, clear of the keyboard-lock toast (top centre) and
   pill (top right); never takes a click meant for the remote. */
.relative-mouse-hint {
  position: absolute;
  bottom: 12px;
  left: 50%;
  transform: translateX(-50%);
  display: flex;
  align-items: center;
  background: rgba(0, 0, 0, 0.6);
  color: rgba(255, 255, 255, 0.9);
  font-size: 12px;
  line-height: 1.3;
  padding: 4px 10px;
  border-radius: 999px;
  pointer-events: none;
  z-index: 30;
}
/* Live stats pills — inline in the toolbar (2026-07-21). Previously
   absolute-positioned over the video canvas, where they covered a
   maximized remote window's caption buttons. */
.stats-readout {
  display: flex;
  gap: 6px;
  align-items: center;
  min-width: 0;
}
/* The resolution pill can grow long ("… · relay-limited (native 2560×1600)");
   let it ellipsize rather than push the toolbar's Connect/fullscreen off. */
.stats-readout .stats-pill:last-child {
  max-width: 34ch;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.stats-pill {
  background: rgba(0, 0, 0, 0.55);
  color: rgba(255, 255, 255, 0.9);
  font: 500 11px/1 ui-monospace, "SF Mono", Menlo, monospace;
  padding: 4px 8px;
  border-radius: 999px;
  letter-spacing: 0.3px;
  backdrop-filter: blur(4px);
}

/* rc.23 agent log viewer — monospace, dark background so the
 * tracing levels (INFO/WARN/ERROR) read clearly. Horizontal scroll
 * for long lines (no wrap so structured log fields stay aligned).
 * Min height keeps the pre visible even when the fetch returns
 * fewer lines than the dialog can hold. */
.agent-log-pre {
  margin: 0;
  padding: 12px 16px;
  background: #1a1a1a;
  color: rgba(230, 230, 230, 0.95);
  font: 12px/1.4 ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  white-space: pre;
  overflow-x: auto;
  overflow-y: auto;
  max-height: 65vh;
  min-height: 200px;
}

/* #1760 — a refusal's `detail` from the device: under the code's sentence,
   smaller than it. */
.rc-record-detail {
  font-size: 0.7rem;
  line-height: 1.3;
}
</style>
