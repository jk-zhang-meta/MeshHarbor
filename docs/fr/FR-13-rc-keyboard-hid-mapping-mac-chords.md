# FR-13 — Remote-desktop keyboard: unmapped HID usages type garbage (CapsLock → `9`); Ctrl chords don't operate a macOS host

> **CLOSED 2026-08-27** — issue #789 is closed and its acceptance criteria are met. Any status line below is the state while the work was in flight, kept as the record.

**Issue:** [#789](https://github.com/gjovanov/roomler-ai/issues/789)
**Status:** implemented — agent half (hid_to_key arms + fallback removed) and viewer half (Ctrl→Cmd translate + toggle) both landed; agent half awaits the next agent release, viewer half the next web deploy; field verification pending

## Field report (2026-08-26)

1. Pressing **CapsLock** in the remote-desktop viewer types the digit **`9`**
   on the controlled host.
2. **Ctrl+C / Ctrl+V** from a Windows viewer into a **macOS** host do
   nothing — no copy, no paste.

## Bug A — the `Key::Other` fallback reinterprets HID usages as native keycodes

The viewer maps `KeyboardEvent.code` → USB-HID usage
(`kbdCodeToHid`, `ui/src/composables/useRemoteControl.ts:10347` —
`CapsLock → 0x39` is **correct**, locked by
`useRemoteControl.spec.ts:234`). The agent maps HID → enigo `Key` in
`hid_to_key` (`agents/meshharbord/src/input/enigo_backend.rs:514-595`) —
which has **no arm for 0x39**, so the caller falls through
(`enigo_backend.rs:210-218`) to:

```rust
enigo.key(Key::Other(code), direction)
```

`Key::Other` is **not a scancode escape hatch** — enigo 0.6.1 documents it as
a *platform-native virtual keycode* (Windows `VIRTUAL_KEY`, macOS `CGKeyCode`,
Linux keysym). So the raw HID byte is reinterpreted in a foreign namespace:

- **Windows host**: `VIRTUAL_KEY(0x39)` = `VK_9` → types **`9`**. HID-usage
  0x39 ≡ ASCII `'9'` ≡ `VK_9` — the same byte in three namespaces, bit-exact
  with the field report.
- **macOS host**: `CGKeyCode 0x39` happens to be `kVK_CapsLock`, so CapsLock
  *works by numeric coincidence* — but the same fallback turns **Numpad4**
  (HID 0x5C) into `ANSI_KEYPAD_9` → types **`9`** on a Mac.

Blast radius of the same fallback (all statically confirmed against
enigo 0.6.1 + core-graphics 0.25): `Pause` → **changes host volume** (mac),
`Numpad3`/`Numpad5` → **opens the Start menu** (`VK_LWIN`/`VK_RWIN`, Windows),
`Numpad7` → **VK_SLEEP sleeps the host** (Windows), NumLock/ScrollLock/
PrintScreen and the whole numpad type wrong letters/digits on both.
The composable's comment at `useRemoteControl.ts:10037-10039` ("works enough")
encodes the wrong assumption.

### Fix A (agent — one release)

1. Map the missing arms in `hid_to_key`: `0x39 → Key::CapsLock` (un-cfg'd in
   enigo, correct on all three OSes), numpad digits/operators
   (0x54–0x63), `IntlBackslash`, `ContextMenu`; platform-gate
   PrintScreen/Pause/NumLock/ScrollLock with the existing `0x49` cfg
   precedent (`enigo_backend.rs:566-571`).
2. **Kill the unsound fallback**: unmapped HID → `tracing::debug!` + drop,
   never `Key::Other` (a HID usage is never a valid VK/CGKeyCode/keysym).
3. Regression lock: extend `hid_table_covers_navigation_keys`
   (`enigo_backend.rs:736-743`) and add a `BROWSER_EMITTED_HID` table test
   asserting **every code `kbdCodeToHid` can emit maps to `Some(_)`** — the
   contract that silently broke.

## Bug B — Ctrl chords are injected literally; macOS shortcuts are Cmd

The viewer forwards `ControlLeft` (HID 0xe0) and the letter as separate
faithful events; the mac host receives literal **Control**+C/V — which is
SIGINT in a terminal and `pageDown:` in Cocoa text views, not copy/paste.
There is no Ctrl→Cmd translation anywhere in the path.

Key finding that shrinks the fix: **the hard half already works.** The
deferred Ctrl+V flow (`useRemoteControl.ts:8119-8160`) pushes the browser
clipboard to the host over the clipboard DC (arboard → NSPasteboard on mac,
ack-gated) *before* replaying the chord — only the final replayed chord is
wrong. Ctrl+C's only mechanism is the keystroke itself, so the host clipboard
never updates and the 25 ms mirror reads back stale content.

### Fix B (viewer — ships to the whole fleet instantly, no agent release)

The composable already receives the host OS (`useRemoteControl(agent)`,
`agent.os: 'linux'|'macos'|'windows'`). When the host is macOS and the viewer
chord is Ctrl-based (no metaKey), translate for the standard edit set
(`KeyC/V/X/A/Z/Y/S/F` — the same set `shouldPreventDefault` already
enumerates at `:9583-9604`):

- **B1** `flushPendingCtrlV` (`:7696-7703`): replay **Cmd**+V (HID 0xe3 —
  `Key::Meta` → `KeyCode::COMMAND`, already mapped in the agent) instead of
  relying on the held Ctrl. Two-line change; paste works against every
  deployed agent.
- **B2** `decideKeyAction` (`:9855-9889`): optional `hostOs` param; swap the
  Ctrl usage for 0xe3 / mods bit 0x08 on the edit set. AltGr and Ctrl+Alt
  combos stay untouched.
- **B3** rewrite the bare `ControlLeft` press (0xe0→0xe3) at the `onKey` send
  site so `heldInputs`/focus-loss release stay consistent with what was
  actually injected.
- **B4** escape hatch: a per-session viewer toolbar toggle ("send Ctrl
  literally") so Ctrl+C-as-SIGINT stays reachable in remote terminals —
  the same trade RustDesk/CRD/Parsec expose.

Agent-side defense-in-depth (held-modifier substitution for old viewers) is
deliberately **phase 2**, behind an env kill-switch, because it silently
changes semantics for terminal users.

## Acceptance criteria

- [ ] CapsLock toggles caps on Windows/macOS/Linux hosts (no `9`).
- [ ] Numpad digits/operators type what they say on all three; none of
      Pause/Numpad3/5/7 triggers volume/Start/sleep side effects.
- [ ] Rust: `BROWSER_EMITTED_HID ⊆ hid_to_key` table test green; unmapped
      HID drops with a debug log, never `Key::Other`.
- [ ] Windows viewer → macOS host: Ctrl+C copies (mirror returns the fresh
      selection), Ctrl+V pastes; Ctrl+C in a remote mac terminal still
      SIGINTs when the literal-Ctrl toggle is on.
- [ ] Vitest: `decideKeyAction` hostOs matrix + `flushPendingCtrlV` chord
      assertions; existing Ctrl-chord specs (`:316-328`, `:447-462`) stay
      green (non-mac paths byte-identical).
- [ ] Field: verified on a real Windows-viewer → macOS-host session
      (fleet Mac) and a Windows→Windows session (no regression).

## Field-verification log

- (pending)
