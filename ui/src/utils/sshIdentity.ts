// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD

/**
 * FR-105 — who a MeshHarbor SSH session runs as, said truthfully.
 *
 * Two facts decide it, and neither is enough alone:
 * - the grant's `account_mode`, what the policy asked for;
 * - the server's `ran_as`, where it sent the grant: the device's SYSTEM
 *   service (`system`, `console_user`) or the agent's own process (`worker`).
 *
 * The agent's own identity differs by install: root under systemd and on a
 * supervised Mac, SYSTEM on a Windows service install, but the SIGNED-IN USER
 * on an attended Windows install. So `daemon` alone must never be rendered as
 * "SYSTEM / root": on an attended device whose service does not serve SSH, it
 * is the person at the keyboard.
 */

import i18n from '@/plugins/i18n'

const tr = (key: string) => i18n.global.t(key)

/** The audit's "As" chip. */
export interface SshAsChip {
  label: string
  /** A Vuetify colour; `warning` marks an identity that owns the machine. */
  color?: string
  title: string
}

/** What `daemon` means when the agent's own process serves the session. */
export const AGENT_ACCOUNT_TITLE =
  'The account the agent runs as: root on Linux and macOS, SYSTEM on a Windows ' +
  'service install, and the signed-in user on an attended Windows install.'

/** The chip for one audit row. `null` for a refusal, which names no account. */
export function sshAsChip(
  accountMode: string | null | undefined,
  ranAs: string | null | undefined,
): SshAsChip | null {
  // The service's two identities are definite, whatever the install.
  if (ranAs === 'system') {
    return {
      label: 'SYSTEM',
      color: 'warning',
      title: tr('mh.sshAs.systemTitle'),
    }
  }
  if (ranAs === 'console_user') {
    return {
      label: tr('mh.sshAs.signedIn'),
      title: tr('mh.sshAs.consoleTitle'),
    }
  }
  // The agent's own process (`worker`), or a row from before FR-105.
  switch (accountMode) {
    case null:
    case undefined:
    case '':
      return null
    case 'daemon':
      return { label: tr('mh.sshAs.agentAccount'), color: 'warning', title: tr('mh.sshAs.agentTitle') }
    case 'console_user':
      return { label: tr('mh.sshAs.signedIn'), title: tr('mh.sshAs.userTitle') }
    case 'named':
      return { label: tr('mh.sshAs.named'), title: tr('mh.sshAs.namedTitle') }
    default:
      // A mode newer than this UI: shown as sent, never blank.
      return { label: accountMode, title: accountMode }
  }
}

/** Does this device serve SSH through its SYSTEM service right now? The
 *  device's live word. Matched by EQUALITY: `ssh` is a prefix of
 *  `ssh-system`, and a prefix match would read every SSH-capable agent as
 *  served by SYSTEM. */
export function servesSshAsSystem(rpc: readonly string[] | null | undefined): boolean {
  return (rpc ?? []).some((w) => w === 'ssh-system')
}

/** FR-97 P5a — does this Linux or macOS device run `console_user` itself, as
 *  the person at its screen? Its agent's `console-user` word. Windows never
 *  says it: there the signed-in user is the SYSTEM service's, keyed on the OS.
 *  Matched by EQUALITY, like every capability word. */
export function dropsToConsoleUser(rpc: readonly string[] | null | undefined): boolean {
  return (rpc ?? []).some((w) => w === 'console-user')
}
