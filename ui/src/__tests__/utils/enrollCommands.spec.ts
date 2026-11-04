// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect } from 'vitest'
import { DEVICE_ID_PLACEHOLDER, enrollCommands, installCards, type OsCommands } from '@/utils/enrollCommands'

/**
 * Locks the enrollment command templates to the shipped installer
 * contracts. If a binary name, flag, role vocabulary, or proxy route
 * changes, this spec fails instead of the admin UI shipping stale copy
 * (the pre-S4 dialogs hardcoded the prod URL and the retired
 * RETIRED-NAME-ANCHOR: names the retired forms on purpose; this suite exists to keep
 * them retired. FR-21.
 * `meshharbor-agent --enroll` / `meshharbor-tunnel enroll` forms).
 */
describe('enrollCommands', () => {
  const ORIGIN = 'https://example.meshharbor.test'
  const TOKEN = 'eyJTOKEN'
  const SCOPES = ['system', 'machine', 'user'] as const
  const manualOf = (os: OsCommands) => os.blocks.find((b) => b.id.endsWith('-manual'))!

  it('covers all three OSes for both kinds and every scope', () => {
    for (const kind of ['agent', 'tunnel'] as const) {
      for (const scope of SCOPES) {
        const all = enrollCommands(kind, ORIGIN, TOKEN, scope)
        expect(all.map((o) => o.os)).toEqual(['windows', 'linux', 'macos'])
        for (const os of all) {
          // Script, wizard, manual — less the wizard where it cannot install
          // an agent (FR-97 D5, below).
          const wizardInstallsIt = kind === 'tunnel' || os.os === 'windows'
          expect(os.blocks).toHaveLength(wizardInstallsIt ? 3 : 2)
          for (const block of os.blocks) {
            if (!block.isDownload) expect(block.command).toContain(TOKEN)
            expect(block.command).toContain(ORIGIN)
          }
        }
      }
    }
  })

  it('defaults the agent scope to system-context (wizard-recommended)', () => {
    const [windows, linux, macos] = enrollCommands('agent', ORIGIN, TOKEN)
    // install.ps1: ValidateSet daemon-user|daemon-machine|daemon-system|tunnel-client
    expect(windows!.blocks[0]!.command).toContain('/api/setup/install.ps1')
    expect(windows!.blocks[0]!.command).toContain('-Role daemon-system')
    expect(windows!.blocks[0]!.command).toContain(`-Token ${TOKEN}`)
    // install.sh: --role daemon|tunnel; --system = root systemd unit (Linux only).
    expect(linux!.blocks[0]!.command).toContain('/api/setup/install.sh')
    expect(linux!.blocks[0]!.command).toContain('--role daemon --system')
    expect(macos!.blocks[0]!.command).toContain('--role daemon')
    expect(macos!.blocks[0]!.command).not.toContain('--system')
    // Manual enrolls use the unified daemon binary; S1b: SystemContext
    // reads the machine-global config, so its enroll writes it.
    expect(manualOf(windows!).command).toMatch(/^meshharbord enroll /)
    expect(manualOf(windows!).command).toContain('--machine-global')
    expect(manualOf(linux!).command).toMatch(
      /^sudo meshharbord --config \/etc\/meshharbor\/config\.toml enroll /,
    )
    expect(manualOf(linux!).command).toContain(`--server ${ORIGIN}`)
    // NOT `meshharbord`: on macOS the daemon lives inside the .app bundle and no
    // binary by that name exists anywhere on the machine.
    expect(manualOf(macos!).command).toMatch(/^\/Library\/MeshHarbor\/meshharbord\.app\S* enroll /)
  })

  it('maps the user scope to the per-user roles', () => {
    const [windows, linux, macos] = enrollCommands('agent', ORIGIN, TOKEN, 'user')
    expect(windows!.blocks[0]!.command).toContain('-Role daemon-user')
    expect(linux!.blocks[0]!.command).toContain('--role daemon')
    expect(linux!.blocks[0]!.command).not.toContain('--system')
    for (const os of [windows!, linux!]) {
      expect(manualOf(os).command).toMatch(/^meshharbord enroll /)
    }
    // macOS resolves to the bundle executable — see above.
    expect(manualOf(macos!).command).toMatch(/^\/Library\/MeshHarbor\/meshharbord\.app\S* enroll /)
    expect(manualOf(windows!).command).not.toContain('--machine-global')
  })

  it('maps the machine scope to the attended role without machine-global', () => {
    const [windows, linux, macos] = enrollCommands('agent', ORIGIN, TOKEN, 'machine')
    expect(windows!.blocks[0]!.command).toContain('-Role daemon-machine')
    // S1b: a plain-SCM service reads the per-user config — machine-global
    // is the SystemContext flavour's config source ONLY.
    expect(manualOf(windows!).command).not.toContain('--machine-global')
    // Linux has no attended/SystemContext split — machine-wide = --system.
    expect(linux!.blocks[0]!.command).toContain('--role daemon --system')
    expect(manualOf(linux!).command).toMatch(/^sudo meshharbord --config /)
    expect(macos!.blocks[0]!.command).not.toContain('--system')
  })

  it('ignores scope for tunnel enrollments', () => {
    const baseline = enrollCommands('tunnel', ORIGIN, TOKEN)
    for (const scope of SCOPES) {
      expect(enrollCommands('tunnel', ORIGIN, TOKEN, scope)).toEqual(baseline)
    }
  })

  it('annotates machine-wide scopes with per-OS caveats', () => {
    for (const scope of ['system', 'machine'] as const) {
      const [windows, linux, macos] = enrollCommands('agent', ORIGIN, TOKEN, scope)
      expect(windows!.note).toMatch(/Administrator PowerShell/)
      expect(linux!.note).toBeTruthy()
      expect(macos!.note).toMatch(/per-user/)
    }
    for (const os of enrollCommands('agent', ORIGIN, TOKEN, 'user')) {
      // macOS carries a caveat at EVERY scope: its per-user/root split is a
      // property of the platform (capture needs a GUI session, a utun needs
      // root), not of the scope the operator picked.
      if (os.os === 'macos') {
        expect(os.note).toMatch(/daemon-token/)
      } else {
        expect(os.note).toBeUndefined()
      }
    }
    for (const os of enrollCommands('tunnel', ORIGIN, TOKEN)) {
      expect(os.note).toBeUndefined()
    }
  })

  it('tunnel commands use the tunnel roles + the meshharbor CLI', () => {
    const [windows, linux] = enrollCommands('tunnel', ORIGIN, TOKEN)
    expect(windows!.blocks[0]!.command).toContain('-Role tunnel-client')
    expect(linux!.blocks[0]!.command).toContain('--role tunnel')
    expect(windows!.blocks[2]!.command).toMatch(/^meshharbor enroll /)
    expect(linux!.blocks[2]!.command).toMatch(/^meshharbor enroll /)
  })

  it('wizard downloads hit the setup proxy with valid platform slugs', () => {
    // setup_release.rs::normalise_platform accepts windows|linux|macos.
    const all = enrollCommands('tunnel', ORIGIN, TOKEN)
    const downloads = all.map((o) => o.blocks.find((b) => b.isDownload)!)
    expect(downloads.map((d) => d.command)).toEqual([
      `${ORIGIN}/api/setup/windows`,
      `${ORIGIN}/api/setup/linux`,
      `${ORIGIN}/api/setup/macos`,
    ])
  })

  it('offers the wizard for an agent only where it installs one (FR-97 D5)', () => {
    // Off Windows, MeshHarbor Setup installs the tunnel client and nothing else
    // (`agents/meshharbor-setup`): offered for an agent there, it could not
    // enroll the device the token was minted for.
    for (const scope of SCOPES) {
      const offered = enrollCommands('agent', ORIGIN, TOKEN, scope)
        .filter((o) => o.blocks.some((b) => b.isDownload))
        .map((o) => o.os)
      expect(offered, scope).toEqual(['windows'])
    }
  })

  it('the homepages offer the wizard by the same rule (FR-97 P0c-4)', () => {
    // They kept their own per-OS map until P0c-4 and offered MeshHarbor Setup on
    // every card, where off Windows it could install only the tunnel client.
    const cards = installCards(ORIGIN)
    expect(cards.map((c) => [c.os, c.wizardUrl])).toEqual([
      ['windows', `${ORIGIN}/api/setup/windows`],
      ['linux', null],
      ['macos', null],
    ])
    // Each card's terminal form is the agent's one-line install, never a download.
    for (const card of cards) {
      expect(card.command, card.os).toBe(
        enrollCommands('agent', ORIGIN, null).find((o) => o.os === card.os)!.blocks[0]!.command,
      )
    }
  })

  it('never emits the retired binary names or a hardcoded server', () => {
    for (const kind of ['agent', 'tunnel'] as const) {
      for (const scope of SCOPES) {
        for (const os of enrollCommands(kind, ORIGIN, TOKEN, scope)) {
          for (const block of os.blocks) {
            // FR-46 P5b REMOVED the macOS exception. The .app, its executable
            // and both launchd plists now carry the current name, so this
            // assertion holds on every platform — and leaving the exemption in
            // would have quietly stopped testing the one platform that still
            // had the name, which is the opposite of what this suite is for.
            // RETIRED-NAME-ANCHOR(3): the retired forms are the SUBJECT of the
            // assertion; naming them is how it asserts they are gone.
            expect(block.command).not.toContain('meshharbor-agent')
            expect(block.command).not.toContain('meshharbor-tunnel')
            expect(block.command).not.toContain('https://meshharbor.itachi.fans')
          }
        }
      }
    }
  })

  it('the macOS manual enroll points at the binary that actually exists there', () => {
    // There is no `meshharbord` anywhere on a Mac — the daemon ships inside the
    // .app bundle — so the generic `meshharbord enroll` this used to print was a
    // command the user could not run.
    const macos = enrollCommands('agent', ORIGIN, TOKEN).find((o) => o.os === 'macos')!
    const manual = macos.blocks.find((b) => b.id.endsWith('-manual'))!
    expect(manual.command).toContain(
      '/Library/MeshHarbor/meshharbord.app/Contents/MacOS/meshharbord enroll',
    )
    expect(manual.command).not.toMatch(/^meshharbord /)
  })

  it('renders a placeholder while the token is still being issued', () => {
    const [windows] = enrollCommands('agent', ORIGIN, null)
    expect(windows!.blocks[0]!.command).toContain('<token>')
  })

  it('normalises a trailing slash off the origin', () => {
    const [windows] = enrollCommands('agent', `${ORIGIN}/`, TOKEN)
    expect(windows!.blocks[0]!.command).not.toContain('.test//api')
  })
})

/**
 * FR-104 — a token that may also anchor the device it enrolls. The anchor
 * command is offered where there is a SYSTEM service to anchor: a
 * machine-wide Windows install, nowhere else.
 */
describe('enrollCommands — the anchor command (FR-104)', () => {
  const ORIGIN = 'https://example.meshharbor.test'
  const TOKEN = 'eyJTOKEN'
  const anchorBlock = (os: OsCommands) =>
    os.blocks.find((b) => b.id === 'agent-windows-anchor')

  it('adds the elevated anchor command, with the same token, for both machine-wide scopes', () => {
    for (const scope of ['system', 'machine'] as const) {
      const [windows] = enrollCommands('agent', ORIGIN, TOKEN, scope, true)
      const block = anchorBlock(windows!)
      expect(block, scope).toBeDefined()
      expect(windows!.blocks.at(-1)).toBe(block)
      expect(block!.command).toBe(
        `meshharbord anchor create --server ${ORIGIN} --token ${TOKEN} --device ${DEVICE_ID_PLACEHOLDER}`,
      )
    }
  })

  it('offers it nowhere else', () => {
    // Not asked for.
    for (const os of enrollCommands('agent', ORIGIN, TOKEN, 'system')) {
      expect(anchorBlock(os)).toBeUndefined()
    }
    // A per-user install has no SYSTEM service; Linux and macOS daemons
    // already run as root; a tunnel client is no device to anchor.
    for (const os of enrollCommands('agent', ORIGIN, TOKEN, 'user', true)) {
      expect(anchorBlock(os)).toBeUndefined()
    }
    for (const os of enrollCommands('agent', ORIGIN, TOKEN, 'system', true).slice(1)) {
      expect(anchorBlock(os)).toBeUndefined()
      expect(os.blocks).toHaveLength(2)
    }
    for (const os of enrollCommands('tunnel', ORIGIN, TOKEN, 'system', true)) {
      expect(anchorBlock(os)).toBeUndefined()
    }
  })

  it('leaves the device id to fill in, as no device exists before the enrollment', () => {
    const [windows] = enrollCommands('agent', ORIGIN, null, 'system', true)
    const block = anchorBlock(windows!)!
    expect(block.command).toContain('--token <token>')
    expect(block.label).toContain(DEVICE_ID_PLACEHOLDER)
  })
})
