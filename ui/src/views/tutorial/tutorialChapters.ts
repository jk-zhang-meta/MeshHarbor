// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import heroMesh from '@/assets/tutorial/hero-mesh.svg'
import heroRemoteDesktop from '@/assets/tutorial/remote-desktop.svg'
import heroPrivateNetwork from '@/assets/tutorial/private-network.svg'
import heroDevices from '@/assets/tutorial/devices.svg'
import heroTunnels from '@/assets/tutorial/tunnels.svg'
import heroAcl from '@/assets/tutorial/acl.svg'
import stepEnroll from '@/assets/tutorial/step-enroll.svg'
import stepConnect from '@/assets/tutorial/step-connect.svg'
import stepForward from '@/assets/tutorial/step-forward.svg'
import stepAcl from '@/assets/tutorial/step-acl.svg'
import stepMagicDns from '@/assets/tutorial/step-magicdns.svg'
import videoTourPoster from '@/assets/tutorial/video-C1YdfmhbAKM.jpg'
import { FEATURED_VIDEO_ID } from '@/utils/videos'

/**
 * FR-12 (#788) — the tour's content, kept OUT of the view so it stays
 * readable, diffable and unit-testable. `**bold**` marks emphasis —
 * rendered as segments, never through v-html.
 */

export interface TutorialStep {
  /** What the reader should do. Supports `**bold**`. */
  text: string
  /** A REAL in-app destination — never a screenshot of a button. */
  to?: { name: string; query?: Record<string, string> }
  /** Label for the link/button (defaults to "Open"). */
  linkLabel?: string
  /** A copyable command (tunnels / ssh chapters). */
  code?: string
  /** Icon for the step's bullet, in place of its number. */
  icon?: string
  /** An illustration for this step alone. */
  graphic?: string
  graphicAlt?: string
}

/** A decorated bullet: icon badge + bold lead-in + the rest. */
export interface TutorialBadge {
  icon: string
  color: string
  title: string
  text: string
}

export interface TutorialChapter {
  /** URL hash + progress key. Stable — progress is stored against it. */
  id: string
  title: string
  icon: string
  /** One-line rail subtitle. */
  blurb: string
  /** Landing-page headline treatment (chapter 0 only). */
  tagline?: { headline: string; accent: string; sub: string }
  /** Capability chips, straight from the landing strip. */
  chips?: string[]
  hero?: string
  heroAlt?: string
  /** FR-88 P3 — a click-to-load video (an id from `@/utils/videos` and its
   *  poster), drawn by `VideoFacade.vue` above the hero. */
  video?: { id: string; poster: string; caption?: string }
  lead: string
  /** The decorated promise bullets. */
  badges?: TutorialBadge[]
  steps: TutorialStep[]
  /** Landing pillar features — the "gems", as cards. */
  highlights?: TutorialBadge[]
  /** FR-12 P2 — a spotlight tour that runs on the real page for this chapter. */
  tour?: { id: string; routeName: string; label: string }
  detail: Array<{ label: string; text: string }>
}

const TEAL = '#009688'
const DEEP = '#00796B'
const CORAL = '#ef5350'

export const TUTORIAL_CHAPTERS: TutorialChapter[] = [
  {
    id: 'get-started',
    title: 'Get started',
    icon: 'mdi-flag-outline',
    blurb: 'What MeshHarbor is, in one screen',
    tagline: {
      headline: 'Every device you own,',
      accent: 'one secure network',
      sub: 'Remote desktop from any browser and a private WireGuard-style mesh between your machines — self-hostable and end-to-end encrypted.',
    },
    chips: [
      'Remote desktop',
      'Private mesh network',
      'Tunnels & SOCKS5',
      'Exit nodes',
      'MagicDNS',
      'Zero-config SSH',
    ],
    video: {
      id: FEATURED_VIDEO_ID,
      poster: videoTourPoster,
      caption:
        'A 9-minute tour: installing the agent on Windows, macOS and Linux, connecting from a browser tab, and how it compares with TeamViewer and AnyDesk.',
    },
    hero: heroMesh,
    heroAlt:
      'Machines joined in a direct encrypted mesh with stable private addresses, crossing NATs and firewalls',
    lead:
      'Remote desktop, private mesh networking, tunnels and SSH on **one small daemon**. You install **one agent per machine** — everything else happens in this browser. Traffic between your machines is **end-to-end encrypted** and goes peer-to-peer whenever a path exists: the server coordinates, it never carries your pixels, keystrokes or files.',
    badges: [
      {
        icon: 'mdi-monitor-eye',
        color: TEAL,
        title: 'Remote desktop and control',
        text: 'from any browser — nothing to install on the viewing side.',
      },
      {
        icon: 'mdi-lan',
        color: CORAL,
        title: 'Private, secure mesh network',
        text: 'for your machines in different geographic locations, with stable addresses and names.',
      },
      {
        icon: 'mdi-transit-connection-variant',
        color: DEEP,
        title: 'Tunnels, SSH and access control',
        text: 'forward ports, run SOCKS5 proxies, and reach machines without opening inbound ports.',
      },
    ],
    steps: [
      {
        icon: 'mdi-office-building-outline',
        text: 'Give this organization a name your team will recognize — it labels **every device and invite**.',
        to: { name: 'admin-settings' },
        linkLabel: 'Organization settings',
      },
      {
        icon: 'mdi-download',
        text: 'Add your first machine: mint an enrollment token and run the **one-line installer** on it.',
        to: { name: 'devices', query: { enroll: '1' } },
        linkLabel: 'Enroll a device',
        graphic: stepEnroll,
        graphicAlt: 'One command on Windows, Linux or macOS enrolls a machine into your organization',
      },
      {
        icon: 'mdi-account-multiple-plus-outline',
        text: 'Bring in the people you work with — by **invite link** or straight to their **email**.',
        to: { name: 'invites' },
        linkLabel: 'Invites',
      },
    ],
    highlights: [
      {
        icon: 'mdi-shield-lock-outline',
        color: CORAL,
        title: 'Works behind strict networks',
        text: 'Direct peer-to-peer when possible; relays and WebSocket fallbacks punch through corporate firewalls and full-tunnel VPNs.',
      },
      {
        icon: 'mdi-monitor-multiple',
        color: TEAL,
        title: 'Fleet management built in',
        text: 'Enroll unattended machines, push updates from the web, transfer files and clipboard, and audit every session.',
      },
      {
        icon: 'mdi-cellphone-link',
        color: DEEP,
        title: 'One daemon per machine',
        text: 'The same agent is the remote-desktop target, the network node, the tunnel exit and the SSH server — not four services to install.',
      },
    ],
    detail: [
      {
        label: 'Nothing to install to watch',
        text: 'The viewing side is a plain browser tab. Only the machine you reach runs the agent.',
      },
      {
        label: 'Works from anywhere',
        text: 'Hotel Wi-Fi, NAT, corporate firewall: the connection cascade finds the fastest path that works and keeps re-trying for a better one.',
      },
      {
        label: 'Self-hostable',
        text: 'Run the full stack on your own server — remote desktop, private mesh, tunnels, SSH and fleet management.',
      },
    ],
  },
  {
    id: 'devices',
    title: 'Devices',
    tour: { id: 'enroll', routeName: 'devices', label: 'Show me on the Devices page' },
    icon: 'mdi-monitor-multiple',
    blurb: 'Enroll machines and keep them current',
    hero: heroDevices,
    heroAlt:
      'A single-use enrollment token turning into a new row in the device list, beside three machines already enrolled',
    lead:
      'Devices is the **home page of your fleet**. Every enrolled machine shows up with its live status, operating system, overlay address, MagicDNS name and agent version. Two kinds share the grid: **full daemons** (remote desktop + network + tunnels) and **tunnel-only clients**. Enrolling is one command on the target machine — there is no manual key exchange.',
    badges: [
      {
        icon: 'mdi-rocket-launch-outline',
        color: TEAL,
        title: 'Set up in minutes',
        text: 'Run the graphical installer or paste one command — the machine appears here as soon as it enrolls.',
      },
      {
        icon: 'mdi-tag-outline',
        color: DEEP,
        title: 'Name it once',
        text: 'A display name and tags follow the device into the network and MagicDNS.',
      },
      {
        icon: 'mdi-update',
        color: CORAL,
        title: 'Updates from the web',
        text: 'Push a release to a device from here — and the server refuses a pin that would downgrade it.',
      },
    ],
    steps: [
      {
        icon: 'mdi-key-plus',
        text: 'Mint an enrollment token, then paste the one-liner on the machine — **shell** on Linux/macOS, **PowerShell** on Windows.',
        to: { name: 'devices', query: { enroll: '1' } },
        linkLabel: 'Enroll a device',
        graphic: stepEnroll,
        graphicAlt: 'One command per platform enrolls a machine',
      },
      {
        icon: 'mdi-rename-box',
        text: 'Give a device a **friendly display name** and tags — renaming propagates to the overlay and MagicDNS.',
        to: { name: 'devices' },
        linkLabel: 'Open Devices',
      },
      {
        icon: 'mdi-table-cog',
        text: 'Tailor the grid: **search across every column**, sort, and pick which columns you see — your choice is remembered.',
        to: { name: 'devices' },
        linkLabel: 'Open Devices',
      },
    ],
    detail: [
      {
        label: 'Install',
        text: 'One line per platform. Windows MSI (per-user or per-machine, signed), Linux .deb/tarball with systemd, macOS .pkg.',
      },
      {
        label: 'Status',
        text: 'Online / stale / offline. "Stale" means the device heartbeats but no server holds its live socket — it self-heals within about two minutes.',
      },
      {
        label: 'Updates',
        text: 'Push a specific release to a device, or let it pick up the latest on its own. A stale pin that would downgrade a device is refused unless you force it.',
      },
    ],
  },
  {
    id: 'remote-desktop',
    title: 'Remote desktop',
    icon: 'mdi-remote-desktop',
    blurb: 'Use any machine from a browser tab',
    hero: heroRemoteDesktop,
    heroAlt:
      'A laptop showing the live desktop of an office PC inside a browser tab, mouse and keyboard flowing back',
    lead:
      'Open a machine and use it **as if you were sitting in front of it**. The picture is hardware-encoded where the GPU allows and fluid enough for real work; clipboard, file transfer and multi-monitor all work, and on Windows the session survives the **lock screen, UAC prompts and logout**. Every session is consent-gated and audit-logged, and the media never touches the server.',
    badges: [
      {
        icon: 'mdi-google-chrome',
        color: TEAL,
        title: 'No viewer to install',
        text: 'Any modern browser is the controller — hardware-encoded H.264/HEVC/VP9 with sub-100 ms input latency.',
      },
      {
        icon: 'mdi-shield-check-outline',
        color: CORAL,
        title: 'Consent-gated and audited',
        text: 'The person at the machine decides, or you grant unattended access deliberately — either way it is logged.',
      },
      {
        icon: 'mdi-content-copy',
        color: DEEP,
        title: 'Clipboard and files',
        text: 'Copy text or images both ways and drag files across, resumable if the link drops.',
      },
    ],
    steps: [
      {
        icon: 'mdi-monitor-arrow-down',
        text: 'Click **Connect** on any online device to open its screen in this tab.',
        to: { name: 'devices' },
        linkLabel: 'Open Devices',
        graphic: stepConnect,
        graphicAlt: 'A browser tab showing a remote desktop, with keyboard and mouse flowing back',
      },
      {
        icon: 'mdi-account-check-outline',
        text: 'Decide how each device answers: **ask the person at the machine** every time, or grant unattended access.',
        to: { name: 'devices' },
        linkLabel: 'Consent per device',
      },
      {
        icon: 'mdi-gesture-tap-button',
        text: 'In a session, try the toolbar: **multi-monitor**, scaling, clipboard sync, file upload and **Ctrl-Alt-Del**.',
      },
    ],
    highlights: [
      {
        icon: 'mdi-speedometer',
        color: TEAL,
        title: 'Built for real work',
        text: 'A low-latency WebCodecs canvas path (Chrome-first) bypasses the browser video jitter buffer for drag-and-type work.',
      },
      {
        icon: 'mdi-lock-open-variant-outline',
        color: CORAL,
        title: 'Unattended access',
        text: 'Runs as a service, survives logout, drives the Windows lock screen and pre-logon desktop; headless Linux gets a virtual desktop.',
      },
      {
        icon: 'mdi-chip',
        color: DEEP,
        title: 'Hardware encoding',
        text: 'NVENC, Quick Sync, AMF and Media Foundation with probe-and-rollback, falling back to software when no GPU path works.',
      },
    ],
    detail: [
      {
        label: 'Codecs',
        text: 'H.264, HEVC, AV1 and VP9 4:4:4 — the last one for crisp text at full chroma.',
      },
      {
        label: 'Input',
        text: 'Full keyboard and mouse, keyboard lock, remote cursor, multi-monitor, scaling and 1:1 host-display matching.',
      },
      {
        label: 'Security',
        text: 'Consent-gated, audit-logged, end-to-end encrypted. The server relays signalling only.',
      },
    ],
  },
  {
    id: 'network',
    title: 'Private network',
    icon: 'mdi-lan-connect',
    blurb: 'Stable addresses and names for every machine',
    hero: heroPrivateNetwork,
    heroAlt:
      'Machines on different networks joined by a private overlay with stable addresses',
    lead:
      'Every enrolled machine gets a **stable private address** and a **name that resolves from any other machine** in your organization — across NAT, on hotel Wi-Fi, behind a corporate firewall. Connections go straight peer-to-peer when a path exists and fall back to an encrypted relay when nothing else gets through, so *"is it reachable?"* stops being a question.',
    badges: [
      {
        icon: 'mdi-ip-network-outline',
        color: TEAL,
        title: 'WireGuard-style mesh',
        text: 'Every device gets a stable private address; traffic flows directly between machines, encrypted end to end.',
      },
      {
        icon: 'mdi-dns-outline',
        color: DEEP,
        title: 'MagicDNS',
        text: 'Reach machines by name instead of chasing addresses that change with every network.',
      },
      {
        icon: 'mdi-router-network',
        color: CORAL,
        title: 'Subnet routers and exit nodes',
        text: 'Expose a whole LAN through one machine, or route all your traffic through a trusted exit node when you travel.',
      },
    ],
    steps: [
      {
        icon: 'mdi-content-copy',
        text: 'Read a device’s **overlay address** and **MagicDNS name** straight off the grid — the copy button puts the name on your clipboard.',
        to: { name: 'devices' },
        linkLabel: 'Open Devices',
        graphic: stepMagicDns,
        graphicAlt: 'A machine name resolving to its stable private address from anywhere',
      },
      {
        icon: 'mdi-web',
        text: 'Set the DNS suffix your names live under, so `laptop.your-org` resolves **fleet-wide**.',
        to: { name: 'network-dns' },
        linkLabel: 'MagicDNS settings',
      },
      {
        icon: 'mdi-console',
        text: 'Shell into any machine by name — **no sshd, no open port, no firewall rule**.',
        code: 'mh ssh <device-name>',
      },
      {
        icon: 'mdi-router-wireless',
        text: 'Let one machine advertise the subnet behind it, so **its LAN becomes reachable** from the mesh.',
        to: { name: 'network-subnet-routes' },
        linkLabel: 'Subnet routes',
      },
    ],
    detail: [
      {
        label: 'Path selection',
        text: 'LAN, then direct over the internet, then a hole-punched path, then an encrypted relay — measured, never assumed, and continuously re-upgraded.',
      },
      {
        label: 'No privileges needed',
        text: 'Where a VPN adapter is unavailable or owned by someone else, a userspace mode gives the same mesh with zero routing changes.',
      },
      {
        label: 'SSH without sshd',
        text: 'Packets for the SSH port are intercepted below the OS, so a machine that cannot host sshd (or has no admin rights) still answers.',
      },
    ],
  },
  {
    id: 'tunnels',
    title: 'Tunnels',
    icon: 'mdi-transit-connection-variant',
    blurb: 'Reach a service without exposing it',
    hero: heroTunnels,
    heroAlt: 'A local port tunnelled to a service reachable only by a remote machine, with the public internet refused',
    lead:
      'A tunnel turns **anything one of your machines can reach** into a local port on yours — a database on a private subnet, an internal web app, a printer. **Nothing is published to the internet**, the payload stays encrypted end to end, and access is default-deny: a tunnel only works where you allowed it.',
    badges: [
      {
        icon: 'mdi-swap-horizontal-bold',
        color: TEAL,
        title: 'Port forwarding',
        text: 'Any host:port an enrolled machine can reach becomes 127.0.0.1 on yours.',
      },
      {
        icon: 'mdi-earth',
        color: DEEP,
        title: 'SOCKS5 proxy',
        text: 'Point a browser at one device — or the whole fleet — and carry TCP and UDP through it.',
      },
      {
        icon: 'mdi-cog-sync-outline',
        color: CORAL,
        title: 'Supervised routes',
        text: 'Declare a forward once and the daemon rebuilds it on every start, with backoff.',
      },
    ],
    steps: [
      {
        icon: 'mdi-arrow-right-bold-box-outline',
        text: 'Forward a remote service to a **local port** on your machine.',
        code: 'mh forward --agent <device-name> --local 127.0.0.1:5432 --remote db:5432',
        graphic: stepForward,
        graphicAlt: 'A local port tunnelled through an enrolled machine to a database on its private LAN',
      },
      {
        icon: 'mdi-web-box',
        text: 'Or route a whole browser through a device’s **vantage point** with a local SOCKS5 proxy.',
        code: 'mh socks5 --agent <device-name> --listen 127.0.0.1:1080',
      },
      {
        icon: 'mdi-pin-outline',
        text: 'Make a forward **permanent**: declare it in the device’s config and the daemon supervises it across reboots.',
        to: { name: 'devices', query: { type: 'both' } },
        linkLabel: 'Devices & tunnel clients',
      },
      {
        icon: 'mdi-laptop',
        text: 'A machine that should **only reach services** (no remote desktop) can enroll as a tunnel-only client.',
        to: { name: 'devices', query: { enroll: '1' } },
        linkLabel: 'Enroll a tunnel client',
      },
    ],
    detail: [
      {
        label: 'Nothing exposed',
        text: 'No public port, no inbound firewall rule. The exit machine dials out, the same as every other connection here.',
      },
      {
        label: 'Whole-fleet proxy',
        text: 'SOCKS5 can target one device or the whole mesh, and carries TCP and UDP.',
      },
      {
        label: 'Supervised routes',
        text: 'Declared routes are reconciled on every start with backoff, and a revoked route stops retrying instead of hammering the server.',
      },
    ],
  },
  {
    id: 'acl',
    title: 'Access control',
    icon: 'mdi-shield-lock-outline',
    blurb: 'Who may reach what — default deny',
    hero: heroAcl,
    heroAlt:
      'Two machines allowed through a policy gate to the ports they were granted, and a third denied, with every decision recorded in an audit line',
    lead:
      'Membership of your organization is **not** the same as permission to reach a machine. Tunnel and overlay policies say which people and devices may reach which destinations, and both **start closed**: nothing is permitted until you write a rule. Every decision is recorded, and the device itself keeps a **local veto** that survives even a compromised control plane.',
    badges: [
      {
        icon: 'mdi-lock-outline',
        color: CORAL,
        title: 'Default deny',
        text: 'An empty policy set grants nothing — rules are additive and scoped to your organization.',
      },
      {
        icon: 'mdi-eye-outline',
        color: TEAL,
        title: 'Try before enforcing',
        text: 'Warn mode shows what would be refused, in the logs, before anything is actually dropped.',
      },
      {
        icon: 'mdi-clipboard-text-clock-outline',
        color: DEEP,
        title: 'Everything audited',
        text: 'Command runs and SSH session decisions are logged — including the refusals, which are the interesting ones.',
      },
    ],
    steps: [
      {
        icon: 'mdi-playlist-check',
        text: 'Write your first rules — **one page**, Overlay and Tunnel tabs.',
        to: { name: 'network-acl' },
        linkLabel: 'Open ACL',
        graphic: stepAcl,
        graphicAlt: 'Default-deny policy between machines: one path allowed, one refused and logged',
      },
      {
        icon: 'mdi-check-decagram-outline',
        text: 'Approve the subnets a device may advertise **before** its LAN becomes reachable.',
        to: { name: 'network-subnet-routes' },
        linkLabel: 'Subnet routes',
      },
      {
        icon: 'mdi-shield-account-outline',
        text: 'Give people **only the powers they need** — device, remote-control, SSH and audit permissions are separate bits.',
        to: { name: 'admin-roles' },
        linkLabel: 'Roles',
      },
      {
        icon: 'mdi-history',
        text: 'Review what actually happened: every command and SSH decision is logged.',
        to: { name: 'audit-exec' },
        linkLabel: 'Command audit',
      },
    ],
    detail: [
      {
        label: 'The device has the last word',
        text: 'Remote command execution and SSH are each gated four times over — org switch, your permission, device policy, and a local setting on the machine itself.',
      },
      {
        label: 'Roles',
        text: 'Reviewing who held a session and being able to open one are deliberately different permissions.',
      },
      {
        label: 'Scope',
        text: 'Every rule, device and log line is scoped to this organization — nothing leaks across orgs.',
      },
    ],
  },
]

/** Chapters keyed by their URL hash — the view resolves `#devices` etc. */
export function chapterById(id: string): TutorialChapter | undefined {
  return TUTORIAL_CHAPTERS.find((c) => c.id === id)
}

/**
 * Split `**bold**` prose into renderable segments. Deliberately NOT
 * `v-html`: the strings are ours and compile-time, but a template that
 * takes raw HTML is a habit worth not forming.
 */
export function richSegments(text: string): Array<{ text: string; bold: boolean }> {
  return text
    .split(/(\*\*[^*]+\*\*)/g)
    .filter((part) => part.length > 0)
    .map((part) =>
      part.startsWith('**') && part.endsWith('**')
        ? { text: part.slice(2, -2), bold: true }
        : { text: part, bold: false },
    )
}
