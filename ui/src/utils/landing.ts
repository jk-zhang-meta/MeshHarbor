// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-87 (#1776) — the landing copy and the plan table, ONE source for the two
 * pages that show them: the SPA's `LandingView.vue` (in-app navigation) and
 * the static homepage the docs generator writes for `/` (what a guest and
 * every crawler get).
 *
 * Zero imports, like `enrollCommands.ts`, so Bun can load it at build time
 * with no Vue and no Vuetify. Icons stay with each renderer: the SPA draws
 * Material Design icons, the static page draws its own inline SVGs, so an
 * entry names its SPA icon and the generator maps it.
 */

export interface LandingFeature {
  /** Material Design icon for the SPA (`mdi-…`). */
  icon: string
  title: string
  description: string
  color: string
}

export interface LandingPillar {
  title: string
  subtitle: string
  features: LandingFeature[]
}

/** FR-115 — one seat's price for one interval and currency. */
export interface PlanPrice {
  interval: 'month' | 'year'
  currency: 'usd' | 'eur'
  unit_amount: number
}

export interface Plan {
  id: string
  name: string
  /** One seat for one month, in US cents. */
  price_cents: number
  features: string[]
  /** FR-115 — every interval and currency on sale; absent from an older server. */
  prices?: PlanPrice[]
  per_seat?: boolean
  commercial_use?: boolean
}

export const HERO = {
  titleLead: 'Every device you own,',
  titleAccent: 'one secure network',
  lead: 'Remote desktop from any browser and a private WireGuard-style mesh between your machines — with team chat and video included.',
}

/** FR-88 P3: the video section under the capability chips. The video itself is
 *  `FEATURED_VIDEO_ID` in `videos.ts`. */
export const VIDEO_TOUR = {
  title: 'See it in action',
  lead: 'Install the agent on Windows, macOS and Linux, connect from a browser tab, and see what MeshHarbor does that TeamViewer and AnyDesk do, and what they still do better.',
}

export const CAPABILITIES = [
  'Remote desktop',
  'Private mesh network',
  'Tunnels & SOCKS5',
  'Exit nodes',
  'MagicDNS',
  'Chat & video included',
]

// Pivot order: remote access first, the private network second,
// collaboration as the included bonus.
export const PILLARS: LandingPillar[] = [
  {
    title: 'Reach any of your devices',
    subtitle: 'A TeamViewer-style remote desktop that lives in your browser',
    features: [
      {
        icon: 'mdi-monitor-eye',
        title: 'Remote desktop in the browser',
        description: 'Hardware-encoded H.264/HEVC/VP9 with sub-100 ms input latency. No viewer install — any Chromium browser is the controller.',
        color: '#009688',
      },
      {
        icon: 'mdi-shield-lock-outline',
        title: 'Works behind strict networks',
        description: 'Direct peer-to-peer when possible; TURN relays and WebSocket fallbacks punch through corporate firewalls and full-tunnel VPNs.',
        color: '#ef5350',
      },
      {
        icon: 'mdi-monitor-multiple',
        title: 'Fleet management built in',
        description: 'Enroll unattended machines, push updates from the web, transfer files and clipboard, and audit every session.',
        color: '#009688',
      },
    ],
  },
  {
    title: 'Your own private network',
    subtitle: 'A Tailscale-style overlay mesh between everything you enroll',
    features: [
      {
        icon: 'mdi-lan',
        title: 'WireGuard-style mesh',
        description: 'Every device gets a stable private address. Traffic flows directly between machines with NAT hole-punching and encrypted end to end.',
        color: '#ef5350',
      },
      {
        icon: 'mdi-router-network',
        title: 'Subnet routers & exit nodes',
        description: 'Expose a whole LAN through one machine, or route all your traffic through a trusted exit node when you travel.',
        color: '#009688',
      },
      {
        icon: 'mdi-dns-outline',
        title: 'MagicDNS & tunnels',
        description: 'Reach machines by name, forward ports, and run SOCKS5 tunnels into networks only one of your devices can see.',
        color: '#ef5350',
      },
    ],
  },
  {
    title: 'Collaboration included',
    subtitle: 'The team layer is part of every plan — not an add-on',
    features: [
      {
        icon: 'mdi-pound',
        title: 'Rooms, chat & threads',
        description: 'Organized rooms with threaded messaging, reactions, mentions and file attachments.',
        color: '#009688',
      },
      {
        icon: 'mdi-video-outline',
        title: 'HD video conferencing',
        description: 'Built-in SFU for crystal-clear meetings with screen sharing and recordings.',
        color: '#ef5350',
      },
      {
        icon: 'mdi-file-document-outline',
        title: 'Files, cloud & AI',
        description: 'File sharing with versioned uploads, per-room libraries and search.',
        color: '#009688',
      },
    ],
  },
]

/** The install section's copy. Its cards, the wizard among them, come from
 *  `installCards` in `enrollCommands.ts`, which offers the wizard only where it
 *  installs the agent (FR-97 D5). */
export const DOWNLOAD = {
  title: 'Set up a device in minutes',
  lead: 'Paste one command, or on Windows run the graphical installer. Enrollment tokens come from your workspace (Devices → Enroll device).',
}

export const PRICING = {
  title: 'Simple, per-user pricing',
  lead:
    'Free for up to 10 users and 100 devices, and that includes commercial use. ' +
    // FR-115 — no interval or currency named here: each card says what the
    // server has on sale (`/api/stripe/plans`), which a static line cannot.
    'Paid plans are priced per user.',
}

/**
 * Shown before `/api/stripe/plans` answers, or when it cannot: that endpoint
 * is the single source of truth, and both pages replace this with its answer.
 * Keep it in step with the server matrix, or the first paint states a price
 * the checkout will not honour.
 */
export const FALLBACK_PLANS: Plan[] = [
  {
    id: 'free',
    name: 'Free',
    price_cents: 0,
    commercial_use: true,
    features: [
      'Free for commercial use',
      '10 users',
      '100 devices with remote desktop',
      'Private network with MagicDNS',
      '1 remote session at a time',
      'Meetings up to 60 minutes, 10 people',
      'Unlimited chat, 1 GB storage',
    ],
  },
  {
    id: 'pro',
    name: 'Pro',
    price_cents: 800,
    per_seat: true,
    features: [
      'Everything in Free, priced per user',
      '1,000 devices',
      '1 remote session at a time per user',
      'Exit nodes',
      'Meetings with 50 people, no time limit',
      '25 GB of relay traffic per user each month',
      '10 GB storage per user',
    ],
  },
  {
    id: 'business',
    name: 'Business',
    price_cents: 1600,
    per_seat: true,
    features: [
      'Everything in Pro',
      '5,000 devices',
      'Unlimited remote sessions',
      'Meetings with 100 people, and recordings',
      '100 GB of relay traffic per user each month',
      '50 GB storage per user',
      'Priority support',
    ],
  },
]

/** FR-115 — the annual line under a paid price: ten months for twelve. */
export function annualLine(plan: Plan): string | null {
  // A free plan has nothing to save by the year: never "or $0 per user per year".
  if (plan.price_cents <= 0) return null
  const year = (plan.prices || []).find((p) => p.interval === 'year' && p.currency === 'usd')
  if (!year) return null
  const eur = (plan.prices || []).find((p) => p.interval === 'year' && p.currency === 'eur')
  const usd = `$${year.unit_amount / 100}`
  return eur
    ? `or ${usd} / €${eur.unit_amount / 100} per user per year (two months free)`
    : `or ${usd} per user per year (two months free)`
}

export const CTA = {
  title: 'Take your devices with you',
  lead:
    'Free for up to 10 users and 100 devices, commercial use included: ' +
    'remote desktop, a private mesh, tunnels, chat and calls.',
  button: 'Create Your Workspace — Free',
}
