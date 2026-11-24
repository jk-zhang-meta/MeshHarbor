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
export function annualLine(plan: Plan, locale = 'en'): string | null {
  // A free plan has nothing to save by the year: never "or $0 per user per year".
  if (plan.price_cents <= 0) return null
  const year = (plan.prices || []).find((p) => p.interval === 'year' && p.currency === 'usd')
  if (!year) return null
  const eur = (plan.prices || []).find((p) => p.interval === 'year' && p.currency === 'eur')
  const usd = `$${year.unit_amount / 100}`
  if (isChinese(locale)) {
    return eur
      ? `或 ${usd} / €${eur.unit_amount / 100} 每用户每年（相当于送两个月）`
      : `或 ${usd} 每用户每年（相当于送两个月）`
  }
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

/*
 * The same page in Chinese (2026-11-24: the product speaks English and Chinese).
 * The English constants above stay as they are: the static homepage the docs
 * generator writes reads them, and that site is English only.
 */

export interface LandingCopy {
  HERO: typeof HERO
  VIDEO_TOUR: typeof VIDEO_TOUR
  CAPABILITIES: string[]
  PILLARS: LandingPillar[]
  DOWNLOAD: typeof DOWNLOAD
  PRICING: typeof PRICING
  CTA: typeof CTA
}

const EN: LandingCopy = { HERO, VIDEO_TOUR, CAPABILITIES, PILLARS, DOWNLOAD, PRICING, CTA }

const ZH: LandingCopy = {
  HERO: {
    titleLead: '你的每一台设备，',
    titleAccent: '连成一张安全的网络',
    lead: '在任何浏览器里远程桌面，设备之间组成类似 WireGuard 的私有网络，团队聊天和视频会议也一并包含。',
  },
  VIDEO_TOUR: {
    title: '看看实际效果',
    lead: '在 Windows、macOS 和 Linux 上装好客户端，从浏览器标签页直接连接。看看 MeshHarbor 能做到 TeamViewer 和 AnyDesk 的哪些事，又有哪些地方它们仍然做得更好。',
  },
  CAPABILITIES: ['远程桌面', '私有组网', '隧道与 SOCKS5', '出口节点', 'MagicDNS', '含聊天与视频会议'],
  PILLARS: [
    {
      title: '连上你的任何一台设备',
      subtitle: '类似 TeamViewer 的远程桌面，直接在浏览器里用',
      features: [
        {
          ...PILLARS[0]!.features[0]!,
          title: '浏览器里的远程桌面',
          description: '硬件编码 H.264/HEVC/VP9，输入延迟低于 100 毫秒。控制端不用装任何软件，Chromium 内核的浏览器都能用。',
        },
        {
          ...PILLARS[0]!.features[1]!,
          title: '严格的网络下也能连',
          description: '能直连就点对点直连；连不上时由 TURN 中继和 WebSocket 兜底，穿过公司防火墙和全局 VPN。',
        },
        {
          ...PILLARS[0]!.features[2]!,
          title: '自带设备管理',
          description: '无人值守的机器也能加入；从网页推送更新、传文件和剪贴板，每次会话都有审计记录。',
        },
      ],
    },
    {
      title: '你自己的私有网络',
      subtitle: '类似 Tailscale 的覆盖网络，连通你加入的每一台设备',
      features: [
        {
          ...PILLARS[1]!.features[0]!,
          title: 'WireGuard 式组网',
          description: '每台设备都有固定的私有地址。流量靠 NAT 打洞在机器之间直接传输，全程端到端加密。',
        },
        {
          ...PILLARS[1]!.features[1]!,
          title: '子网路由与出口节点',
          description: '通过一台机器把整个局域网接进来；出门在外时，也可以让全部流量走一个可信的出口节点。',
        },
        {
          ...PILLARS[1]!.features[2]!,
          title: 'MagicDNS 与隧道',
          description: '按名字访问机器、转发端口，还能开 SOCKS5 隧道，进入只有某一台设备才连得到的网络。',
        },
      ],
    },
    {
      title: '协作功能已包含在内',
      subtitle: '团队协作是每个套餐都有的，不是另外付费的插件',
      features: [
        {
          ...PILLARS[2]!.features[0]!,
          title: '房间、聊天与话题',
          description: '按房间组织，支持话题回复、表情回应、@提及和文件附件。',
        },
        {
          ...PILLARS[2]!.features[1]!,
          title: '高清视频会议',
          description: '内置 SFU，会议清晰流畅，支持屏幕共享和录制。',
        },
        {
          ...PILLARS[2]!.features[2]!,
          title: '文件、云端与 AI',
          description: '文件共享，支持多版本上传、每个房间各自的文件库和搜索。',
        },
      ],
    },
  ],
  DOWNLOAD: {
    title: '几分钟装好一台设备',
    lead: '粘贴一条命令就行；Windows 上也可以运行图形安装程序。加入用的令牌在你的工作区里生成（设备 → 加入）。',
  },
  PRICING: {
    title: '简单的按人计费',
    lead: '最多 10 名用户、100 台设备免费，商业用途也免费。付费套餐按用户数计费。',
  },
  CTA: {
    title: '带上你的所有设备',
    lead: '最多 10 名用户、100 台设备免费，商业用途也包括在内：远程桌面、私有网络、隧道、聊天和通话。',
    button: '免费创建工作区',
  },
}

function isChinese(locale: string): boolean {
  return locale.toLowerCase().startsWith('zh')
}

/** The landing copy in the page's language; anything but Chinese reads English. */
export function landingCopy(locale: string): LandingCopy {
  return isChinese(locale) ? ZH : EN
}

const PLAN_NAMES_ZH: Record<string, string> = { free: '免费版', pro: '专业版', business: '商业版' }

/** The plan lines the server sends (`/api/stripe/plans`), in Chinese. */
const PLAN_FEATURES_ZH: Record<string, string> = {
  'Free for commercial use': '商业用途免费',
  '10 users': '10 名用户',
  '100 devices with remote desktop': '100 台设备，含远程桌面',
  'Private network with MagicDNS': '私有网络与 MagicDNS',
  '1 remote session at a time': '同时 1 个远程会话',
  'Meetings up to 60 minutes, 10 people': '会议最长 60 分钟，最多 10 人',
  'Unlimited chat, 1 GB storage': '聊天不限量，1 GB 存储',
  'Everything in Free, priced per user': '包含免费版的全部功能，按用户计费',
  '1,000 devices': '1,000 台设备',
  '1 remote session at a time per user': '每位用户同时 1 个远程会话',
  'Exit nodes': '出口节点',
  'Meetings with 50 people, no time limit': '会议最多 50 人，不限时长',
  '25 GB of relay traffic per user each month': '每位用户每月 25 GB 中继流量',
  '10 GB storage per user': '每位用户 10 GB 存储',
  'Everything in Pro': '包含专业版的全部功能',
  '5,000 devices': '5,000 台设备',
  'Unlimited remote sessions': '远程会话不限数量',
  'Meetings with 100 people, and recordings': '会议最多 100 人，可录制',
  '100 GB of relay traffic per user each month': '每位用户每月 100 GB 中继流量',
  '50 GB storage per user': '每位用户 50 GB 存储',
  'Priority support': '优先支持',
}

/** A plan's name in the page's language. A plan this table does not know keeps the server's name. */
export function planName(plan: Plan, locale: string): string {
  return (isChinese(locale) && PLAN_NAMES_ZH[plan.id]) || plan.name
}

/** One plan line in the page's language. A line this table does not know stays as the server sent it. */
export function planFeature(line: string, locale: string): string {
  return (isChinese(locale) && PLAN_FEATURES_ZH[line]) || line
}
