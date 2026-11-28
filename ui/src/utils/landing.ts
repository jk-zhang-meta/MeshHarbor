// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-87 (#1776) — the landing copy, ONE source for the two pages that show it:
 * the SPA's `LandingView.vue` (in-app navigation) and the static homepage the
 * docs generator writes for `/` (what a guest and every crawler get).
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

export const HERO = {
  titleLead: 'Every device you own,',
  titleAccent: 'one secure network',
  lead: 'Remote desktop with screen recording, a private WireGuard-style mesh with SSH and tunnels, and GPU/NPU fleet monitoring — self-hostable and end-to-end encrypted.',
}

/** FR-88 P3: the video section under the capability chips. The video itself is
 *  `FEATURED_VIDEO_ID` in `videos.ts`. */
export const VIDEO_TOUR = {
  title: 'See it in action',
  lead: 'Install the agent on Windows, macOS and Linux, connect from a browser tab, and see what MeshHarbor does that TeamViewer and AnyDesk do, and what they still do better.',
}

export const CAPABILITIES = [
  'Remote desktop',
  'Screen recording',
  'Private mesh network',
  'Tunnels & SOCKS5',
  'Exit nodes',
  'MagicDNS',
  'Zero-config SSH',
  'GPU / NPU fleet',
]

export const PILLARS: LandingPillar[] = [
  {
    title: 'Reach and monitor your fleet',
    subtitle: 'Browser-based remote desktop, recording, and GPU/NPU fleet visibility on one daemon',
    features: [
      {
        icon: 'mdi-monitor-eye',
        title: 'Remote desktop & screen recording',
        description: 'Hardware-encoded H.264/HEVC/AV1/VP9 with sub-100 ms input latency, P2P file transfer, clipboard sync, keep-busy, and full-quality MP4 screen recording.',
        color: '#009688',
      },
      {
        icon: 'mdi-shield-lock-outline',
        title: 'Works behind strict networks',
        description: 'Direct peer-to-peer when possible; TURN relays and WebSocket fallbacks punch through corporate firewalls and full-tunnel VPNs.',
        color: '#ef5350',
      },
      {
        icon: 'mdi-expansion-card',
        title: 'Fleet & GPU/NPU monitoring',
        description: 'Enroll unattended servers and workstations, track live NVIDIA/AMD/Ascend GPU & NPU telemetry with alerts, push updates, and audit every session.',
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
        title: 'MagicDNS, tunnels & SSH',
        description: 'Reach machines by name, open zero-config resumable SSH sessions, forward ports, and run SOCKS5 tunnels into private networks.',
        color: '#ef5350',
      },
    ],
  },
]

/** The install section's copy. Its cards, the wizard among them, come from
 *  `installCards` in `enrollCommands.ts`. */
export const DOWNLOAD = {
  title: 'Set up a device in minutes',
  lead: 'Paste one command, or on Windows run the graphical installer. Enrollment tokens come from your workspace (Devices → Enroll device).',
}

export const CTA = {
  title: 'Take your devices with you',
  lead: 'Remote desktop with recording, a private encrypted mesh, tunnels, SSH, and GPU/NPU fleet monitoring — self-hostable on one lightweight daemon.',
  button: 'Create Your Workspace',
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
  CTA: typeof CTA
}

const EN: LandingCopy = { HERO, VIDEO_TOUR, CAPABILITIES, PILLARS, DOWNLOAD, CTA }

const ZH: LandingCopy = {
  HERO: {
    titleLead: '你的所有设备，',
    titleAccent: '一张安全的网络',
    lead: '浏览器远程桌面与录屏、WireGuard 式私有组网与免配置 SSH/隧道，以及 GPU/NPU 算力集群监控——支持自托管，全程端到端加密。',
  },
  VIDEO_TOUR: {
    title: '看看实际效果',
    lead: '在 Windows、macOS 和 Linux 上装好客户端，从浏览器标签页直接连接。看看 MeshHarbor 能做到 TeamViewer 和 AnyDesk 的哪些事，又有哪些地方它们仍然做得更好。',
  },
  CAPABILITIES: ['远程桌面', '屏幕录制', '私有组网', '隧道与 SOCKS5', '出口节点', 'MagicDNS', '免配置 SSH', 'GPU / NPU 集群'],
  PILLARS: [
    {
      title: '随时连接并掌控你的设备集群',
      subtitle: '集浏览器远程桌面、屏幕录制与 GPU/NPU 算力监控于一体的轻量级守护进程',
      features: [
        {
          ...PILLARS[0]!.features[0]!,
          title: '浏览器远程桌面与录屏',
          description: '硬件编码 H.264/HEVC/AV1/VP9，输入延迟低于 100 毫秒；支持 P2P 文件传输、剪贴板同步、防休眠以及原画质 MP4 录屏。',
        },
        {
          ...PILLARS[0]!.features[1]!,
          title: '严格的网络下也能连',
          description: '能直连就点对点直连；连不上时由 TURN 中继和 WebSocket 兜底，穿过公司防火墙和全局 VPN。',
        },
        {
          ...PILLARS[0]!.features[2]!,
          title: '设备与 GPU/NPU 集群监控',
          description: '无人值守机器一键接入，实时监控 NVIDIA/AMD/昇腾 GPU 与 NPU 指标并配置告警，支持网页推送更新与全量会话审计。',
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
          title: 'MagicDNS、隧道与 SSH',
          description: '按名字访问机器、发起免配置可续传 SSH 会话、转发端口，并通过 SOCKS5 隧道访问私网服务。',
        },
      ],
    },
  ],
  DOWNLOAD: {
    title: '几分钟装好一台设备',
    lead: '粘贴一条命令就行；Windows 上也可以运行图形安装程序。加入用的令牌在你的工作区里生成（设备 → 加入）。',
  },
  CTA: {
    title: '带上你的所有设备',
    lead: '浏览器远程桌面与录屏、端到端加密私有网络、隧道与 SSH 以及 GPU/NPU 集群监控，一套轻量级守护进程即可自托管部署。',
    button: '创建工作区',
  },
}

function isChinese(locale: string): boolean {
  return locale.toLowerCase().startsWith('zh')
}

/** The landing copy in the page's language; anything but Chinese reads English. */
export function landingCopy(locale: string): LandingCopy {
  return isChinese(locale) ? ZH : EN
}
