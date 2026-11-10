// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * RC/RDP Phase C — "改用 RDP" ("Switch to RDP") fallback rules, error-code
 * classification table, viewer-local per-device auto-fallback storage, and
 * desktop bridge detection/invocation.
 */

export const RDP_SCREEN_LOCK_WARNING = 'RDP 会话会锁定远端电脑的本地屏幕'

export const RDP_AUTO_FALLBACK_STORAGE_PREFIX = 'meshharbor:rdp-auto-fallback:v1:'

export type RcErrorSource =
  | 'rc:error'
  | 'rc:terminate'
  | 'rc:media-unavailable'
  | 'client-webrtc'

export interface RcErrorCodeSpec {
  code: string
  source: RcErrorSource
  showRdpCard: boolean
  category:
    | 'technical-signaling-or-agent'
    | 'technical-media-or-capture'
    | 'technical-webrtc-transport'
    | 'user-consent-or-host-stop'
    | 'authorization-or-policy'
    | 'security-or-identity'
    | 'normal-or-subchannel'
  reason: string
}

/**
 * Exhaustive classification of all Remote Control error / termination /
 * media-unavailable codes in the codebase (`crates/modules/remote/src/controller.rs`,
 * `crates/remote_control/src/models.rs`, `agents/meshharbord/src/capture/mod.rs`,
 * and `ui/src/composables/useRemoteControl.ts`).
 */
export const RC_ERROR_CODE_TABLE: readonly RcErrorCodeSpec[] = [
  // ── 1. Eligible technical failures (`showRdpCard = true`) ──────────────────
  // Server `rc:error` technical / signaling / agent state failures
  {
    code: 'agent_offline',
    source: 'rc:error',
    showRdpCard: true,
    category: 'technical-signaling-or-agent',
    reason: 'WebRTC RC 信令通道不可达，但本机 overlay 隧道仍可直连目标 RDP 端口',
  },
  {
    code: 'agent_on_other_pod',
    source: 'rc:error',
    showRdpCard: true,
    category: 'technical-signaling-or-agent',
    reason: '跨实例 RC 信令路由失败，本机 overlay RDP 隧道不依赖该信令实例',
  },
  {
    code: 'session_not_found',
    source: 'rc:error',
    showRdpCard: true,
    category: 'technical-signaling-or-agent',
    reason: 'RC 会话状态丢失或异常中断，可改用 RDP 恢复访问',
  },
  {
    code: 'bad_phase',
    source: 'rc:error',
    showRdpCard: true,
    category: 'technical-signaling-or-agent',
    reason: 'RC 握手状态机异常中断，可改用 RDP',
  },
  {
    code: 'bad_message',
    source: 'rc:error',
    showRdpCard: true,
    category: 'technical-signaling-or-agent',
    reason: 'RC 信令协议消息协商异常，可改用 RDP',
  },
  {
    code: 'send_failed',
    source: 'rc:error',
    showRdpCard: true,
    category: 'technical-signaling-or-agent',
    reason: '服务端向被控端转发 RC 信令失败，可尝试通过本机 overlay 用 RDP 连接',
  },
  {
    code: 'internal',
    source: 'rc:error',
    showRdpCard: true,
    category: 'technical-signaling-or-agent',
    reason: 'RC 内部服务异常，可改用 RDP',
  },
  // `rc:terminate` unexpected technical / codec / disconnect failures
  {
    code: 'no_common_codec',
    source: 'rc:terminate',
    showRdpCard: true,
    category: 'technical-media-or-capture',
    reason: '主控与被控没有共同支持的视频编解码器，无法建立 WebRTC 视频流',
  },
  {
    code: 'error',
    source: 'rc:terminate',
    showRdpCard: true,
    category: 'technical-media-or-capture',
    reason: '远控会话因内部媒体或传输错误意外中断',
  },
  {
    code: 'agent_disconnect',
    source: 'rc:terminate',
    showRdpCard: true,
    category: 'technical-signaling-or-agent',
    reason: '被控端 RC 会话连接意外断开',
  },
  {
    code: 'agent_hangup',
    source: 'rc:terminate',
    showRdpCard: true,
    category: 'technical-signaling-or-agent',
    reason: '被控端采集管线异常退出',
  },
  // `rc:media-unavailable` screen capture / display technical unavailability
  {
    code: 'no_display',
    source: 'rc:media-unavailable',
    showRdpCard: true,
    category: 'technical-media-or-capture',
    reason: '被控端无物理显示器或处于无活动控制台会话（如 Session 0 / 锁屏），无法采集屏幕',
  },
  {
    code: 'not_built',
    source: 'rc:media-unavailable',
    showRdpCard: true,
    category: 'technical-media-or-capture',
    reason: '被控端安装包未编译屏幕采集模块',
  },
  {
    code: 'backend_error',
    source: 'rc:media-unavailable',
    showRdpCard: true,
    category: 'technical-media-or-capture',
    reason: '被控端屏幕采集后端初始化失败（如 DXGI / PipeWire 报错）',
  },
  {
    code: 'wayland_not_enabled',
    source: 'rc:media-unavailable',
    showRdpCard: true,
    category: 'technical-media-or-capture',
    reason: '被控端 Wayland 采集未启用',
  },
  {
    code: 'x11_not_enabled',
    source: 'rc:media-unavailable',
    showRdpCard: true,
    category: 'technical-media-or-capture',
    reason: '被控端 X11 采集未启用',
  },
  {
    code: 'permission',
    source: 'rc:media-unavailable',
    showRdpCard: true,
    category: 'technical-media-or-capture',
    reason: '会话已获准但系统屏幕录制 API 权限缺失，无法采集画面',
  },
  // Client WebRTC / signaling / media stall technical failures
  {
    code: 'connection_timed_out',
    source: 'client-webrtc',
    showRdpCard: true,
    category: 'technical-webrtc-transport',
    reason: 'WebRTC 远控连接建立超时（15 秒未连通）',
  },
  {
    code: 'peer_connection_failed',
    source: 'client-webrtc',
    showRdpCard: true,
    category: 'technical-webrtc-transport',
    reason: 'WebRTC 点对点媒体连接失败（ICE/DTLS 失败）',
  },
  {
    code: 'create_offer_failed',
    source: 'client-webrtc',
    showRdpCard: true,
    category: 'technical-webrtc-transport',
    reason: '浏览器创建 WebRTC Offer 失败',
  },
  {
    code: 'set_remote_description_failed',
    source: 'client-webrtc',
    showRdpCard: true,
    category: 'technical-webrtc-transport',
    reason: 'WebRTC SDP 远端描述协商失败',
  },
  {
    code: 'session_setup_raced_teardown',
    source: 'client-webrtc',
    showRdpCard: true,
    category: 'technical-webrtc-transport',
    reason: '远控会话初始化竞态中断',
  },
  {
    code: 'media_stalled',
    source: 'client-webrtc',
    showRdpCard: true,
    category: 'technical-media-or-capture',
    reason: '远控视频流长时间无帧到达',
  },

  // ── 2. Ineligible codes (`showRdpCard = false`) ────────────────────────────
  // Someone is already using the machine / explicit user rejection / consent timeout / host manually ended session
  {
    code: 'agent_busy',
    source: 'rc:error',
    showRdpCard: false,
    category: 'user-consent-or-host-stop',
    reason: '目标设备当前已有活跃远控会话（active_sessions >= max_sessions），改用 RDP 会接管控制台会话并把正在远控的人和本地用户一起挤掉',
  },
  {
    code: 'consent_denied',
    source: 'rc:terminate',
    showRdpCard: false,
    category: 'user-consent-or-host-stop',
    reason: '远端用户明确拒绝了本次远控请求，不得引导切换 RDP 绕过用户意愿',
  },
  {
    code: 'user_denied',
    source: 'rc:terminate',
    showRdpCard: false,
    category: 'user-consent-or-host-stop',
    reason: '远端用户明确拒绝了连接请求',
  },
  {
    code: 'consent_timeout',
    source: 'rc:terminate',
    showRdpCard: false,
    category: 'user-consent-or-host-stop',
    reason: '远端用户未在规定时间内批准授权弹窗',
  },
  {
    code: 'no_prompt_surface',
    source: 'rc:terminate',
    showRdpCard: false,
    category: 'user-consent-or-host-stop',
    reason: '当前策略要求远端桌面弹窗确认，但远端无交互桌面可显示授权弹窗',
  },
  {
    code: 'host_disconnect',
    source: 'rc:terminate',
    showRdpCard: false,
    category: 'user-consent-or-host-stop',
    reason: '远端被控侧用户主动点击停止了共享会话',
  },
  // Authorization / authentication / rate-limit / plan quota / missing target
  {
    code: 'permission_denied',
    source: 'rc:error',
    showRdpCard: false,
    category: 'authorization-or-policy',
    reason: '当前账号无该设备的远控权限（RBAC 拒绝）',
  },
  {
    code: 'forbidden',
    source: 'rc:error',
    showRdpCard: false,
    category: 'authorization-or-policy',
    reason: '跨租户或策略禁止访问该设备',
  },
  {
    code: 'invalid_token',
    source: 'rc:error',
    showRdpCard: false,
    category: 'authorization-or-policy',
    reason: '登录凭据无效或已过期，需重新登录',
  },
  {
    code: 'rate_limited',
    source: 'rc:error',
    showRdpCard: false,
    category: 'authorization-or-policy',
    reason: '请求过于频繁触发限流',
  },
  {
    code: 'org_session_limit',
    source: 'rc:terminate',
    showRdpCard: false,
    category: 'authorization-or-policy',
    reason: '组织并发会话数已达套餐上限',
  },
  {
    code: 'agent_not_found',
    source: 'rc:error',
    showRdpCard: false,
    category: 'authorization-or-policy',
    reason: '目标设备不存在或已注销',
  },
  // Cryptographic peer identity / external share security failures
  {
    code: 'peer_auth_key_changed',
    source: 'client-webrtc',
    showRdpCard: false,
    category: 'security-or-identity',
    reason: '被控端身份公钥发生变化，存在安全风险，必须阻断而非引导切换协议',
  },
  {
    code: 'peer_auth_bad_signature',
    source: 'client-webrtc',
    showRdpCard: false,
    category: 'security-or-identity',
    reason: '被控端身份签名校验失败，疑似中间人篡改，必须阻断',
  },
  {
    code: 'external_answer_unsealed',
    source: 'client-webrtc',
    showRdpCard: false,
    category: 'security-or-identity',
    reason: '外部连接码会话缺少端到端加密封装，安全校验拒绝',
  },
  {
    code: 'external_login_gone',
    source: 'client-webrtc',
    showRdpCard: false,
    category: 'security-or-identity',
    reason: '外部连接码一次性会话令牌已失效',
  },
  {
    code: 'external_session_ended',
    source: 'client-webrtc',
    showRdpCard: false,
    category: 'security-or-identity',
    reason: '外部连接码会话已结束',
  },
  // Normal user hangup / admin / idle / duration / file-only subchannel
  {
    code: 'controller_hangup',
    source: 'rc:terminate',
    showRdpCard: false,
    category: 'normal-or-subchannel',
    reason: '主控用户自己主动挂断会话',
  },
  {
    code: 'admin_terminated',
    source: 'rc:terminate',
    showRdpCard: false,
    category: 'normal-or-subchannel',
    reason: '管理员在后台强制终止了会话',
  },
  {
    code: 'idle_timeout',
    source: 'rc:terminate',
    showRdpCard: false,
    category: 'normal-or-subchannel',
    reason: '会话长时间无操作自动空闲断开',
  },
  {
    code: 'max_duration',
    source: 'rc:terminate',
    showRdpCard: false,
    category: 'normal-or-subchannel',
    reason: '会话达到最大允许时长',
  },
  {
    code: 'file_child_error',
    source: 'rc:error',
    showRdpCard: false,
    category: 'normal-or-subchannel',
    reason: '仅文件传输子进程报错，不影响屏幕远控主会话',
  },
] as const

const ELIGIBLE_CODE_SET: ReadonlySet<string> = new Set(
  RC_ERROR_CODE_TABLE.filter((entry) => entry.showRdpCard).map((entry) => entry.code),
)

/**
 * Returns `true` iff `code` is an RC failure / media-unavailable code that
 * qualifies for showing the "改用 RDP" card when `rdp_available === true`.
 */
export function isEligibleRdpFallbackErrorCode(code: string | null | undefined): boolean {
  if (!code || typeof code !== 'string') return false
  const normalized = code.trim().toLowerCase()
  if (!normalized) return false
  const stripped = normalized.startsWith('media_unavailable:')
    ? normalized.slice('media_unavailable:'.length)
    : normalized
  return ELIGIBLE_CODE_SET.has(stripped)
}

/**
 * Determines whether the "改用 RDP" card should be displayed.
 *
 * Contract (`V0011-1794327403` §5(b)):
 * - Shown ONLY when `rdpAvailable === true` (never when `false`, `undefined`,
 *   or on Windows Home SKUs) AND the RC session either failed/disconnected with
 *   an eligible error code or reported `rc:media-unavailable` with an eligible
 *   reason.
 */
export function shouldShowRdpFallbackCard(params: {
  phase: string
  errorCode?: string | null
  mediaUnavailableReason?: string | null
  rdpAvailable?: boolean | null
}): boolean {
  if (params.rdpAvailable !== true) {
    return false
  }
  if (params.mediaUnavailableReason && isEligibleRdpFallbackErrorCode(params.mediaUnavailableReason)) {
    return true
  }
  if (params.phase === 'error' && isEligibleRdpFallbackErrorCode(params.errorCode)) {
    return true
  }
  return false
}

function storageKeyForDevice(deviceId: string): string {
  return `${RDP_AUTO_FALLBACK_STORAGE_PREFIX}${deviceId.trim().toLowerCase()}`
}

/**
 * Read the viewer-local per-device "自动改用 RDP" setting from `localStorage`.
 * Defaults to `false`. Never reads any server-pushed field.
 */
export function getDeviceAutoRdpFallback(
  deviceId: string | null | undefined,
  storage: Pick<Storage, 'getItem'> | null = typeof window !== 'undefined' ? window.localStorage : null,
): boolean {
  if (!deviceId || typeof deviceId !== 'string' || !deviceId.trim() || !storage) {
    return false
  }
  try {
    return storage.getItem(storageKeyForDevice(deviceId)) === '1'
  } catch {
    return false
  }
}

/**
 * Update the viewer-local per-device "自动改用 RDP" setting in `localStorage`.
 *
 * Contract (`V0011-1794327403` §5(c)):
 * - Turning it ON (`enabled === true`) requires `confirmedScreenLockWarning === true`
 *   (the user must explicitly confirm the screen-lock warning first). If
 *   `confirmedScreenLockWarning` is `false`, the setting stays `false`.
 */
export function setDeviceAutoRdpFallback(
  deviceId: string | null | undefined,
  enabled: boolean,
  confirmedScreenLockWarning: boolean,
  storage: Pick<Storage, 'setItem' | 'removeItem' | 'getItem'> | null = typeof window !== 'undefined'
    ? window.localStorage
    : null,
): boolean {
  if (!deviceId || typeof deviceId !== 'string' || !deviceId.trim() || !storage) {
    return false
  }
  const key = storageKeyForDevice(deviceId)
  try {
    if (!enabled) {
      storage.removeItem(key)
      return false
    }
    if (!confirmedScreenLockWarning) {
      return getDeviceAutoRdpFallback(deviceId, storage)
    }
    storage.setItem(key, '1')
    return true
  } catch {
    return false
  }
}

interface DesktopBridgeWindow {
  __MESHHARBOR_DESKTOP_BRIDGE__?: {
    openRdp?: (payload: {
      target: string
      org?: string
      port?: number
      certSha256?: string
    }) => Promise<unknown>
  }
  __TAURI__?: {
    core?: {
      invoke?: (cmd: string, args?: Record<string, unknown>) => Promise<unknown>
    }
  }
  __TAURI_INTERNALS__?: {
    invoke?: (cmd: string, args?: Record<string, unknown>) => Promise<unknown>
  }
}

/**
 * Returns `true` when the current page is running inside the desktop app with
 * a bridge capable of invoking `cmd_open_rdp` (Windows WebView2 bridge or
 * Tauri invoke context). Returns `false` in system browsers (macOS/Linux/web).
 */
export function hasDesktopRdpBridge(win: unknown = typeof window !== 'undefined' ? window : null): boolean {
  if (!win || typeof win !== 'object') return false
  const w = win as DesktopBridgeWindow
  if (typeof w.__MESHHARBOR_DESKTOP_BRIDGE__?.openRdp === 'function') {
    return true
  }
  if (typeof w.__TAURI__?.core?.invoke === 'function') {
    return true
  }
  if (typeof w.__TAURI_INTERNALS__?.invoke === 'function') {
    return true
  }
  return false
}

/**
 * Invoke `cmd_open_rdp` over the available desktop bridge.
 * Never passes any password or credential field.
 */
export async function invokeDesktopOpenRdp(
  params: {
    target: string
    org?: string | null
    port?: number | null
    certSha256?: string | null
  },
  win: unknown = typeof window !== 'undefined' ? window : null,
): Promise<void> {
  const target = params.target?.trim()
  if (!target) {
    throw new Error('缺少目标设备标识')
  }
  const w = (win ?? {}) as DesktopBridgeWindow
  const cleanOrg = params.org?.trim() || undefined
  const cleanPort =
    typeof params.port === 'number' && params.port >= 1 && params.port <= 65535
      ? params.port
      : undefined
  const cleanCert = params.certSha256?.trim() || undefined

  if (typeof w.__MESHHARBOR_DESKTOP_BRIDGE__?.openRdp === 'function') {
    await w.__MESHHARBOR_DESKTOP_BRIDGE__.openRdp({
      target,
      org: cleanOrg,
      port: cleanPort,
      certSha256: cleanCert,
    })
    return
  }
  const invokeFn = w.__TAURI__?.core?.invoke ?? w.__TAURI_INTERNALS__?.invoke
  if (typeof invokeFn === 'function') {
    await invokeFn('cmd_open_rdp', {
      target,
      org: cleanOrg ?? null,
      port: cleanPort ?? null,
      certSha256: cleanCert ?? null,
    })
    return
  }
  throw new Error('当前环境无桌面应用桥接，请在桌面应用中打开或使用 mh rdp 命令')
}

/**
 * Format the CLI fallback command `mh rdp <设备名>` for system-browser viewers
 * where no desktop bridge is available.
 */
export function formatMhRdpCommand(deviceNameOrId: string | null | undefined): string {
  const raw = (deviceNameOrId ?? '').trim() || '<设备名>'
  if (/\s/.test(raw) || /["'\\]/.test(raw)) {
    return `mh rdp "${raw.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
  }
  return `mh rdp ${raw}`
}
