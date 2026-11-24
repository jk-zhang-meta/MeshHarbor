// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * MeshHarbor Setup Wizard — plain-JS i18n dictionary (`en` and `zh-CN`).
 *
 * Resolution order matches the web UI (`ui/src/plugins/i18n.ts`):
 *   1. Saved explicit choice (`localStorage['meshharbor.locale']`: 'en' | 'zh-CN').
 *   2. OS / browser locale: any `zh*` (`zh`, `zh-CN`, `zh-Hans`, `zh-TW`, …) → 'zh-CN',
 *      otherwise 'en'.
 */
(function (root) {
  'use strict';

  const STORAGE_KEY = 'meshharbor.locale';
  const LOCALES = [
    { code: 'en', label: 'English', shortLabel: 'EN' },
    { code: 'zh-CN', label: '简体中文', shortLabel: '中文' },
  ];

  const MESSAGES = {
    en: {
      'app.title': 'MeshHarbor Setup',
      'lang.aria': 'Language',

      // Step indicator
      'step.progressAria': 'Wizard progress',
      'step.welcome': 'Welcome',
      'step.server': 'Server',
      'step.token': 'Token',
      'step.install': 'Install',
      'step.done': 'Done',

      // Step 1: Welcome
      'welcome.title': 'MeshHarbor Setup',
      'welcome.lead':
        'One wizard for everything: the always-on daemon (so this machine can be accessed) or the tunnel client (so you can reach others). No terminal commands required.',
      'welcome.detectTitle': 'Detected on this machine',
      'welcome.probing': 'Probing…',
      'welcome.ambiguousWarning':
        "Both perUser and perMachine daemon installs detected. The MSI's cleanup custom action will remove the one not selected.",
      'welcome.roleTitle': 'What should this machine be?',
      'welcome.platformNote':
        'This platform supports the tunnel client only — the daemon roles are Windows-only.',
      'welcome.role.daemonSystem.title': 'Be accessed — background service (pre-logon, recommended)',
      'welcome.role.daemonSystem.desc':
        'Installs for all users and runs as a system service so remote control works on the lock screen, UAC prompts, and admin apps. Requires administrator approval.',
      'welcome.role.daemonMachine.title': 'Be accessed — attended service',
      'welcome.role.daemonMachine.desc':
        'Installs for all users on this PC for signed-in sessions only (no lock-screen or UAC control). Requires administrator approval during install.',
      'welcome.role.daemonUser.title': 'Be accessed — this user only',
      'welcome.role.daemonUser.desc': 'Installs for your account only. No administrator password needed.',
      'welcome.role.tunnelClient.title': 'Reach others only — tunnel client',
      'welcome.role.tunnelClient.descPre': 'Installs the ',
      'welcome.role.tunnelClient.descPost':
        ' CLI and enrolls it, so this machine can forward ports through enrolled agents. No daemon.',
      'welcome.crossFlavourAck':
        'I understand my existing enrollment will be lost; I have a fresh enrollment token from my administrator.',
      'welcome.diagLabelPre': 'Send anonymous setup diagnostics to ',
      'welcome.diagHint':
        'One record per step: which step, whether it passed, how long it took and an error code — never the token, a name, a path or an address. Nothing is sent unless you tick this, and it is not remembered for the next run.',
      'welcome.detect.agentUnsupported': 'Daemon: not available on this platform (Windows-only).',
      'welcome.detect.agentClean': 'Daemon: no existing install detected.',
      'welcome.detect.agentPerUser': 'Daemon: existing perUser install (version {version}).',
      'welcome.detect.agentPerMachine': 'Daemon: existing perMachine install (version {version}).',
      'welcome.detect.agentAmbiguous':
        'Daemon: both flavours installed (perUser {perUser} + perMachine {perMachine}).',
      'welcome.detect.tunnelConfigured':
        'Tunnel client: already configured{machine} at {path}. Continuing will overwrite the enrollment.',
      'welcome.detect.tunnelMachine': ' (machine: {name})',
      'welcome.detect.tunnelNone': 'Tunnel client: not configured on this machine.',
      'welcome.crossFlavour.userToMachine':
        "Switching from perUser → perMachine. Your existing enrollment will be lost; you'll need a fresh enrollment token from your administrator.",
      'welcome.crossFlavour.machineToUser':
        "Switching from perMachine → perUser. Your existing enrollment will be lost; you'll need a fresh enrollment token from your administrator.",
      'welcome.crossFlavour.ambiguous':
        "Both perUser and perMachine installs detected. The MSI's cleanup custom action will remove the one not selected.",
      'welcome.unknown': 'unknown',

      // Role & flavour names
      'role.daemonSystem': 'Background service (pre-logon)',
      'role.daemonMachine': 'Attended service',
      'role.daemonUser': 'This user only',
      'role.tunnelClient': 'Tunnel client',
      'role.none': '(none)',

      // Step 2: Server
      'server.title': 'Server + device',
      'server.lead': 'Where to enroll this machine and what to call it.',
      'server.urlLabel': 'Server URL',
      'server.urlHintPre': 'Production: ',
      'server.deviceLabel': 'Device name',
      'server.deviceHint':
        'Pre-filled from hostname; edit if you want something more memorable (e.g. "Reception PC — ground floor").',
      'server.advancedSummary': 'Advanced options (optional)',
      'server.advFirewall':
        'Allow direct connections on trusted networks (one administrator approval)',
      'server.advFirewallHint':
        'Optional for a per-user install. Prepares this MeshHarbor app for Private and Domain networks before it starts. Your account and the app keep their normal permissions.',
      'server.advFirewallPublic': 'Also allow direct connections on Public networks',
      'server.advOverlay': 'Join the overlay network (private mesh between your devices)',
      'server.advOverlayHint':
        "A per-user daemon runs with limited rights and cannot create the private network's TUN adapter, so it joins through a userspace network stack instead: no system routes and no firewall change. Apps on this machine reach the mesh through a local SOCKS5 proxy; remote desktop needs nothing.",
      'server.advLocalSubnets':
        'Advertise directly-connected subnets (admin approval required before use)',
      'server.advAutoGrant': 'Auto-approve incoming remote-control sessions on this device',
      'server.advOverlayRoutes': 'Overlay subnet routes',
      'server.advOverlayRoutesHint':
        'Comma-separated CIDRs this node offers to route for overlay peers. Leave empty unless this is a subnet router.',
      'server.advTunnelRoutes': 'Tunnel subnet routes',
      'server.advTunnelRoutesHint': 'Comma-separated CIDRs for the tunnel/SOCKS mesh.',

      // Step 3: Token
      'token.title': 'Enrollment token',
      'token.leadDefault': 'Paste a fresh token from the MeshHarbor admin UI.',
      'token.leadTunnel': 'Paste a tunnel-enrollment token from Admin → Tunnels.',
      'token.leadAgent': 'Paste a fresh enrollment token from Admin → Agents.',
      'token.label': 'Token',
      'token.hint': 'Stored only in memory, used once. Never persisted to disk.',
      'token.issuerLabel': 'Issuer:',
      'token.typeLabel': 'Token type:',
      'token.expiryLabel': 'Expires:',
      'token.none': '(none)',
      'token.noExp': '(no exp)',
      'token.expiryAgo': '{stamp} ({mins} min ago)',
      'token.expiryIn': '{stamp} (in {mins} min)',
      'token.anchorYesStrong': 'Also anchors this device for SYSTEM exec.',
      'token.anchorYesRest':
        ' After enrolling, Windows asks for administrator approval a second time, so commands from the dashboard can run as SYSTEM here.',
      'token.anchorNo':
        'This token could also anchor the device for SYSTEM exec, but this install type has no SYSTEM service; it is only used to enroll.',
      'token.warnAudiencePre': 'This is not a tunnel-enrollment token (token type is ',
      'token.warnAudienceMid': "). You'll get one from ",
      'token.warnAudienceNav': 'Admin → Tunnels',
      'token.warnAudiencePost':
        '; the agent-enrollment token from Admin → Agents is a different one.',
      'token.warnExpired': 'This token has already expired. Ask your admin to issue a new one.',
      'token.warnParse':
        'Could not parse this as a JWT. Make sure you copied the whole token (three dot-separated parts).',

      // Step 4: Install
      'install.title': 'Installing',
      'install.summary': 'Installing the {what} from {server} as “{device}”.',
      'install.whatTunnel': 'tunnel client',
      'install.whatDaemon': 'daemon ({flavour})',
      'install.progressLabel': '{received} MB of {total} MB ({pct}%)',
      'install.errorTitle': 'Install failed',
      'install.errorTitleAt': 'Install failed at: {step}',
      'install.forceKillTitle': 'Force-kill the MSI installer?',
      'install.forceKillBody':
        ' This terminates msiexec mid-run and may leave a partial install that needs manual cleanup (re-run this wizard or uninstall from Windows Settings).',
      'install.forceKillBtn': 'Force-kill installer',
      'install.sc.envVarWrite': 'Writing the service env-var failed',
      'install.sc.serviceRestart': 'Restarting the service failed',
      'install.sc.unknown': 'SystemContext step failed',
      'install.sc.other': 'SystemContext ({stage}) failed',
      'install.scRow.envVarWrite': 'Writing service env-var',
      'install.scRow.serviceRestart': 'Restarting service',
      'install.scRow.unknown': 'SystemContext step',
      'install.scRow.other': 'SystemContext ({stage})',
      'install.scRow.failed': '{stage} failed: {message}{hint}',
      'install.step.Started': 'Install started',
      'install.step.PreflightStarted': 'Pre-flight checks',
      'install.step.PreflightOk': 'Pre-flight: detected install',
      'install.step.PreflightWarning': 'Pre-flight warning',
      'install.step.AssetResolving': 'Resolving download URL',
      'install.step.AssetResolved': 'Download URL resolved',
      'install.step.DownloadStarted': 'Downloading',
      'install.step.DownloadVerified': 'Download verified (SHA256)',
      'install.step.MsiSpawned': 'Running MSI installer',
      'install.step.MsiCompleted': 'MSI installer finished',
      'install.step.ExtractStarted': 'Extracting archive',
      'install.step.ExtractDone': 'Archive extracted',
      'install.step.IntegrationStarted': 'Wiring up PATH',
      'install.step.IntegrationDone': 'PATH integration finished',
      'install.step.EnrollStarted': 'Enrolling with MeshHarbor',
      'install.step.EnrollOk': 'Enrolled',
      'install.step.AnchorStarted': 'Anchoring for SYSTEM exec (administrator prompt)',
      'install.step.AnchorOk': 'Anchored for SYSTEM exec',
      'install.step.AnchorSkipped': 'Not anchored',
      'install.step.Done': 'Done',
      'install.step.Error': 'Error',
      'install.step.SystemContextError': 'SystemContext step failed',
      'install.existing.clean': 'not installed',
      'install.existing.perUser': 'existing single-user install ({version})',
      'install.existing.perMachine': 'existing machine-wide install ({version})',
      'install.existing.ambiguous': 'both user and machine installs ({perUser} + {perMachine})',
      'install.existing.installed': 'existing install ({detail})',
      'install.row.preflightOk': 'Pre-flight: detected {existing}',
      'install.row.preflightWarning': '{base}: {message}',
      'install.row.assetResolving': 'Resolving download URL ({artifact})',
      'install.row.assetResolved': 'Resolved tag {tag} ({mb} MB)',
      'install.row.msiSpawned': 'Running MSI installer (PID {pid})',
      'install.row.msiCompleted': 'MSI installer finished (exit {code}, {decoded})',
      'install.row.extractDone': 'Extracted. Binary at {path}',
      'install.row.integrationDone': 'Integration: PATH {pathState}; shortcut {shortcutState}',
      'install.row.pathUpdated': 'updated',
      'install.row.pathUnchanged': 'unchanged',
      'install.row.shortcutCreated': 'created',
      'install.row.shortcutSkipped': 'skipped',
      'install.row.enrollOk': 'Enrolled ({kind} {id})',
      'install.row.anchorSkipped': 'Not anchored: {reason}',
      'install.row.error': 'Error at {step}: {message}',

      // Step 5: Done
      'done.title': 'Done',
      'done.leadDefault': 'Installed and enrolled.',
      'done.leadTunnel': 'The tunnel client is installed, enrolled, and on PATH.',
      'done.leadDaemon': 'The MeshHarbor daemon is installed and enrolled.',
      'done.leadCli': ' The meshharbor CLI came with it (managed by the daemon\'s updater).',
      'done.leadDesktop': ' The meshharbor-desktop app is installed alongside it.',
      'done.leadAnchored': ' It is anchored: commands can run as SYSTEM here.',
      'done.enrolledId': 'Enrolled ID',
      'done.tunnelClientId': 'Tunnel client ID',
      'done.agentId': 'Agent ID',
      'done.tenantId': 'Tenant ID',
      'done.role': 'Role',
      'done.mode': 'Mode',
      'done.binaryPath': 'CLI installed at',
      'done.configPath': 'Config saved to',
      'done.version': 'Version',
      'done.unknownMissing': '(unknown — install report missing)',
      'done.unknown': '(unknown)',
      'done.pathNotePre': 'The ',
      'done.pathNotePost':
        " CLI is on your PATH after you open a new shell. If it isn't found, run it directly via the path above.",
      'done.anchorNoteTitle': 'Not anchored for SYSTEM exec.',
      'done.anchorNoteBody':
        'The install itself is complete. To anchor this device later, run this from an elevated shell, with a fresh enrollment token from the dashboard:',
      'done.scNoteTitle': 'SystemContext mode active.',
      'done.scNoteBodyPre':
        'The perMachine MSI is installed, the daemon is enrolled, and the SCM service runs with ',
      'done.scNoteBodyMid': ' in its ',
      'done.scNoteBodyPost':
        ' block. Remote control can now drive the Windows lock screen, UAC dialogs, and admin apps when an operator connects from the browser.',
      'done.scNoteHintPre': 'To disable SystemContext mode later, run ',
      'done.scNoteHintPost':
        ' from an elevated shell, or re-run this wizard and pick the attended-service role.',

      // Buttons & snackbars
      'btn.cancel': 'Cancel',
      'btn.continue': 'Continue →',
      'btn.back': '← Back',
      'btn.backPlain': 'Back',
      'btn.install': 'Install →',
      'btn.retry': 'Retry',
      'btn.backToStart': '← Back to start',
      'btn.finish': 'Finish',
      'snack.detectFailed': 'Detection failed: {err}',
      'snack.alreadyRunning': 'Wizard is already running — finish the current install first.',
      'snack.cancelRequested': 'Cancellation requested — bailing at the next checkpoint.',
      'snack.cancelFailed': 'Cancel failed: {err}',
      'snack.msiTerminated': 'msiexec terminated. The install may be partial.',
      'snack.forceKillFailed': 'Force-kill failed: {err}',
      'snack.wizardError': 'Wizard error: {err}',
      'snack.initFailed': 'Init failed: {err}',
    },

    'zh-CN': {
      'app.title': 'MeshHarbor 安装向导',
      'lang.aria': '界面语言',

      // Step indicator
      'step.progressAria': '安装步骤',
      'step.welcome': '欢迎',
      'step.server': '服务器',
      'step.token': '令牌',
      'step.install': '安装',
      'step.done': '完成',

      // Step 1: Welcome
      'welcome.title': 'MeshHarbor 安装向导',
      'welcome.lead':
        '一站式安装：常驻守护服务（供其他设备访问本机）或隧道客户端（仅主动连接其他设备）。全程无需终端命令。',
      'welcome.detectTitle': '本机检测结果',
      'welcome.probing': '正在检测…',
      'welcome.ambiguousWarning':
        '同时检测到 perUser 和 perMachine 守护服务安装。MSI 清理操作会自动移除未选中的那一份。',
      'welcome.roleTitle': '希望这台设备担任什么角色？',
      'welcome.platformNote': '当前平台仅支持隧道客户端 —— 守护服务角色仅支持 Windows。',
      'welcome.role.daemonSystem.title': '被访问 —— 后台系统服务（登录前可用，推荐）',
      'welcome.role.daemonSystem.desc':
        '为本机所有用户安装，以系统身份运行，可在锁屏、UAC 弹窗和管理员窗口上远程控制。安装时需要管理员确认。',
      'welcome.role.daemonMachine.title': '被访问 —— 有人值守服务',
      'welcome.role.daemonMachine.desc':
        '为本机所有用户安装，仅在用户登录后可用（不控制锁屏和 UAC 弹窗）。安装时需要管理员确认。',
      'welcome.role.daemonUser.title': '被访问 —— 仅当前用户',
      'welcome.role.daemonUser.desc': '仅为当前账号安装，无需管理员密码。',
      'welcome.role.tunnelClient.title': '仅访问其他设备 —— 隧道客户端',
      'welcome.role.tunnelClient.descPre': '安装并注册 ',
      'welcome.role.tunnelClient.descPost':
        ' CLI，使本机可通过已注册的节点转发端口，不安装守护服务。',
      'welcome.crossFlavourAck':
        '我了解现有设备注册信息会丢失，并且已从管理员处获取了新的注册令牌。',
      'welcome.diagLabelPre': '发送匿名安装诊断信息到 ',
      'welcome.diagHint':
        '每步仅记录一条信息：步骤名称、是否成功、耗时与错误码 —— 绝不包含令牌、设备名、路径或地址。不勾选不会发送任何信息，且不会记住供下次使用。',
      'welcome.detect.agentUnsupported': '守护服务：当前平台不可用（仅支持 Windows）。',
      'welcome.detect.agentClean': '守护服务：未检测到已有安装。',
      'welcome.detect.agentPerUser': '守护服务：检测到已有的 perUser 安装（版本 {version}）。',
      'welcome.detect.agentPerMachine': '守护服务：检测到已有的 perMachine 安装（版本 {version}）。',
      'welcome.detect.agentAmbiguous':
        '守护服务：同时存在两种安装（perUser {perUser} + perMachine {perMachine}）。',
      'welcome.detect.tunnelConfigured':
        '隧道客户端：已在 {path} 配置{machine}。继续安装将覆盖现有注册信息。',
      'welcome.detect.tunnelMachine': '（设备：{name}）',
      'welcome.detect.tunnelNone': '隧道客户端：本机尚未配置。',
      'welcome.crossFlavour.userToMachine':
        '正在从 perUser 切换到 perMachine。现有注册信息会丢失，需要向管理员获取新的注册令牌。',
      'welcome.crossFlavour.machineToUser':
        '正在从 perMachine 切换到 perUser。现有注册信息会丢失，需要向管理员获取新的注册令牌。',
      'welcome.crossFlavour.ambiguous':
        '同时检测到 perUser 和 perMachine 安装。MSI 清理操作会移除未选中的那一份。',
      'welcome.unknown': '未知',

      // Role & flavour names
      'role.daemonSystem': '后台系统服务（登录前可用）',
      'role.daemonMachine': '有人值守服务',
      'role.daemonUser': '仅当前用户',
      'role.tunnelClient': '隧道客户端',
      'role.none': '（无）',

      // Step 2: Server
      'server.title': '服务器与设备',
      'server.lead': '指定要注册到的服务器地址及本机名称。',
      'server.urlLabel': '服务器地址',
      'server.urlHintPre': '正式环境：',
      'server.deviceLabel': '设备名称',
      'server.deviceHint':
        '默认使用主机名，也可以改成更好记的名字（例如“一楼前台电脑”）。',
      'server.advancedSummary': '高级选项（可选）',
      'server.advFirewall': '允许在受信任网络中直连（需一次管理员批准）',
      'server.advFirewallHint':
        'perUser 安装的可选项。在启动前为本 MeshHarbor 应用放行专用网络和域网络。你的账号和应用权限保持不变。',
      'server.advFirewallPublic': '同时也允许在公用网络中直连',
      'server.advOverlay': '加入覆盖网络（设备间的私有 Mesh 组网）',
      'server.advOverlayHint':
        'perUser 守护服务权限有限，无法创建私有网络的 TUN 虚拟网卡，因此改用用户态网络栈加入：不修改系统路由和防火墙。本机其他应用通过本地 SOCKS5 代理访问组网；远程桌面无需额外配置。',
      'server.advLocalSubnets': '通告直连子网（需管理员批准后生效）',
      'server.advAutoGrant': '自动批准发往本机的远程控制会话',
      'server.advOverlayRoutes': '覆盖网络子网路由',
      'server.advOverlayRoutesHint':
        '逗号分隔的 CIDR，表示本节点为覆盖网络对端提供的路由。非子网路由器请留空。',
      'server.advTunnelRoutes': '隧道子网路由',
      'server.advTunnelRoutesHint': '逗号分隔的 CIDR，供隧道 / SOCKS 组网使用。',

      // Step 3: Token
      'token.title': '注册令牌',
      'token.leadDefault': '粘贴从 MeshHarbor 管理界面获取的新注册令牌。',
      'token.leadTunnel': '粘贴从「管理 → 隧道」获取的隧道注册令牌。',
      'token.leadAgent': '粘贴从「管理 → 设备」获取的新设备注册令牌。',
      'token.label': '令牌',
      'token.hint': '仅保存在内存中，使用一次即清除，绝不写入磁盘。',
      'token.issuerLabel': '签发方：',
      'token.typeLabel': '令牌类型：',
      'token.expiryLabel': '过期时间：',
      'token.none': '（无）',
      'token.noExp': '（未设过期时间）',
      'token.expiryAgo': '{stamp}（{mins} 分钟前已过期）',
      'token.expiryIn': '{stamp}（{mins} 分钟后过期）',
      'token.anchorYesStrong': '同时为本机锚定 SYSTEM 命令执行权限。',
      'token.anchorYesRest':
        ' 注册完成后，Windows 会再次请求管理员批准，以便从控制台以 SYSTEM 身份在此运行命令。',
      'token.anchorNo':
        '此令牌也支持为设备锚定 SYSTEM 执行权限，但当前安装类型没有 SYSTEM 服务，仅用于注册。',
      'token.warnAudiencePre': '这不是隧道注册令牌（当前令牌类型为 ',
      'token.warnAudienceMid': '）。请在 ',
      'token.warnAudienceNav': '管理 → 隧道',
      'token.warnAudiencePost':
        ' 中获取；「管理 → 设备」里的节点注册令牌不能混用。',
      'token.warnExpired': '此令牌已过期，请让管理员签发新的令牌。',
      'token.warnParse':
        '无法解析为 JWT。请确认已完整复制整个令牌（由两个点分隔的三段内容）。',

      // Step 4: Install
      'install.title': '正在安装',
      'install.summary': '正在从 {server} 安装{what}，设备名为“{device}”。',
      'install.whatTunnel': '隧道客户端',
      'install.whatDaemon': '守护服务（{flavour}）',
      'install.progressLabel': '已下载 {received} MB / {total} MB（{pct}%）',
      'install.errorTitle': '安装失败',
      'install.errorTitleAt': '安装失败（阶段：{step}）',
      'install.forceKillTitle': '强制结束 MSI 安装程序？',
      'install.forceKillBody':
        ' 这会中途终止 msiexec，可能留下未完成的安装文件并需要手动清理（重新运行本向导，或在 Windows 设置中卸载）。',
      'install.forceKillBtn': '强制结束安装程序',
      'install.sc.envVarWrite': '写入服务环境变量失败',
      'install.sc.serviceRestart': '重启服务失败',
      'install.sc.unknown': 'SystemContext 步骤失败',
      'install.sc.other': 'SystemContext（{stage}）失败',
      'install.scRow.envVarWrite': '写入服务环境变量',
      'install.scRow.serviceRestart': '重启服务',
      'install.scRow.unknown': 'SystemContext 步骤',
      'install.scRow.other': 'SystemContext（{stage}）',
      'install.scRow.failed': '{stage}失败：{message}{hint}',
      'install.step.Started': '开始安装',
      'install.step.PreflightStarted': '运行安装前检查',
      'install.step.PreflightOk': '安装前检查：已检测本机环境',
      'install.step.PreflightWarning': '安装前警告',
      'install.step.AssetResolving': '正在解析下载地址',
      'install.step.AssetResolved': '已解析下载地址',
      'install.step.DownloadStarted': '正在下载',
      'install.step.DownloadVerified': '下载校验通过（SHA256）',
      'install.step.MsiSpawned': '正在运行 MSI 安装程序',
      'install.step.MsiCompleted': 'MSI 安装程序已完成',
      'install.step.ExtractStarted': '正在解压安装包',
      'install.step.ExtractDone': '安装包解压完成',
      'install.step.IntegrationStarted': '正在配置 PATH',
      'install.step.IntegrationDone': 'PATH 配置完成',
      'install.step.EnrollStarted': '正在注册到 MeshHarbor',
      'install.step.EnrollOk': '注册成功',
      'install.step.AnchorStarted': '正在锚定 SYSTEM 执行权限（需管理员确认）',
      'install.step.AnchorOk': '已完成 SYSTEM 执行权限锚定',
      'install.step.AnchorSkipped': '未锚定',
      'install.step.Done': '完成',
      'install.step.Error': '出错',
      'install.step.SystemContextError': 'SystemContext 步骤失败',
      'install.existing.clean': '未安装',
      'install.existing.perUser': '已有单用户安装（{version}）',
      'install.existing.perMachine': '已有全机安装（{version}）',
      'install.existing.ambiguous': '同时存在单用户与全机安装（{perUser} + {perMachine}）',
      'install.existing.installed': '已有安装（{detail}）',
      'install.row.preflightOk': '安装前检查：检测到{existing}',
      'install.row.preflightWarning': '{base}：{message}',
      'install.row.assetResolving': '正在解析下载地址（{artifact}）',
      'install.row.assetResolved': '已解析版本 {tag}（{mb} MB）',
      'install.row.msiSpawned': '正在运行 MSI 安装程序（PID {pid}）',
      'install.row.msiCompleted': 'MSI 安装程序已完成（退出码 {code}，{decoded}）',
      'install.row.extractDone': '解压完成，程序位于 {path}',
      'install.row.integrationDone': '环境集成：PATH {pathState}；快捷方式{shortcutState}',
      'install.row.pathUpdated': '已更新',
      'install.row.pathUnchanged': '未变化',
      'install.row.shortcutCreated': '已创建',
      'install.row.shortcutSkipped': '已跳过',
      'install.row.enrollOk': '已注册（{kind} {id}）',
      'install.row.anchorSkipped': '未锚定：{reason}',
      'install.row.error': '阶段 {step} 出错：{message}',

      // Step 5: Done
      'done.title': '安装完成',
      'done.leadDefault': '已完成安装并成功注册。',
      'done.leadTunnel': '隧道客户端已安装、完成注册并加入 PATH。',
      'done.leadDaemon': 'MeshHarbor 守护服务已安装并完成注册。',
      'done.leadCli': ' 同时已附带安装 meshharbor CLI（由守护服务的更新器统一管理）。',
      'done.leadDesktop': ' 同时已安装 meshharbor-desktop 桌面端应用。',
      'done.leadAnchored': ' 已完成锚定：控制台可以在此以 SYSTEM 身份运行命令。',
      'done.enrolledId': '注册 ID',
      'done.tunnelClientId': '隧道客户端 ID',
      'done.agentId': '设备 ID',
      'done.tenantId': '组织 ID',
      'done.role': '角色',
      'done.mode': '模式',
      'done.binaryPath': 'CLI 安装路径',
      'done.configPath': '配置文件路径',
      'done.version': '版本',
      'done.unknownMissing': '（未知 —— 缺少安装报告）',
      'done.unknown': '（未知）',
      'done.pathNotePre': '重新打开终端后即可在 PATH 中直接使用 ',
      'done.pathNotePost': ' CLI。若找不到命令，可直接运行上方显示的路径。',
      'done.anchorNoteTitle': '尚未锚定 SYSTEM 执行权限。',
      'done.anchorNoteBody':
        '安装本身已经完成。如需稍后为本机锚定，请在管理员终端中使用从控制台获取的新注册令牌运行以下命令：',
      'done.scNoteTitle': 'SystemContext 模式已启用。',
      'done.scNoteBodyPre': '已安装 perMachine MSI，守护服务已注册，SCM 服务已将 ',
      'done.scNoteBodyMid': ' 写入 ',
      'done.scNoteBodyPost':
        ' 环境变量块。现在通过浏览器远程控制时，可正常操作 Windows 锁屏界面、UAC 弹窗和管理员应用。',
      'done.scNoteHintPre': '如需日后关闭 SystemContext 模式，请在管理员终端运行 ',
      'done.scNoteHintPost': '，或重新运行本向导并选择“有人值守服务”角色。',

      // Buttons & snackbars
      'btn.cancel': '取消',
      'btn.continue': '继续 →',
      'btn.back': '← 返回',
      'btn.backPlain': '返回',
      'btn.install': '开始安装 →',
      'btn.retry': '重试',
      'btn.backToStart': '← 返回开始',
      'btn.finish': '完成',
      'snack.detectFailed': '检测失败：{err}',
      'snack.alreadyRunning': '安装向导已在运行中 —— 请先完成当前安装。',
      'snack.cancelRequested': '已请求取消 —— 将在下一个检查点中止。',
      'snack.cancelFailed': '取消失败：{err}',
      'snack.msiTerminated': '已终止 msiexec，安装可能不完整。',
      'snack.forceKillFailed': '强制结束失败：{err}',
      'snack.wizardError': '向导出错：{err}',
      'snack.initFailed': '初始化失败：{err}',
    },
  };

  function normalizeLang(raw) {
    if (typeof raw !== 'string') return null;
    const norm = raw.trim().replace('_', '-').toLowerCase();
    if (norm === 'en') return 'en';
    if (norm === 'zh-cn') return 'zh-CN';
    return null;
  }

  function detectOsLang(locales) {
    let langs;
    if (Array.isArray(locales)) {
      langs = locales;
    } else if (typeof locales === 'string') {
      langs = [locales];
    } else if (typeof navigator !== 'undefined') {
      langs =
        Array.isArray(navigator.languages) && navigator.languages.length
          ? navigator.languages
          : [navigator.language || ''];
    } else {
      return 'en';
    }
    return langs.some((l) => typeof l === 'string' && l.trim().toLowerCase().startsWith('zh'))
      ? 'zh-CN'
      : 'en';
  }

  function readSavedLang() {
    try {
      return normalizeLang(typeof localStorage !== 'undefined' ? localStorage.getItem(STORAGE_KEY) : null);
    } catch (_) {
      return null;
    }
  }

  let currentLang = readSavedLang() || detectOsLang();

  function t(key, params) {
    const table = MESSAGES[currentLang] || MESSAGES.en;
    let str = Object.prototype.hasOwnProperty.call(table, key)
      ? table[key]
      : Object.prototype.hasOwnProperty.call(MESSAGES.en, key)
        ? MESSAGES.en[key]
        : key;
    if (params && typeof str === 'string') {
      str = str.replace(/\{(\w+)\}/g, (_, k) =>
        Object.prototype.hasOwnProperty.call(params, k) && params[k] != null ? String(params[k]) : '',
      );
    }
    return str;
  }

  function syncLangButtons(container) {
    const scope = container || (typeof document !== 'undefined' ? document : null);
    if (!scope || !scope.querySelectorAll) return;
    scope.querySelectorAll('[data-lang-btn]').forEach((btn) => {
      const active = btn.dataset.langBtn === currentLang;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
  }

  function applyI18n(container) {
    const scope = container || (typeof document !== 'undefined' ? document : null);
    if (!scope) return;
    if (typeof document !== 'undefined') {
      document.documentElement.lang = currentLang;
      const titleEl = document.querySelector('title[data-i18n]');
      if (titleEl) document.title = t(titleEl.dataset.i18n);
    }
    if (scope.querySelectorAll) {
      scope.querySelectorAll('[data-i18n]').forEach((el) => {
        if (el.tagName === 'TITLE') return;
        el.textContent = t(el.dataset.i18n);
      });
      scope.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
        el.placeholder = t(el.dataset.i18nPlaceholder);
      });
      scope.querySelectorAll('[data-i18n-title]').forEach((el) => {
        el.title = t(el.dataset.i18nTitle);
      });
      scope.querySelectorAll('[data-i18n-aria-label]').forEach((el) => {
        el.setAttribute('aria-label', t(el.dataset.i18nAriaLabel));
      });
    }
    syncLangButtons(scope);
  }

  function getLang() {
    return currentLang;
  }

  function setLang(lang) {
    const next = normalizeLang(lang);
    if (!next) return currentLang;
    currentLang = next;
    try {
      if (typeof localStorage !== 'undefined') localStorage.setItem(STORAGE_KEY, next);
    } catch (_) {
      /* storage unavailable */
    }
    if (typeof document !== 'undefined') {
      applyI18n(document);
      document.dispatchEvent(new CustomEvent('meshharbor:lang', { detail: next }));
    }
    return currentLang;
  }

  function wireLangToggles(container) {
    const scope = container || (typeof document !== 'undefined' ? document : null);
    if (!scope || !scope.querySelectorAll) return;
    scope.querySelectorAll('[data-lang-btn]').forEach((btn) => {
      if (btn.dataset.langWired) return;
      btn.dataset.langWired = '1';
      btn.addEventListener('click', () => setLang(btn.dataset.langBtn));
    });
    syncLangButtons(scope);
  }

  if (typeof document !== 'undefined') {
    document.documentElement.lang = currentLang;
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        applyI18n(document);
        wireLangToggles(document);
      });
    } else {
      applyI18n(document);
      wireLangToggles(document);
    }
  }

  const api = {
    LOCALES,
    MESSAGES,
    STORAGE_KEY,
    normalizeLang,
    detectOsLang,
    t,
    applyI18n,
    getLang,
    setLang,
    syncLangButtons,
    wireLangToggles,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.MeshHarborSetupI18n = api;
  }
})(typeof window !== 'undefined' ? window : globalThis);
