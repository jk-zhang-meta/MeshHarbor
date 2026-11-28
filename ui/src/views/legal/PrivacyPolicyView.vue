<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-theme-provider theme="light">
    <div class="legal-page">
      <v-container class="legal-container py-6 py-md-12 px-4 px-md-6">
        <router-link to="/landing" class="text-body-2 text-primary text-decoration-none d-inline-flex align-center mb-6">
          <v-icon size="small" class="mr-1">mdi-arrow-left</v-icon>
          Back to home
        </router-link>

        <h1 class="text-h4 text-md-h3 font-weight-bold mb-2">Privacy Policy</h1>
        <p class="text-body-2 legal-muted mb-8">Last updated: November 2026</p>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">1. Introduction</h2>
          <p class="text-body-1 legal-muted mb-4">
            MeshHarbor ("MeshHarbor," "we," "us," or "our") is operated by <strong>G ROX EOOD</strong>, which is the
            data controller for the processing described here — see our
            <router-link to="/imprint" class="text-primary">Imprint</router-link> for full company details.
            This policy explains what we collect, why, and what we deliberately do not collect, when you use
            <a href="https://meshharbor.itachi.fans" class="text-primary">meshharbor.itachi.fans</a>.
          </p>
          <p class="text-body-1 legal-muted">
            MeshHarbor combines <strong>remote desktop</strong> (with peer-to-peer file transfer and device-side
            screen recording), a <strong>private encrypted mesh network</strong> (with tunnels, subnet routers, exit
            nodes and SSH), and <strong>GPU/NPU fleet monitoring</strong>. Each collects different operational
            metadata, and section 3 is the one worth reading first — it describes the categories of data that never
            reach us at all.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">2. Information We Collect</h2>

          <h3 class="text-h6 font-weight-bold mb-2">2.1 Account Information</h3>
          <p class="text-body-1 legal-muted mb-4">
            When you create an account, we collect your email address, display name, username, and optionally a
            profile avatar. This information is necessary to provide you with access to the platform and to
            identify you within your workspaces.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.2 Tenant and Workspace Data</h3>
          <p class="text-body-1 legal-muted mb-4">
            We collect data related to the tenants (workspaces) you create or join, including workspace names,
            settings, membership roles, network zone definitions, access-control rules, and invite links.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.3 Sign-In Provider Data</h3>
          <p class="text-body-1 legal-muted mb-4">
            When you sign in using Google or another configured OAuth provider, we receive your email address,
            display name, and profile picture from the respective provider. We do not receive or store your
            passwords from these services. We use this information solely to create and authenticate your MeshHarbor
            account. Where a provider does not confirm that it has verified an email address, we record the claim
            separately and do not treat it as proof of ownership of that address.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.4 Devices You Enroll</h3>
          <p class="text-body-1 legal-muted mb-4">
            When you enroll a device, we store a record of it so it can be addressed on your private network and
            shown in your workspace: a machine identifier, the device name you choose, its operating system,
            the agent version, its assigned address on the private network, its public key for the encrypted
            network, which user enrolled and owns it, and how it was installed (the setup wizard, an install
            script or by hand, and for the whole machine or one user). The agent reports periodic status so the workspace can
            show whether a device is online, together with capability information (for example which video
            encoders and displays it has) and, where GPU/NPU monitoring is enabled for a server, hardware utilization
            and alert telemetry.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.5 Network and Connection Data</h3>
          <p class="text-body-1 legal-muted mb-4">
            To connect two devices directly wherever possible, the agent and our servers exchange candidate
            network addresses — including public and local IP addresses and ports — and measurements about which
            paths work. We keep connection diagnostics (which route was chosen, latency, packet loss, whether a
            relay was needed) to operate the network and to investigate faults. For a remote-desktop session we
            also note the kind of path it used — direct, through a relay, or through the private network — with
            the session's own record, and we count sessions by path, per day and without naming anyone, to
            measure remote-desktop quality. This is metadata about connections; it is not the contents of them.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.6 Access and Audit Records</h3>
          <p class="text-body-1 legal-muted mb-4">
            Because this platform grants access to real machines, we record access <em>events</em> so that you can
            audit them: who started a remote-desktop session and against which device; who ran a command or
            requested an SSH session and whether it was permitted or refused; who opened a tunnel; and
            administrative changes within a workspace. Devices may additionally report their own account of a
            session (that a shell opened, that a file transfer occurred, that a forward was allowed or refused),
            which is stored separately from our own records because a device's self-report and our decision are
            different kinds of evidence. Command text is truncated and passed through a filter intended to
            remove credentials before it leaves the device.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.7 Diagnostics, Crash Reports and Logs</h3>
          <p class="text-body-1 legal-muted mb-4">
            If the agent crashes it may send us a report containing the reason, the agent version, the operating
            system, the device hostname, the process identifier and a short tail of its own log. You can also
            choose to upload agent logs when reporting a problem. Agent logs describe the software's behaviour —
            connections, errors, decisions — and are not a record of what you did inside a session.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.8 Notifications and Email</h3>
          <p class="text-body-1 legal-muted mb-4">
            If you enable browser push notifications, we store the subscription your browser issues so we can
            deliver them. We send service email (account verification, invitations, and security or GPU alert
            notices) through an email delivery provider.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.9 Diagnostics and Session Feedback</h3>
          <p class="text-body-1 legal-muted mb-4">
            The setup wizard can send <strong>anonymous setup diagnostics</strong> if you tick the box on its first
            page; it is unticked by default and not remembered for the next run. If you do, it sends one record per
            step of the install: the step's name, whether it passed, failed or was cancelled, how long it took, a
            short error code from a fixed list when it failed, the operating system family and the wizard's version
            — under a random identifier for that run. The records go to the server you enroll into: a self-hosted
            server receives its own and sends nothing to us.
          </p>
          <p class="text-body-1 legal-muted mb-4">
            After a remote-desktop session of thirty seconds or more, the viewer may ask how it went: a thumbs
            up or down and, if you like, one or more reasons from a fixed list (lag, picture, mouse or
            keyboard, couldn't connect, something else). It asks <strong>at most once a day</strong>, you can
            dismiss it, and there is no text field. A self-hosted server keeps its own ratings and sends none to us,
            and its administrator can switch the question off entirely.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">3. What We Deliberately Do Not See</h2>
          <p class="text-body-1 legal-muted mb-4">
            This is the most important section of this policy, and it is a design property of the product rather
            than a promise about our intentions.
          </p>
          <p class="text-body-1 legal-muted mb-2">
            For remote desktop, SSH and the private network, <strong>our servers coordinate connections but do not
            carry readable data</strong>. The two devices exchange the information needed to find each other, and
            then talk to each other directly. Where a direct path is impossible — a restrictive firewall, for
            example — traffic falls back to a relay, and that relay only ever moves data that is already encrypted
            end to end between your devices. Concretely, we do not receive:
          </p>
          <ul class="text-body-1 legal-muted ml-6 mb-4">
            <li class="mb-1">The contents of a remote-desktop session — the screen you view, or the keystrokes and mouse input you send</li>
            <li class="mb-1">Screen recordings — recorded directly on the device and transferred peer-to-peer when downloaded, never stored on the server</li>
            <li class="mb-1">Anything typed into, or printed by, an SSH or remote shell session</li>
            <li class="mb-1">Files transferred between your devices over remote control or the private network</li>
            <li class="mb-1">The contents of traffic routed through a tunnel, a subnet router or an exit node</li>
            <li class="mb-1">Clipboard contents synchronised during a session</li>
          </ul>
          <p class="text-body-1 legal-muted">
            We deliberately do not record session content on the server even though we operate the signalling:
            recording a terminal or screen server-side would mean shipping whatever an operator typed — passwords
            included — off the machine, which is precisely the property this design exists to avoid. What we do keep
            is the <em>metadata</em> in sections 2.5 and 2.6: that a session happened, between whom, and when.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">4. Cookies and Local Storage</h2>
          <p class="text-body-1 legal-muted mb-4">
            Your browser session is held in a <strong>cookie that JavaScript cannot read</strong> (an
            <code>HttpOnly</code> cookie), sent over HTTPS. This is deliberate: a session token readable by page
            scripts can be stolen by any cross-site scripting flaw, so we do not put one there.
          </p>
          <p class="text-body-1 legal-muted">
            Your browser's local storage holds only non-credential conveniences — a flag recording that you appear
            to be signed in, so the app knows which screen to show, and interface preferences such as table column
            choices. We also maintain a WebSocket connection for real-time device status, signalling and notifications.
            We do not use third-party tracking cookies.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">5. How We Use Your Information</h2>
          <p class="text-body-1 legal-muted mb-2">We use the information we collect to:</p>
          <ul class="text-body-1 legal-muted ml-6 mb-2">
            <li class="mb-1">Provide, maintain, and improve the MeshHarbor platform</li>
            <li class="mb-1">Authenticate your identity and manage your account</li>
            <li class="mb-1">Establish connections between your devices and route them over the private network</li>
            <li class="mb-1">Enforce the access rules you configure, and give you an audit trail of who reached what</li>
            <li class="mb-1">Deliver GPU/NPU fleet telemetry and alerts you configure</li>
            <li class="mb-1">Send service-related communications (e.g., account verification, security alerts)</li>
            <li class="mb-1">Diagnose faults, monitor performance and reliability, and detect abuse</li>
            <li class="mb-1">Comply with legal obligations</li>
          </ul>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">6. Data Sharing and Disclosure</h2>
          <p class="text-body-1 legal-muted mb-2">
            We do not sell your personal data. We may share your information only in the following circumstances:
          </p>
          <ul class="text-body-1 legal-muted ml-6 mb-2">
            <li class="mb-1"><strong>With workspace members:</strong> Your profile information is visible to members of the same workspace. Device names, their status, GPU telemetry and audit records are visible according to workspace roles and permissions.</li>
            <li class="mb-1"><strong>Between your own devices:</strong> Devices on the same private network learn each other's addresses and public keys — that is how the network functions.</li>
            <li class="mb-1"><strong>Service providers:</strong> Where configured, an email delivery provider for service email and infrastructure providers for hosting, bound by data processing agreements.</li>
            <li class="mb-1"><strong>Legal requirements:</strong> We may disclose information if required by law, regulation, legal process, or governmental request. Note that for session and network contents there is nothing for us to disclose — see section 3.</li>
            <li class="mb-1"><strong>Business transfers:</strong> In the event of a merger, acquisition, or sale of assets, your data may be transferred as part of that transaction.</li>
          </ul>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">7. Data Retention</h2>
          <p class="text-body-1 legal-muted mb-2">
            We retain your account data for as long as your account is active. Beyond that:
          </p>
          <ul class="text-body-1 legal-muted ml-6 mb-2">
            <li class="mb-1">Access and audit records — the audit trail of remote sessions, command execution, SSH decisions and device-reported activity — are deleted automatically <strong>90 days</strong> after they are written.</li>
            <li class="mb-1">The record of a remote-desktop session itself — who controlled which device, when, for how long, its connection quality and the kind of network path it used — is deleted automatically <strong>25 months</strong> after the session began. Daily counts derived from these records name no one and are kept.</li>
            <li class="mb-1">Short-lived operational data such as connection diagnostics is deleted automatically on a shorter cycle, typically <strong>7 days</strong>. Crash reports (2.7) are deleted automatically <strong>30 days</strong> after we receive them.</li>
            <li class="mb-1">Enrollment tokens and similar one-time credentials expire within minutes to hours. The record that an administrator issued one, and whether a device used it — never the token itself — is deleted automatically after <strong>90 days</strong>.</li>
            <li class="mb-1">Setup diagnostics sent with your consent (2.9) are deleted automatically <strong>90 days</strong> after they are written.</li>
            <li class="mb-1">A rating you give a remote-desktop session from the viewer (2.9) is kept for <strong>25 months</strong> and deleted with your account.</li>
          </ul>
          <p class="text-body-1 legal-muted">
            These deletions are enforced by the database itself rather than by a manual process. When you delete
            your account, we will remove your personal data within 30 days, except where retention is required by
            law.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">8. Data Security</h2>
          <p class="text-body-1 legal-muted">
            We implement industry-standard security measures, including encrypted connections (TLS/HTTPS),
            secure WebSocket connections, encrypted media streams, modern encryption between devices on the
            private network, signed and verified agent updates, and access controls that deny by default. Access
            to devices is gated independently at several layers, and the last of them is a setting held on the
            device itself: by default our servers cannot change it, so a compromise of our systems does not by
            itself open a device. A device's administrator may choose to delegate that setting to us, but that is
            their decision to make and it is off unless they make it. While we strive to protect your information,
            no method of electronic transmission or storage is 100% secure, and we cannot guarantee absolute
            security.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">9. Your Rights (GDPR and Global Privacy)</h2>
          <p class="text-body-1 legal-muted mb-2">
            Depending on your jurisdiction, you may have the following rights regarding your personal data:
          </p>
          <ul class="text-body-1 legal-muted ml-6 mb-2">
            <li class="mb-1"><strong>Access:</strong> Request a copy of the personal data we hold about you.</li>
            <li class="mb-1"><strong>Rectification:</strong> Request correction of inaccurate or incomplete data.</li>
            <li class="mb-1"><strong>Erasure:</strong> Request deletion of your personal data ("right to be forgotten").</li>
            <li class="mb-1"><strong>Portability:</strong> Request a machine-readable copy of your data.</li>
            <li class="mb-1"><strong>Restriction:</strong> Request that we limit how we process your data.</li>
            <li class="mb-1"><strong>Objection:</strong> Object to processing of your data for certain purposes.</li>
            <li class="mb-1"><strong>Withdraw consent:</strong> Where processing is based on consent, you may withdraw it at any time.</li>
          </ul>
          <p class="text-body-1 legal-muted">
            To exercise any of these rights, please contact us at
            <a href="mailto:privacy@meshharbor.itachi.fans" class="text-primary">privacy@meshharbor.itachi.fans</a>.
            We will respond to your request within 30 days. You also have the right to lodge a complaint with a
            supervisory authority — in Bulgaria, the Commission for Personal Data Protection.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">10. Children's Privacy</h2>
          <p class="text-body-1 legal-muted">
            MeshHarbor is not intended for use by individuals under the age of 16. We do not knowingly collect
            personal data from children. If we become aware that we have collected data from a child under 16,
            we will take steps to delete that information promptly.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">11. Changes to This Policy</h2>
          <p class="text-body-1 legal-muted">
            We may update this Privacy Policy from time to time. We will notify you of material changes by
            posting the updated policy on this page and updating the "Last updated" date. Your continued use
            of MeshHarbor after any changes constitutes acceptance of the updated policy.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">12. Contact Us</h2>
          <p class="text-body-1 legal-muted">
            If you have any questions or concerns about this Privacy Policy or our data practices, please
            contact us at:
          </p>
          <p class="text-body-1 legal-muted mt-2">
            <strong>Email:</strong> <a href="mailto:privacy@meshharbor.itachi.fans" class="text-primary">privacy@meshharbor.itachi.fans</a>
          </p>
          <p class="text-body-1 legal-muted mt-2">
            The data controller is <strong>G ROX EOOD</strong>, registered in the Bulgarian Commercial Register
            under UIC 205174895, with its registered office at Plovdivska 110, 4400 Pazardzhik, Bulgaria, and
            represented by Goran Jovanov, Manager. Full company details are set out in our
            <router-link to="/imprint" class="text-primary">Imprint</router-link>.
          </p>
        </section>
      </v-container>
    </div>
  </v-theme-provider>
</template>

<script setup>
</script>

<style scoped>
.legal-page {
  background: #ffffff;
  color: #1a1a2e;
  min-height: 100vh;
}

.legal-container {
  max-width: 800px;
}

.legal-muted {
  color: rgba(26, 26, 46, 0.75) !important;
  line-height: 1.7;
}

code {
  background: rgba(26, 26, 46, 0.06);
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 0.9em;
}
</style>
