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

        <h1 class="text-h4 text-md-h3 font-weight-bold mb-2">Terms of Service</h1>
        <p class="text-body-2 legal-muted mb-8">Last updated: August 2026</p>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">1. Introduction and Acceptance</h2>
          <p class="text-body-1 legal-muted mb-4">
            These Terms of Service ("Terms") govern your access to and use of MeshHarbor ("MeshHarbor," "we," "us,"
            or "our"), available at <a href="https://meshharbor.itachi.fans" class="text-primary">meshharbor.itachi.fans</a> and
            operated by G ROX EOOD (see our <router-link to="/imprint" class="text-primary">Imprint</router-link>).
          </p>
          <p class="text-body-1 legal-muted mb-2">
            MeshHarbor is three products on one platform:
          </p>
          <ul class="text-body-1 legal-muted ml-6 mb-4">
            <li class="mb-1"><strong>Remote desktop</strong> — viewing and controlling the screen, keyboard and mouse of devices you have enrolled, from your browser.</li>
            <li class="mb-1"><strong>Private networking</strong> — an encrypted mesh network between your devices, with subnet routers, exit nodes, tunnels, a SOCKS5 proxy and SSH access.</li>
            <li class="mb-1"><strong>Collaboration</strong> — rooms, chat, threads, file sharing and video conferencing.</li>
          </ul>
          <p class="text-body-1 legal-muted">
            Using the first two requires installing our agent software on the devices concerned. Sections 4 to 6
            set out obligations specific to those features; they matter more than the rest of this document,
            because they concern access to real machines and real networks. By creating an account or using
            MeshHarbor, you agree to be bound by these Terms. If you do not agree, please do not use the platform.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">2. Eligibility</h2>
          <p class="text-body-1 legal-muted">
            You must be at least 16 years of age to use MeshHarbor. By using the platform, you represent and warrant
            that you meet this age requirement and have the legal capacity to enter into these Terms. If you are
            using MeshHarbor on behalf of an organization, you represent that you have the authority to bind that
            organization to these Terms.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">3. Account Responsibilities</h2>
          <p class="text-body-1 legal-muted mb-2">
            When you create an account on MeshHarbor, you agree to:
          </p>
          <ul class="text-body-1 legal-muted ml-6 mb-2">
            <li class="mb-1">Provide accurate and complete registration information</li>
            <li class="mb-1">Maintain the security and confidentiality of your login credentials</li>
            <li class="mb-1">Promptly notify us of any unauthorized use of your account</li>
            <li class="mb-1">Accept responsibility for all activities that occur under your account</li>
          </ul>
          <p class="text-body-1 legal-muted">
            You may authenticate using email and password, or through a third-party sign-in provider (Google,
            Microsoft, GitHub, LinkedIn or Facebook). You are responsible for maintaining the security of your
            chosen authentication method. Because your account can be used to reach enrolled devices, its
            compromise is more consequential here than on a chat product alone — we strongly recommend
            protecting it accordingly.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">4. The Agent and Enrolled Devices</h2>
          <p class="text-body-1 legal-muted mb-4">
            Remote desktop and private networking work by running our agent software (the "agent") on each
            device you enroll. You install it yourself, using an enrollment token issued from your workspace.
          </p>
          <p class="text-body-1 legal-muted mb-2">By enrolling a device, you represent and agree that:</p>
          <ul class="text-body-1 legal-muted ml-6 mb-4">
            <li class="mb-1"><strong>You are authorised to install it.</strong> The device is yours, or you have permission from its owner and from whoever administers it. Installing the agent on a device belonging to an employer, a school, a client or anyone else without their authorisation is a violation of these Terms, and may also be unlawful.</li>
            <li class="mb-1"><strong>The agent runs with administrative privilege.</strong> On Windows it typically runs as a system service; on Linux and macOS it typically runs as root. This is required to capture the screen, inject input and manage the network stack. Commands and sessions the agent carries out inherit that privilege.</li>
            <li class="mb-1"><strong>One agent per machine.</strong> The agent is designed as a single daemon per device and may adjust host-level network settings, including virtual network adapters, routes, DNS and firewall rules, to provide the mesh.</li>
            <li class="mb-1"><strong>It updates itself.</strong> The agent may download and install signed updates so that security fixes reach devices without manual intervention.</li>
            <li class="mb-1"><strong>You remain responsible for the device.</strong> Including for anything done through it by anyone you grant access to.</li>
          </ul>
          <p class="text-body-1 legal-muted">
            You may remove a device from your workspace at any time, and uninstall the agent from the device
            itself. Removing a device from the workspace revokes its access to the network; it does not by
            itself uninstall the software.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">5. Remote Access and Control</h2>
          <p class="text-body-1 legal-muted mb-4">
            Remote desktop lets an authorised user see and control an enrolled device: its screen, keyboard,
            mouse, clipboard and — where enabled — file transfer. Related features allow running commands on a
            device and opening SSH sessions to it.
          </p>
          <ul class="text-body-1 legal-muted ml-6 mb-4">
            <li class="mb-1"><strong>Only connect to devices you are entitled to use.</strong> Your workspace role and the device's own settings determine what you may do; neither replaces the permission of the people who use that device.</li>
            <li class="mb-1"><strong>Unattended access is a deliberate choice.</strong> A device may be configured to accept sessions without someone present to approve them. Whoever configures it that way is responsible for telling the device's users, and for any legal obligation to inform them — workplace and privacy law in many countries requires notice before monitoring or remote access.</li>
            <li class="mb-1"><strong>Sessions are recorded as events, not as content.</strong> We log who connected, to what, and when. We deliberately do not record screen contents, keystrokes or command output — see our <router-link to="/privacy" class="text-primary">Privacy Policy</router-link>.</li>
            <li class="mb-1"><strong>Commands and shells run with the agent's privilege</strong> unless the device is configured to drop to a specific account. Treat that access as you would physical access to the machine.</li>
            <li class="mb-1"><strong>You are responsible for what you do in a session.</strong> Reading someone's files, capturing their screen or acting as them may be unlawful even where you hold the technical ability to do it.</li>
          </ul>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">6. The Private Network, Tunnels and Exit Nodes</h2>
          <p class="text-body-1 legal-muted mb-4">
            MeshHarbor can join your devices into an encrypted private network and route traffic between them. Some
            of these features move other people's traffic through your infrastructure, or yours through theirs,
            and carry obligations accordingly.
          </p>
          <ul class="text-body-1 legal-muted ml-6 mb-4">
            <li class="mb-1"><strong>Subnet routers</strong> expose a whole local network to the mesh. Only advertise networks you are entitled to expose.</li>
            <li class="mb-1"><strong>Exit nodes</strong> send a device's entire internet traffic out through another node. If you operate an exit node, traffic from other users will appear to originate from your connection and your IP address; if you use one, your traffic appears to come from someone else's. Both directions require the consent of whoever is responsible for the connection involved, and may breach the acceptable-use policy of an internet or corporate network provider.</li>
            <li class="mb-1"><strong>Tunnels, port forwarding and the SOCKS5 proxy</strong> reach services on or through an enrolled device. Do not use them to bypass a network control you are not authorised to bypass, or to expose a service you do not have the right to expose.</li>
            <li class="mb-1"><strong>Access control is yours to set.</strong> Access rules default to denying what has not been granted. Widening them is your decision and your responsibility.</li>
          </ul>
          <p class="text-body-1 legal-muted">
            You must not use the private network to conceal unlawful activity, to evade a lawful restriction, or
            to attack, scan or interfere with systems you do not own or have permission to test.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">7. Acceptable Use</h2>
          <p class="text-body-1 legal-muted mb-2">
            You agree not to use MeshHarbor to:
          </p>
          <ul class="text-body-1 legal-muted ml-6 mb-2">
            <li class="mb-1">Access, control or monitor any device without the authorisation of its owner and users</li>
            <li class="mb-1">Install the agent on a device you are not entitled to install software on</li>
            <li class="mb-1">Route, tunnel or proxy traffic in a way that evades a network restriction you are not authorised to evade</li>
            <li class="mb-1">Scan, probe, attack or interfere with systems you do not own or have written permission to test</li>
            <li class="mb-1">Operate the platform as anonymising infrastructure for unlawful activity</li>
            <li class="mb-1">Harass, bully, threaten, or intimidate other users in chat rooms, direct messages, or video calls</li>
            <li class="mb-1">Share, upload, or transmit illegal, obscene, defamatory, or harmful content</li>
            <li class="mb-1">Distribute malware, spam, or phishing content through messages, file uploads or an enrolled device</li>
            <li class="mb-1">Impersonate any person or entity, or misrepresent your identity</li>
            <li class="mb-1">Attempt to gain unauthorized access to other users' accounts, workspaces, devices or data</li>
            <li class="mb-1">Interfere with or disrupt the platform, servers, relays, or networks connected to MeshHarbor</li>
            <li class="mb-1">Use the platform to violate any applicable law or regulation, including export control and sanctions law</li>
            <li class="mb-1">Record, screenshot, or redistribute calls, sessions or content without the consent of all participants</li>
            <li class="mb-1">Use automated bots or scripts to access the platform without our prior written consent</li>
          </ul>
          <p class="text-body-1 legal-muted">
            We reserve the right to investigate and take appropriate action against any violations, including
            suspending or terminating your account or disconnecting a device from the network.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">8. Content Ownership and User-Generated Content</h2>
          <p class="text-body-1 legal-muted mb-4">
            You retain ownership of all content you create, upload, or share on MeshHarbor, including chat messages,
            files, documents, and any other materials ("User Content"). By uploading or sharing User Content, you
            grant us a limited, non-exclusive, worldwide license to store, process, transmit, and display
            your content solely for the purpose of providing the platform services to you and your workspace members.
          </p>
          <p class="text-body-1 legal-muted">
            You are solely responsible for your User Content and represent that you have all necessary rights
            to share it. We do not claim ownership over your User Content, and this license terminates when you
            delete your content or your account. Data that passes through the private network or a remote-desktop
            session is not User Content in this sense — we do not receive it in a readable form at all.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">9. Intellectual Property</h2>
          <p class="text-body-1 legal-muted">
            The MeshHarbor platform, including its software, agent, design, logos, trademarks, and documentation, is
            owned by <strong>G ROX EOOD</strong> and is protected by intellectual property laws. These Terms do not
            grant you any right to use our trademarks, logos, or brand assets without our prior written permission.
            You may not reverse engineer, decompile or redistribute the agent except to the extent that applicable
            law expressly permits it notwithstanding this restriction. All rights not expressly granted to you are
            reserved. Third-party open-source components remain governed by their own licences.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">10. Recording Consent</h2>
          <p class="text-body-1 legal-muted mb-4">
            MeshHarbor offers call recording features for video and audio conferences.
            By using these features, you acknowledge and agree to the following:
          </p>
          <ul class="text-body-1 legal-muted ml-6 mb-2">
            <li class="mb-1">Recording can only be initiated by authorized participants with appropriate workspace permissions</li>
            <li class="mb-1">All participants in a call will be notified when recording begins</li>
            <li class="mb-1">By remaining in a call after recording notification, participants consent to being recorded</li>
            <li class="mb-1">Recordings are stored according to workspace settings and your subscription plan</li>
            <li class="mb-1">You are responsible for complying with all applicable laws regarding recording consent in your jurisdiction</li>
          </ul>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">11. Billing and Subscriptions</h2>
          <p class="text-body-1 legal-muted mb-2">
            MeshHarbor offers free and paid subscription plans. For paid plans:
          </p>
          <ul class="text-body-1 legal-muted ml-6 mb-2">
            <li class="mb-1">All payments are processed securely by Stripe. We do not store your full payment card details.</li>
            <li class="mb-1">Subscriptions are billed on a recurring basis (monthly or annually) according to your chosen plan.</li>
            <li class="mb-1">You may upgrade, downgrade, or cancel your subscription at any time through your workspace billing settings.</li>
            <li class="mb-1">Cancellation takes effect at the end of the current billing period. No prorated refunds are provided for partial periods.</li>
            <li class="mb-1">We reserve the right to modify pricing with at least 30 days' advance notice. Price changes will apply at your next renewal.</li>
            <li class="mb-1">If payment fails, we may suspend access to paid features after a reasonable grace period.</li>
          </ul>
          <p class="text-body-1 legal-muted">
            If you are a consumer in the EU, statutory withdrawal rights apply where the law provides them; nothing
            in these Terms limits rights you have that cannot be waived by agreement.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">12. Termination</h2>
          <p class="text-body-1 legal-muted mb-4">
            You may terminate your account at any time by contacting us or through your account settings.
            We may suspend or terminate your account if you violate these Terms, engage in prohibited conduct,
            or if required by law.
          </p>
          <p class="text-body-1 legal-muted">
            Upon termination, your right to use the platform ceases immediately and enrolled devices lose access
            to the private network. We may retain certain data as required by law or for legitimate business
            purposes. Content shared in workspaces may persist if other members of the workspace retain access
            to it. Uninstalling the agent from your devices remains your responsibility.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">13. Disclaimers</h2>
          <p class="text-body-1 legal-muted">
            MeshHarbor is provided on an "AS IS" and "AS AVAILABLE" basis without warranties of any kind, whether
            express or implied, including but not limited to warranties of merchantability, fitness for a
            particular purpose, and non-infringement. We do not warrant that the platform will be uninterrupted,
            error-free, or secure. Real-time performance — call quality, remote-desktop responsiveness and
            network throughput — depends on network conditions between the devices involved, which are outside
            our control, and MeshHarbor is not a substitute for physical access to a device or for your own backups.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">14. Limitation of Liability</h2>
          <p class="text-body-1 legal-muted">
            To the maximum extent permitted by applicable law, G ROX EOOD and its officers, directors,
            employees, and agents shall not be liable for any indirect, incidental, special, consequential, or
            punitive damages, including but not limited to loss of data, loss of profits, or business
            interruption, arising out of or in connection with your use of the platform. Our total aggregate
            liability for any claims arising under these Terms shall not exceed the amount you paid to us in
            the twelve (12) months preceding the claim. Nothing in these Terms excludes liability that cannot
            lawfully be excluded, including for death or personal injury caused by negligence, for fraud, or
            under mandatory consumer protection law.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">15. Indemnification</h2>
          <p class="text-body-1 legal-muted">
            You agree to indemnify, defend, and hold harmless G ROX EOOD from and against any
            claims, liabilities, damages, losses, and expenses (including reasonable legal fees) arising from
            your use of the platform, your User Content, devices you enroll, traffic you route through the
            private network, your violation of these Terms, or your violation of any rights of a third party.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">16. Governing Law and Disputes</h2>
          <p class="text-body-1 legal-muted">
            These Terms are governed by the laws of the <strong>Republic of Bulgaria</strong>, where G ROX EOOD is
            established, without regard to conflict of law principles. Any dispute shall first be attempted to be
            resolved through good-faith negotiation; please write to
            <a href="mailto:legal@meshharbor.itachi.fans" class="text-primary">legal@meshharbor.itachi.fans</a>. Failing that, disputes
            shall be subject to the courts of competent jurisdiction in Bulgaria. If you are a consumer resident
            in the EU, this does not deprive you of the protection of mandatory provisions of the law of your
            country of residence, or of your right to bring proceedings there.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">17. Changes to These Terms</h2>
          <p class="text-body-1 legal-muted">
            We may update these Terms from time to time. We will notify you of material changes by posting
            the updated Terms on this page and updating the "Last updated" date. For significant changes, we
            may also notify you via email or an in-app notification. Your continued use of MeshHarbor after the
            effective date of any changes constitutes acceptance of the updated Terms.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">18. Severability</h2>
          <p class="text-body-1 legal-muted">
            If any provision of these Terms is found to be unenforceable or invalid, that provision shall be
            limited or eliminated to the minimum extent necessary, and the remaining provisions shall continue
            in full force and effect.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">19. Contact Us</h2>
          <p class="text-body-1 legal-muted">
            If you have any questions or concerns about these Terms of Service, please contact us at:
          </p>
          <p class="text-body-1 legal-muted mt-2">
            <strong>Email:</strong> <a href="mailto:legal@meshharbor.itachi.fans" class="text-primary">legal@meshharbor.itachi.fans</a>
          </p>
          <p class="text-body-1 legal-muted mt-2">
            MeshHarbor is operated by <strong>G ROX EOOD</strong>, registered in the Bulgarian Commercial Register
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
</style>
