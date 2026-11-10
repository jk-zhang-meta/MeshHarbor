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
        <p class="text-body-2 legal-muted mb-8">Last updated: October 2026</p>

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
            MeshHarbor is three things at once: a <strong>remote desktop</strong> for devices you enroll, a
            <strong>private encrypted network</strong> between them (with tunnels, subnet routers, exit nodes and
            SSH), and a <strong>collaboration</strong> layer of rooms, chat, files and video calls. Each collects
            different data, and section 3 is the one worth reading first — it describes the categories of data
            that never reach us at all.
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
            settings, room configurations, membership roles, and invite links. This data is used to manage your
            collaborative environment.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.3 Chat Messages and Content</h3>
          <p class="text-body-1 legal-muted mb-4">
            Messages you send in rooms, direct messages, threads, reactions, mentions, and pinned items are stored
            to provide the chat functionality. Message history is retained according to your workspace plan limits.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.4 Files and Uploads</h3>
          <p class="text-body-1 legal-muted mb-4">
            Files you upload to MeshHarbor are stored in our S3-compatible object storage. This includes
            documents, images, and any other files shared within rooms or direct messages. Files are associated
            with your account and the workspace where they were shared.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.5 Call Recordings</h3>
          <p class="text-body-1 legal-muted mb-4">
            If recording is enabled for a video or audio call, the recording
            is stored on our servers. Recordings are only created when explicitly initiated by an authorized
            participant, and all participants are notified when recording begins.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.6 Sign-In Provider Data</h3>
          <p class="text-body-1 legal-muted mb-4">
            When you sign in using Google, Microsoft, GitHub, LinkedIn or Facebook, we receive your email address,
            display name, and profile picture from the respective provider. We do not receive or store your
            passwords from these services. We use this information solely to create and authenticate your MeshHarbor
            account. Where a provider does not confirm that it has verified an email address, we record the claim
            separately and do not treat it as proof of ownership of that address.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.7 Conferencing Data</h3>
          <p class="text-body-1 legal-muted mb-4">
            During video and audio calls, your media streams are routed through our media server for delivery to
            other participants. They are processed in real time and are <strong>not stored</strong> unless
            recording has been explicitly enabled for the call. Connection metadata (IP addresses, codec
            information, bandwidth statistics) may be temporarily logged for quality monitoring and
            troubleshooting.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.8 Devices You Enroll</h3>
          <p class="text-body-1 legal-muted mb-4">
            When you enroll a device, we store a record of it so it can be addressed on your private network and
            shown in your workspace: a machine identifier, the device name you choose, its operating system,
            the agent version, its assigned address on the private network, its public key for the encrypted
            network, which user enrolled and owns it, and how it was installed (the setup wizard, an install
            script or by hand, and for the whole machine or one user). The agent reports periodic status so the workspace can
            show whether a device is online, together with capability information (for example which video
            encoders and displays it has).
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.9 Network and Connection Data</h3>
          <p class="text-body-1 legal-muted mb-4">
            To connect two devices directly wherever possible, the agent and our servers exchange candidate
            network addresses — including public and local IP addresses and ports — and measurements about which
            paths work. We keep connection diagnostics (which route was chosen, latency, packet loss, whether a
            relay was needed) to operate the network and to investigate faults. For a remote-desktop session we
            also note the kind of path it used — direct, through a relay, or through the private network — with
            the session's own record, and we count sessions by path, per day and without naming anyone, to
            measure remote-desktop quality. This is metadata about connections; it is not the contents of them.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.10 Access and Audit Records</h3>
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

          <h3 class="text-h6 font-weight-bold mb-2">2.11 Diagnostics, Crash Reports and Logs</h3>
          <p class="text-body-1 legal-muted mb-4">
            If the agent crashes it may send us a report containing the reason, the agent version, the operating
            system, the device hostname, the process identifier and a short tail of its own log. You can also
            choose to upload agent logs when reporting a problem. Agent logs describe the software's behaviour —
            connections, errors, decisions — and are not a record of what you did inside a session.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.12 Billing Information</h3>
          <p class="text-body-1 legal-muted mb-4">
            Payment processing is handled by Stripe. We do not store your credit card numbers, CVV, or full
            payment card details on our servers. We may store your Stripe customer ID, subscription plan details,
            billing email, and transaction history for account management and invoicing purposes.
          </p>
          <p class="text-body-1 legal-muted mb-4">
            For a workspace with a paid subscription we keep a record of what Stripe reports about it: the
            subscription being created, changed, cancelled or reaching the end of its trial, and each invoice
            paid or failed — with the plan, the number of seats, the amount billed and its currency, the billing
            period, and Stripe's identifiers for the invoice and the subscription. It names the workspace, never a
            card, an address or a person. We use it for one purpose: to know what the service earns — billed
            revenue, renewals, cancellations — and what serving each workspace costs against it. We also count,
            per workspace and per day, how often it reaches one of its plan's limits (for example the number of
            members or devices), to see which workspaces outgrow their plan. Both are kept for as long as the
            workspace exists and are deleted with it; monthly revenue totals, which name no workspace, are kept.
            The legal basis is our legitimate interest in running the service as a business (Art. 6(1)(f) GDPR).
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.13 Notifications and Email</h3>
          <p class="text-body-1 legal-muted mb-4">
            If you enable browser push notifications, we store the subscription your browser issues so we can
            deliver them. We send service email (account verification, invitations, security and billing notices)
            through an email delivery provider.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.14 Product Update Emails</h3>
          <p class="text-body-1 legal-muted mb-4">
            If you give us your email address through the "keep me posted" form on our website, we store that
            address, which page you submitted it from (or, if a campaign link brought you there, that campaign's
            name, as described in 2.16), and the times you submitted it and confirmed it. We use it
            for one purpose: occasional email about the product. We do not need an account for this, and the
            address is <strong>not linked to any account you may separately hold</strong>.
          </p>
          <p class="text-body-1 legal-muted mb-4">
            We use confirmed opt-in: after you submit the form we send one message asking you to confirm, and
            <strong>we send nothing else unless you click that link</strong>. Every email carries a one-click
            unsubscribe link that works without signing in. If you unsubscribe, we keep a record that this address
            opted out — so that it is not silently added again — and stop sending. We do not sell, rent or share
            this list, and we do not use it for advertising.
          </p>
          <p class="text-body-1 legal-muted mb-4">
            For each issue we send, we keep a record of which addresses it was sent to and whether our email
            delivery provider accepted it. The provider then reports, and we record with that send, whether the
            message was <strong>delivered, bounced, dropped, or reported as spam</strong>. We use this for one
            purpose: to keep the list deliverable and to know how each issue fared. If the provider reports that an
            address does not exist (a hard bounce) or that its owner marked the email as spam, we stop sending to
            it until you subscribe again. <strong>We never record whether you opened an email or clicked a
            link</strong>: there are no tracking pixels, and the provider's open and click tracking is switched off.
          </p>
          <p class="text-body-1 legal-muted mb-4">
            The links in an issue that point to our own website carry that issue's name (for example
            <code>utm_campaign=nl-october-notes</code>) so our analytics (2.15) can count visits per issue. The tag is
            <strong>identical for every reader</strong> — the only part of the email that is specific to you is
            your unsubscribe link, which also names the issue it came in. If you unsubscribe through it, we note
            which issue it was. This record is kept with the subscription record (see section 7) and erased with it
            on request; the legal basis is our legitimate interest in sending a newsletter people want
            (Art. 6(1)(f) GDPR).
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.15 Analytics</h3>
          <p class="text-body-1 legal-muted mb-4">
            We use our own self-hosted analytics to understand how the site is used. For each page you view, it
            records the page's address, the address of the page that sent you to it (in full, as your browser
            reports it), and coarse information such as the country a request came from, derived from the IP
            address. It also records a few named events: creating an account, subscribing to product updates,
            copying an install command, and following a link to our source code. We do not use third-party
            advertising or cross-site tracking services.
          </p>
          <p class="text-body-1 legal-muted mb-4">
            The setup wizard can also send us <strong>anonymous setup diagnostics</strong>, but only if you tick
            the box on its first page; it is unticked by default and not remembered for the next run. If you do,
            it sends one record per step of the install: the step's name, whether it passed, failed or was
            cancelled, how long it took, a short error code from a fixed list when it failed, the operating
            system family and the wizard's version — under a random identifier for that run. The record cannot
            carry the enrollment token, a name, a file path, a hostname or a network address, and we store
            neither the address nor the browser-style identifier the request came with. The records go to the
            server you enroll into: a self-hosted server receives its own and sends nothing to us. We use them
            to see where installs stop, and keep them for 90 days; after that only daily counts remain.
          </p>
          <p class="text-body-1 legal-muted mb-4">
            After a remote-desktop session of thirty seconds or more, the viewer may ask how it went: a thumbs
            up or down and, if you like, one or more reasons from a fixed list (lag, picture, mouse or
            keyboard, couldn't connect, something else). It asks <strong>at most once a day</strong>, you can
            dismiss it, and there is no text field. If you answer, the server you are signed in to stores the
            rating with that session's identifier, the workspace, your account identifier and the time, for
            25 months; it is deleted with your account, and we read it only as counts — how many sessions
            were rated well or badly, and which reasons were given. A self-hosted server keeps its own
            ratings and sends none to us, and its administrator can switch the question off entirely.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.16 How You Found Us</h3>
          <p class="text-body-1 legal-muted mb-4">
            Links we publish, for example under a video or in a post, can carry campaign tags: the
            <code>utm_source</code>, <code>utm_medium</code>, <code>utm_campaign</code>, <code>utm_content</code>,
            <code>utm_term</code> or <code>ref</code> parameters in the address. When you arrive through such a link,
            our pages pass the tags on in the address of their own sign-in, sign-up, install and download links,
            and give the campaign's name to the product-updates form (2.14). Our analytics (2.15) sees them too,
            because it records the address of each page you view. If you then create an account, we store with it
            the source, medium, campaign, content and term from those tags, the name of the website that sent you
            (for example <code>www.youtube.com</code>), and the path of the first page you visited on our site. The
            account keeps only that website's name, never the full address of the page that linked to you; our
            analytics records that full address, as your browser reports it (2.15).
          </p>
          <p class="text-body-1 legal-muted mb-4">
            The sign-up form also asks "How did you hear about MeshHarbor?". Answering is optional; if you choose an
            answer, we store it with the account in the same way. If you sign up through Google or another
            provider, these details wait on our server for at most ten minutes while you sign in there, and are
            then attached to the new account or discarded.
          </p>
          <p class="text-body-1 legal-muted mb-4">
            We use this for one purpose: to learn which of our channels bring people to MeshHarbor, and we look at it
            as counts per channel. It is recorded once, when the account is created, and never changed. It is not
            shown on your profile or to anyone in your workspace, and it is deleted together with your account. The
            legal basis is our legitimate interest in knowing which of our channels work (Art. 6(1)(f) GDPR); you
            can object to it at any time (section 9).
          </p>
          <p class="text-body-1 legal-muted mb-4">
            <strong>Nothing about this is stored on your device</strong>: no cookie, no local storage, no session
            storage. The tags travel only in the links you follow.
          </p>

          <h3 class="text-h6 font-weight-bold mb-2">2.17 YouTube</h3>
          <p class="text-body-1 legal-muted mb-4">
            MeshHarbor uses YouTube API Services to publish MeshHarbor's own videos to the MeshHarbor YouTube channel and to
            read that channel's statistics. This tool is used only by MeshHarbor; it does not access, collect or store
            data about other YouTube users or channels. Using it is subject to the
            <a href="https://www.youtube.com/t/terms" class="text-primary" target="_blank" rel="noopener">YouTube Terms of Service</a>
            and the
            <a href="https://policies.google.com/privacy" class="text-primary" target="_blank" rel="noopener">Google Privacy Policy</a>.
            We store only the statistics of our own videos. Access we granted can be revoked at any time through
            <a href="https://myaccount.google.com/permissions" class="text-primary" target="_blank" rel="noopener">Google's security settings</a>,
            and we delete the stored YouTube data within 30 days of a revocation or on request to
            <a href="mailto:privacy@meshharbor.itachi.fans" class="text-primary">privacy@meshharbor.itachi.fans</a>.
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
            <li class="mb-1">Anything typed into, or printed by, an SSH or remote shell session</li>
            <li class="mb-1">Files transferred between your devices over the private network</li>
            <li class="mb-1">The contents of traffic routed through a tunnel, a subnet router or an exit node</li>
            <li class="mb-1">Clipboard contents synchronised during a session</li>
          </ul>
          <p class="text-body-1 legal-muted">
            We deliberately do not record session content even though we operate the signalling: recording a
            terminal would mean shipping whatever an operator typed into it — passwords included — off the
            machine, which is precisely the property this design exists to avoid. What we do keep is the
            <em>metadata</em> in sections 2.9 and 2.10: that a session happened, between whom, and when. Chat
            messages, uploaded files and call recordings are different — those are stored on our servers, as
            described above, because delivering them is what the collaboration features do.
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
            choices. We also maintain a WebSocket connection for real-time messaging and presence. We do not use
            third-party tracking cookies.
          </p>
        </section>

        <section class="mb-8">
          <h2 class="text-h5 font-weight-bold mb-3">5. How We Use Your Information</h2>
          <p class="text-body-1 legal-muted mb-2">We use the information we collect to:</p>
          <ul class="text-body-1 legal-muted ml-6 mb-2">
            <li class="mb-1">Provide, maintain, and improve the MeshHarbor platform</li>
            <li class="mb-1">Authenticate your identity and manage your account</li>
            <li class="mb-1">Deliver chat messages, files, and video/audio streams to the intended recipients</li>
            <li class="mb-1">Establish connections between your devices and route them over the private network</li>
            <li class="mb-1">Enforce the access rules you configure, and give you an audit trail of who reached what</li>
            <li class="mb-1">Process call recordings when recording is enabled</li>
            <li class="mb-1">Process payments and manage subscription billing</li>
            <li class="mb-1">Send service-related communications (e.g., account verification, security alerts)</li>
            <li class="mb-1">Learn which of our channels bring people to MeshHarbor, counted per channel (section 2.16)</li>
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
            <li class="mb-1"><strong>With workspace members:</strong> Your profile information, messages, and shared files are visible to members of the same workspace according to room permissions. Device names, their status, and audit records are visible to workspace administrators.</li>
            <li class="mb-1"><strong>Between your own devices:</strong> Devices on the same private network learn each other's addresses and public keys — that is how the network functions.</li>
            <li class="mb-1"><strong>Service providers:</strong> We use Stripe for payment processing, an email delivery provider for service email, and infrastructure providers for hosting, all bound by data processing agreements.</li>
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
            <li class="mb-1">Chat message history is retained according to your workspace plan limits.</li>
            <li class="mb-1">Files are retained until deleted by you or a workspace administrator; call recordings according to your workspace settings.</li>
            <li class="mb-1">Access and audit records — the audit trail of remote sessions, command execution, SSH decisions and device-reported activity — are deleted automatically <strong>90 days</strong> after they are written.</li>
            <li class="mb-1">The record of a remote-desktop session itself — who controlled which device, when, for how long, its connection quality and the kind of network path it used — is deleted automatically <strong>25 months</strong> after the session began. Daily counts derived from these records name no one and are kept.</li>
            <li class="mb-1">Short-lived operational data such as connection diagnostics is deleted automatically on a shorter cycle, typically <strong>7 days</strong>. Crash reports (2.11) are deleted automatically <strong>30 days</strong> after we receive them.</li>
            <li class="mb-1">Enrollment tokens and similar one-time credentials expire within minutes to hours. The record that an administrator issued one, and whether a device used it — never the token itself — is deleted automatically after <strong>90 days</strong>.</li>
            <li class="mb-1">Product-update subscriptions are kept until you unsubscribe. After that we retain only the fact that the address opted out, so it cannot be re-added silently; ask us and we will erase that too.</li>
            <li class="mb-1">The record of which issues were sent to an address — with the delivery status our email provider reported (delivered, bounced, dropped, reported as spam) and, if you unsubscribed through an issue's link, which issue — is kept with that subscription record and erased with it on request.</li>
            <li class="mb-1">A workspace's billing events (what Stripe reported about its subscription and invoices) and its daily count of plan-limit hits are kept for as long as the workspace exists and deleted with it; monthly revenue totals, which name no workspace, are kept.</li>
            <li class="mb-1">Setup diagnostics the wizard sent with your consent (2.15) are deleted automatically <strong>90 days</strong> after they are written; the daily counts derived from them name no one and are kept.</li>
            <li class="mb-1">A rating you give a remote-desktop session from the viewer (2.15) is kept for <strong>25 months</strong> and deleted with your account.</li>
          </ul>
          <p class="text-body-1 legal-muted">
            These deletions are enforced by the database itself rather than by a manual process. When you delete
            your account, we will remove your personal data within 30 days, except where retention is required by
            law or for legitimate business purposes (such as billing records).
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
