# scripts/signing

Operator scripts for obtaining and wiring the code-signing credentials that
`.github/workflows/release-*.yml` consume. Full background, rationale and the
CI-side design live in [`docs/code-signing.md`](../../docs/code-signing.md).

Every script is idempotent and safe to re-run.

## Order

```
00-preflight.ps1            check tooling, subscription, region, billing type, country
10-azure-provision.ps1      create the Artifact Signing account + operator roles
                            -> then submit identity validation IN THE PORTAL
15-azure-identity-status.ps1  portal-only status guide; -SetId records the result
20-azure-cert-profile.ps1   create the Public Trust certificate profile
30-github-oidc.ps1          app registration + federated credentials + repo variables
40-smoke-sign.ps1           sign a throwaway PE locally to prove profile + RBAC
```

While that processes (it is the long pole), the whole pipeline can be
rehearsed for free:

```
50-selfsigned-dev-cert.ps1  self-signed cert -> WIN_TEST_PFX_* secrets
51-trust-dev-cert.ps1       trust it locally; GPO / Intune recipes for pilots
```

Other platforms:

```
60-apple-setup.sh csr|p12|secrets|check    Developer ID + notarytool credentials
70-gpg-release-key.sh create|export|check  detached .asc release signatures
```

Gate:

```
90-verify-release.ps1 -Tag <tag>    Authenticode half (incl. MSI payload)
90-verify-release.sh  --tag <tag>   Gatekeeper + GPG + provenance half
```

## State

`00-preflight.ps1` writes `.meshharbor-signing.json` here; every later script
reads it, so each value is typed once. It holds only public identifiers
(subscription id, tenant id, account/profile names) and is gitignored anyway.

## What must never be committed

`dev-cert/`, `apple/`, and everything under `gpg/` except
`meshharbor-release-pubkey.asc` are gitignored. `*.pfx`, `*.p12`, `*.key` and
`*.p8` are ignored repo-wide as a backstop.

The Azure path is the exception worth noting: it produces **no key material
at all**. CI authenticates with GitHub OIDC, the private key never leaves
Microsoft's HSM, and the six `AZURE_SIGNING_*` / `AZURE_*` values are
repository *variables*, not secrets.

## Two facts that shape all of this

1. **A PFX-based public code-signing certificate can no longer be bought.**
   Since June 2023 the CA/Browser Forum requires every publicly-trusted
   code-signing private key to live in FIPS 140-2 Level 2 hardware. The
   `WIN_CODESIGN_PFX_BASE64` secret the workflows used to expect is a secret
   that cannot be filled, which is why signing moved to a cloud HSM.

2. **Signing does not clear SmartScreen on day one.** Microsoft removed
   instant-reputation-for-EV in 2024; OV, EV and Azure Artifact Signing all
   build reputation from download volume now. What signing buys immediately
   is the "Verified publisher" name in the UAC prompt, publisher-based
   AppLocker/WDAC rules, far fewer AV false positives, an unblocked macOS
   Gatekeeper -- and reputation that finally accumulates across releases
   instead of restarting from zero every time.
