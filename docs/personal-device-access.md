# Personal devices and host-selected invitation access

## Enrollment contract

A fresh device enrolled through browser-approved **personal device login**
enables its owner's supported desktop, clipboard, files, SSH, command execution,
RDP and mesh networking. The server binds this profile to the single-use login
credential; an ordinary enrollment token or self-reported machine ID cannot
claim it. Browser approval discloses the privileges before confirmation.

This is not an organization-wide grant. Other organization members and
administrators do not inherit personal-device access. Existing local OFF
settings survive another login. Signing in merges the existing configuration;
it does not erase other enrollments or accepted invitations.

An upgrade alone does not convert existing organization devices into personal
devices. Existing fleets need an explicit, reviewed migration identifying the
actual owner and excluding invited devices. Do not infer personal ownership
from `owner_user_id`: invited devices also store their inviter in that field.

## Invitations

The person accepting an invitation chooses eight capabilities:

| Capability | Meaning |
| --- | --- |
| `desktop_view` | View the desktop and associated audio/recording scopes |
| `desktop_control` | Input and privacy controls; requires desktop view |
| `clipboard` | Clipboard exchange; requires desktop view |
| `files` | File access |
| `ssh` | MeshHarbor SSH access |
| `exec` | Remote command execution |
| `rdp` | RDP over the mesh, where the host supports it |
| `network` | General mesh network access, including native OS services |

**Network access can reach native SSH/RDP servers independently of the separate
MeshHarbor service switches.** Select only the narrower service capabilities
when general network access is unwanted. SSH/exec may execute as the daemon's
OS account, including root or SYSTEM. These warnings are part of acceptance.

Capabilities are a ceiling for the specific inviter and the invitation's
allowed roles, not a union granted to every inviter. Organization policy, local
host switches, OS permissions, and installed build support still apply. No
permission selection installs an OS RDP service or grants macOS screen/input
permissions. Expiry and revocation remain effective.

The dedicated SSH grant path currently uses TCP 2222 for the worker or 2223
for the SYSTEM service. Its selected-service network rules cover those ports;
the existing grant API does not advertise arbitrary custom SSH listener ports.
Port filtering limits reachability, not application identity: SSH grant and
host-key validation still apply. RDP requires an actual OS RDP service.

The native acceptance dialog presents all eight choices. For unattended CLI
acceptance, specify an explicit selection:

```sh
mh join INVITE_CODE --yes --features ssh,files
mh join INVITE_CODE --yes --features all
```

The accepting host can later change a particular invitation in the tray's
**Choose exposed features** dialog, or with:

```sh
mh invite-features --invite INVITE_ID --features ssh,files
mh invite-features --invite INVITE_ID --features none
```

The management website displays the host's selection. It does not let the
inviter override it. Revision checks reject stale simultaneous edits. A local
service switched OFF remains OFF; enabling its invitation capability does not
silently turn that service on or change another invitation.

A selection update returns HTTP 202 and remains pending while the host closes
managed access. The native client must collect successful closure evidence,
including any independently anchored service domain, restart the relevant
daemon runtime and observe its target organization's first applied network map
before acknowledging the exact selection revision. Failed cleanup or readiness
checks leave the operation pending; a process exit alone is not completion.

The server retains a durable activation barrier while applying the new network
projection. Projection writes are fenced by an authorization generation, so an
older calculation cannot overwrite a newer restriction or connection's deadline
capability. Redis publication alone does not complete activation: online affected
host-family nodes must acknowledge the full map actually sent to their current connection,
matching the required revision and epoch. Errors/timeouts remain retryable and
must not be presented as successful propagation. Managed-session closure is the
native host's responsibility; the network ACK is not a server attestation that
every OS process restarted. Ordinary reconnect/offline-continuity behavior is
not redefined by this contract.

Invitation network grants carry individual deadlines enforced in the receiving
data plane, including existing flows. A pair with an older client that cannot
enforce these deadlines is withheld rather than silently granting unbounded
access. Upgrade both ends before treating those invitation paths as available.
These implementation guarantees still require supported-platform and real
rollout verification; source review or isolated tests alone are not deployment
completion.

The close operation may temporarily interrupt this machine's connections and
in-flight managed commands across **all** of its organizations; the other
organizations' permission settings and invitation relationships are preserved.
The native interface must disclose this before a capability change. Revocation
ends MeshHarbor-managed access; it cannot undo changes made by previously
authorized commands, remove a service that a user deliberately installed, or
retract work deliberately detached from MeshHarbor's process management.
Do not describe a terminated session leader as proof that every historical
descendant or external side effect has disappeared.

Old invitations with no recorded selection are displayed as legacy/unknown,
not as explicit permission for every feature. New clients refuse a server that
cannot acknowledge selected features. Avoid downgrading the server after hosts
have relied on these access ceilings: old servers do not enforce them.

## Build and rollout acceptance

Use `local-build.md` and inspect the actual compiled feature set. A daemon built
with only overlay and SSH features is not a full remote-desktop build. Preserve
device IDs, invitation proofs, organization membership, local settings, update
trust anchors, OS permission identity, and platform supervision during upgrades.

Before production rollout, require capability allow/deny tests, owner and
cross-inviter isolation tests, host-only update tests, supported native builds,
independent authorization review, and tested recovery. Upgrade a canary first;
then test real connections before proceeding to the remaining devices. Record
offline devices and unsupported or OS-denied functions separately. Compilation,
package creation, installation, and end-to-end feature verification are distinct
milestones; none substitutes for the next.
