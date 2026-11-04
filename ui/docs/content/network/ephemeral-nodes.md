---
title: Ephemeral nodes
description: Devices that remove themselves — CI runners, containers and autoscaled workers that join the mesh on start and disappear cleanly when they stop.
tags: [network, ephemeral, ci, containers, automation, enrollment]
order: 9
---

A CI runner that lives for four minutes should not leave a device row behind
forever. **Ephemeral nodes** join the mesh on start, do their work, and remove
themselves when they stop.

## Reusable enrollment keys

A normal enrollment token is single-use, which does not suit something that
starts fifty times a day. Ephemeral nodes use a **reusable key** instead, with
four controls that hold at once:

:::badges
- **An expiry** icon:warning — the key stops working at a date you choose.
- **Revocable** icon:shield — revoking takes effect on the very next use.
- **A use limit** icon:check — cap how many devices it may create.
- **A per-use record** icon:book — every use is recorded, and the record outlives the device.
:::

:::tip The audit record deliberately outlives the device
An ephemeral device deletes itself, so if the only trace lived on the device row
there would be no trace at all. The record of *who used the key, when* is kept
separately.
:::

Create one in the dashboard under **Devices → Enrollment keys**.

## Enrolling as ephemeral

```bash
roomlerd enroll --server https://roomler.ai --token <reusable-key> --ephemeral --name ci-runner
```

:::warning Ephemeral is a property of the credential, not a flag on a request
A device cannot ask to be treated as permanent when it enrolled with an
ephemeral key, or vice versa. The distinction rides the key, which is what makes
it something an administrator controls rather than something the machine
asserts.
:::

## What "ephemeral" changes

| Behaviour | Normal device | Ephemeral device |
|---|---|---|
| Machine identity | Stable, derived from hardware | Random per enrollment |
| Restarting the agent | The same device comes back | A **new** device |
| Clean shutdown | Stays in the list | Removes itself |
| Disappearing without stopping | Shows offline indefinitely | Reaped automatically |

:::danger A restart is a new device, by design
Ephemeral nodes deliberately do not reuse a machine identity — two containers
from the same image on the same host must not collide. The consequence is that
**restarting an ephemeral agent produces a second device**, with a new address.

If you want a machine that keeps its identity across restarts, it should not be
ephemeral.
:::

## Cleaning up

Two mechanisms, because a machine cannot always announce its own exit:

- **On a clean stop**, the agent removes itself as it shuts down. A Windows
  per-user install stops cleanly on `roomlerd service stop`, on sign-out and on
  shutdown. Ending its task (Task Manager, `schtasks /End`) is not a clean stop.
- **Otherwise**, a reaper removes ephemeral devices that have stopped reporting.

An update that restarts the agent does **not** count as a shutdown — otherwise
every update would silently delete the device it was updating.

## Using it in CI

```bash
curl -fsSL https://roomler.ai/api/setup/install.sh | sh -s -- \
  --role daemon --system --token "$MESHHARBOR_ENROLL_KEY" \
  --server https://roomler.ai --name "ci-$CI_JOB_ID" --ephemeral
```

The runner joins the mesh, can reach your private services for the length of the
job, and is gone afterwards.

:::warning Keep the reusable key in your CI secret store
It is a standing credential that can add machines to your organization. Give it
an expiry and a use limit, and revoke it if a job log ever prints it.
:::

## Not yet available for tunnel clients

Ephemeral enrollment currently applies to full agents. A tunnel-only client
needs its own credential type, which is not built — it is deferred until there
is evidence of need rather than implemented speculatively.
