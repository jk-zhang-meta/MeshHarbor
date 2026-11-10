---
title: Collecting diagnostics
description: What to gather before asking for help — status, peers, logs and a paired diagnostic bundle — and what to redact before you share it.
tags: [troubleshooting, diagnostics, logs, support]
order: 6
---

A good report answers three questions: **what did you expect**, **what happened**,
and **what does the machine say about itself**.

## The minimum

```bash
mh status
mh peers
mh --version
```

## For a connectivity problem, gather BOTH ends

:::warning One side's output is half the picture
Connectivity is a property of a **pair**. A report from one machine cannot show
whether the other agrees about the path, and disagreement between the two ends
is itself a diagnosis.
:::

```bash
mh diag pair <other-device>
```

That runs a paired diagnostic and reports what each end sees.

For one machine on its own:

```bash
mh diag host
```

:::tip Diagnostics live in the CLI, not in the agent
Which means a new probe reaches you in a CLI update rather than requiring a
fleet-wide agent rollout. If someone asks you to run a `diag` subcommand you do
not have, update the CLI.
:::

## Logs

:::os
@windows
```powershell
mh logs --tail 200
```
Or the service log directory under `%PROGRAMDATA%\meshharbor\logs`.

@macos
```bash
mh logs --tail 200          # the user half
sudo mh logs --tail 200     # the root half
```

@linux
```bash
journalctl -u meshharbor -n 200 --no-pager           # system unit
journalctl --user -u meshharbor -n 200 --no-pager    # per-user unit
```
:::

:::warning `mh logs --grep` reads only a recent tail
It searches a bounded slice of the end of the log, not the whole thing. **A
negative result is not proof of absence** — if you are looking for something
older, read the log directly.
:::

## Turning up the detail

Raise the log level, reproduce the problem, then put it back. Verbose logging is
for a reproduction, not for permanent operation.

## What to redact before sharing

:::danger Logs and config can contain credentials
- **`config.toml` holds the agent token** and, with SSH enabled, the SSH host private key. Do not paste it.
- **Enrollment tokens** may appear in shell history and installer output.
- **Log lines can contain a credential.** Command output is redacted before it leaves a machine, but a log you export by hand has had no such pass.

If a token does end up in something you shared, remove the device and re-enroll
it. That revokes the credential — which is exactly why removal is immediate.
:::

Machine names, mesh addresses and versions are generally safe and are usually
the useful part.

## Where to send it

[github.com/jk-zhang-meta/MeshHarbor/issues](https://github.com/jk-zhang-meta/MeshHarbor/issues).
Include:

:::steps
1. What you expected to happen.
2. What happened instead, with the exact message.
3. `mh status` from the affected machine — and from both, for a connectivity problem.
4. Operating system and version, on each end.
5. Whether it is the hosted service or self-hosted.
6. Whether it ever worked, and what changed if so.
:::

Point 6 is the one most often omitted and most often decisive.
