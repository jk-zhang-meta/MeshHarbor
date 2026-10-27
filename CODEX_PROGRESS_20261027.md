# MeshHarbor: N-hop continuation, 2026-10-27

Baseline: `ed11f5ccc0794a798cb2ff8e498686f0f0a6d354` in the isolated ROG Kali WSL worktree `/root/.agent-work/runtime/pac/roomler-ai-20261022/codex-nhop`, branch `codex-nhop-20261027`. The production system and integration source were not modified. Follow `MESHHARBOR_HANDOFF_20261024.md` for the binding restrictions and the remaining work.

This branch is **not an N-hop implementation**. Its only code change checks the bridge grant's source agent against the local primary enrollment on the production signaling dispatch path, before the bridge manager can replace or start any bridge. It includes a dispatch test for matching, mismatched, missing and malformed identities, and secondary-org rejection. Do not deploy this change until the applicable gates pass.

Additional considerations for the N-hop implementation:

- Business-isolation peer visibility calls `cross_border_lines` and represents zone connectivity by currently approved direct edges. Arbitrary-hop reachability must also be reflected in netmap visibility and revocation; just changing the mint and discovery planner will leave valid multi-hop peers hidden. Preserve same-tenant authorization and apply the approved crossing rule at each edge.
- The current path rank is `(worst leg class, sum of measured RTTs, sum of relay load)`, with reachable < unknown < unreachable. A single Dijkstra label ordered by this tuple is not generally safe: a later unknown or unreachable edge can equalize previously different classes, after which an earlier discarded lower-RTT path may win. Search independently under successive allowed class thresholds (or keep non-dominated labels), and verify ties, directed edges and simple-path loop prevention.
- The handoff suggests a four-relay cap, but the user explicitly asked that routing be independent of hop count. Do not silently impose a four-relay product limit; bound resource use and message size explicitly while supporting valid longer paths.
- Trial, fallback and discovery have separate state and revoke paths. Session, relay, bridge, edge and readiness revocation must all cover every hop before rollout. The existing two-hop wire protocol cannot be assumed compatible with the new topology.

Validation: built the `roomlerd` library tests in the isolated WSL/bubblewrap environment with `overlay-netstack,overlay-l3`; the three dispatch tests passed. Rebuilt with the source check removed and confirmed that the new dispatch test fails; the original source was then restored. This is targeted evidence only, not the full server, tunnel-core, field or N-hop gate.
