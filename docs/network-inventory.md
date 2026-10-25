# Node network inventory (MeshHarbor #19)

Each node reports what its own kernel says about its networking, read-only,
so an administrator can see the network that actually exists next to the
overlay ACL. This is the first slice of the v039 topology design (§4,
"Agent reporting"). A reported route or rule is only a fact about one host.
It is not evidence that a path works, and it is not an ACL grant.

## What a node reports

`rc:agent.net_inventory`, typed in
[`remote_control/src/net_inventory.rs`](../crates/remote_control/src/net_inventory.rs):

| section | Linux source | notes |
|---|---|---|
| interfaces | `ip -j -d addr show` | name, index, link kind (`wireguard`, `tun`, `bridge`, …), up, MTU, addresses |
| routes | `ip -j -4/-6 route show table all` | every table, with kind (`unicast`, `local`, `blackhole`, …), gateway, device, protocol, metric |
| rules | `ip -j -4/-6 rule show` | priority, a compact selector (`from 10.0.0.0/8 iif eth0 fwmark 0x1`), action |
| listeners | `/proc/net/{tcp,udp}{,6}` | listening TCP and bound UDP sockets; the owner's short process name when visible |
| forwarding | `/proc/sys/net/ipv{4,6}/…forwarding` | the two flags |
| firewall chains and rules | `nft -j list ruleset` | hook, type, priority, policy; each rule's matches, verdict, NAT target and counters; an owner tag (`docker`, `firewalld`, `fail2ban`, `libvirt`, `kubernetes`, `meshharbor`, `unknown`) |

Every section carries a state: `complete`, `partial` (capped, or some items
unreadable), `unsupported`, `denied` or `error`, and the real total. A
`complete` section whose count disagrees with its items is rejected, so a
truncated picture can never pass for a whole one.

Only the host network namespace is read (`namespaces: "host_only"`).
Containers' own namespaces are not covered. iptables-legacy rules, which nft
cannot show, are counted and the firewall sections marked `partial`; they are
not parsed. Windows and macOS report every section `unsupported` until they
have native adapters.

**Never reported:** command lines, environment, rule comments, keys, payloads,
raw conntrack. Every string is length-capped and every section item-capped
(`MAX_*` in the module).

## What the server accepts

[`network/src/net_inventory.rs`](../crates/modules/network/src/net_inventory.rs):

- **Identity is the socket's.** The row is the authenticated connection's
  agent and tenant; the frame names neither.
- **Order.** `boot_id` is random per agent process and `seq` rises within it.
  A replay, an older `seq`, or a late frame from one of the last four retired
  boots is dropped. A new process starts over.
- **Whole or nothing.** A snapshot travels in up to 16 pages of one `seq`.
  They must all arrive within 30 s; the merge must validate. Then one
  conditional write, so a racing writer loses as stale.
- **Freshness is the server's clock.** A row is `fresh` for 15 minutes after
  it arrived; a heartbeat never extends that. Nodes send every 5 minutes.
  Rows of nodes that stopped reporting are deleted after 7 days.

## Reading it

`GET /api/tenant/{tenant_id}/net-inventory` lists each node's summary
(per-section state, total and count, `fresh`), and
`GET /api/tenant/{tenant_id}/net-inventory/{agent_id}` returns the whole
snapshot. Both need `MANAGE_AGENTS` in that tenant, like the overlay ACL.

## Turning it off

The agent config key `net_inventory = false` (env `ROOMLERD_NET_INVENTORY=0`)
stops reporting. A device enrolled in more than one org never reports: the
host inventory would show each org the other enrollments' overlay interfaces
and routes.

## Not built yet (v039)

The UI view, observed flows, deltas instead of full snapshots, non-host
namespaces, native Windows and macOS adapters, and everything in §6 (managed
forwards).
