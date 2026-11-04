# Relay PoP — regional coturn + DERP on a cheap VPS

One VPS per region runs the whole relay stack: **coturn** (TURN over
UDP/3478, TCP/3478, TLS/5349, UDP/443-via-DNAT), the **derp-relay** binary
(ticket-authenticated regional DERP), and an **SNI-splitting nginx** so
TCP/443 serves both `turns:` (corp escape) and `wss:` (DERP) on one address.
Selection is client-probed RTT (no GeoDNS): agents receive the region list
over the control WS, time a STUN binding to each, and the server derives
their `relay_home`.

Secrets on the box: the TURN shared secret (bandwidth-theft blast radius
only) and the DERP ticket **public** key. The JWT secret and the ticket
**private** key never leave the API.

## Region matrix (procurement)

| Phase | Region id | Provider / location | Plan |
|---|---|---|---|
| 1 | `us-east` | OVH VPS-1, Vint Hill VA | ~$4.5/mo, unlimited @500 Mbps |
| 1 | `us-west` | OVH VPS-1, Hillsboro OR | ~$4.5/mo |
| 1 | `ca-east` | OVH VPS-1, Beauharnois QC | ~$4.5/mo |
| 2 | `eu-central` | existing fleet coturn (Vienna) | $0 |
| 2 | `eu-west` | OVH VPS-1, Gravelines FR | ~$4.5/mo |
| 2 | `eu-north` | Hetzner CX23, Helsinki | ~€5.5/mo, 20 TB |
| 3 | `jp-tokyo` | Vultr, Tokyo | $3.5–6/mo |
| 3 | `sg` | Contabo, Singapore | ~€5.5+surcharge, ~32 TB |
| 3 | `in-mumbai` | Vultr, Mumbai | $3.5–6/mo |
| 3 | `me-dubai` | LightNode, Dubai | ~$7.7/mo |
| 3 | `hk` | LightNode, Hong Kong (best-effort China adjacency) | ~$7.7/mo |
| 4 | `au-sydney` | Binary Lane, Sydney (also serves NZ) | ~AU$4.9/mo |
| 5 | `br-saopaulo` | Vultr, São Paulo | $3.5–6/mo |
| 5 | `mx-mexicocity` | Vultr, Mexico City | $3.5–6/mo |
| 5 | `za-johannesburg` | Vultr, Johannesburg | $3.5–6/mo |

Cost guards: bump a Vultr plan at 80% of included egress; any PoP whose
monthly egress+overage exceeds ~$25 graduates to an unmetered/32 TB provider
in the same metro (Hetzner auction EU, Contabo, ReliableSite US). Prices are
mid-2026 — re-quote at signup.

## Bring-up (per PoP)

1. **VPS + DNS.** Order the VPS (Debian 12/Ubuntu 22.04+). Create A records
   `coturn-{region}.roomler.ai` and `derp-{region}.roomler.ai` → its IP.
2. **Copy this kit** to the box and stage the daemon binary (built by CI or
   the build host — `cargo build -p derp-relay --release`):
   ```bash
   scp -r scripts/relay-pop root@<pop>:/opt/relay-pop
   scp target/release/derp-relay root@<pop>:/opt/relay-pop/bin/derp-relay
   ssh root@<pop> chmod +x /opt/relay-pop/bin/derp-relay
   ```
3. **Configure**: `cp /opt/relay-pop/pop.env.example /opt/relay-pop/pop.env`
   and fill in (region id, both hostnames, public IP, the TURN shared secret,
   the DERP ticket **public** key from the API's startup log line
   `derp ticket signer loaded — set DERP_TICKET_PUBLIC_KEY to this`).
4. **Provision**: `bash /opt/relay-pop/provision.sh` (idempotent — installs
   docker, sysctls, the UDP/443 DNAT, issues the LE cert via acme.sh
   standalone :80, renders configs, starts the compose stack).
5. **Verify from anywhere** — one line per advertised transport variant
   (STUN on udp/3478 + udp/443-DNAT + tcp/3478, STUN-over-TLS on 5349 and on
   443 through the SNI split, derp healthz). With `TURN_SECRET_FILE` set it
   also performs full TURN **Allocates** over udp/443 and TLS/443 (catches
   static-auth-secret drift and relay-address misconfig) plus a **relay-echo**
   — a udp/443 and a tls/443 allocation exchanging real bytes both ways —
   which catches allocate-succeeds-data-vanishes regressions like the
   missing-`relay-ip` loopback blackhole:
   ```bash
   TURN_SECRET_FILE=~/coturn.auth python3 scripts/relay-pop/healthcheck.py \
     us-east=coturn-us-east.roomler.ai:3478,derp-us-east.roomler.ai
   ```
6. **Register the region** — append to `MESHHARBOR__RELAY__REGIONS` in the prod
   configmap (deploy repo) and redeploy the web:
   ```json
   {"id":"us-east",
    "turn_url":"turn:coturn-us-east.roomler.ai:3478",
    "derp_url":"wss://derp-us-east.roomler.ai/derp",
    "caps":{"tls_443_udp":false}}
   ```
   `tls_443_udp: false` because that variant is DTLS and structurally dead
   here: the UDP/443 DNAT lands on coturn's **plain** 3478 listener (webrtc-rs
   drops the URL anyway; browsers would burn an allocate timeout on it). The
   other :443 caps stay on — `udp_443` rides the DNAT and `tls_443_tcp` rides
   the nginx SNI passthrough to coturn's TLS listener; both field-verified
   allocate-level on all four phase-1 PoPs (2026-08-17).
   Requires `MESHHARBOR__RELAY__REGIONS_ENABLED=true` and (for DERP)
   `MESHHARBOR__RELAY__DERP_TICKET_PRIVATE_KEY`
   (`openssl genpkey -algorithm ed25519 -outform DER | base64 -w0`).
7. **Watch**: `relay_region_pick_total` in `/api/cluster/status`,
   `GET /api/relay/regions`, `agents.relay_home` in Mongo / the Devices UI.
   Soak ≥1 week before the next procurement wave.

## Health cron (buildhost)

`TURN_SECRET_FILE` points at the fleet truth file so every run exercises real
Allocates; the trailing-comma `eu-central` row (no PoP DERP) keeps the fleet
coturn's own :443 DNAT under the same watch:

```cron
*/15 * * * * TURN_SECRET_FILE=/home/gjovanov/coturn.auth \
  python3 /opt/roomler/relay-pop/healthcheck.py \
  us-east=coturn-us-east.roomler.ai:3478,derp-us-east.roomler.ai \
  ... \
  eu-central=coturn.roomler.ai:3478, \
  >> ~/relay-pop-health.log 2>&1 || <alert: gh issue / mail>
```

## Rollback

A misbehaving region: set its spec `"enabled": false` (or drop it) and
redeploy — grants fall back to the default region within the 10-min sticky
window; agents keep their probe tables and simply re-home on the next push.
Global off-switch: `MESHHARBOR__RELAY__REGIONS_ENABLED=false` restores the
single-region behaviour byte-for-byte.
