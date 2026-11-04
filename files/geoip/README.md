# GeoIP database: DB-IP "IP to Country Lite" (CC BY 4.0)

The platform user analytics resolves a client's country at WebSocket
connect time and then **drops the address**, so no IP is ever stored. That
lookup needs a MaxMind-format country database. The server image carries
one: DB-IP's **IP to Country Lite**, at
`/usr/share/roomler/geoip/dbip-country-lite.mmdb`, the path the image's
`MESHHARBOR__STATS__GEOIP_MMDB` names (#1896).

It is never committed. `scripts/fetch-geoip.sh` stages it in this
directory before `docker build`, and both image workflows run it
(`hosted-image.yml`, `publish-selfhost-image.yml`):

```bash
scripts/fetch-geoip.sh     # this month's release (or last month's), verified
docker build .             # COPY files/geoip/ bakes it in
```

| | |
|---|---|
| Database | IP to Country Lite by DB-IP, MaxMind DB format, released monthly |
| Download | `https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz` |
| Licence | [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/) |
| Credit shown | "IP Geolocation by DB-IP", linking <https://db-ip.com>, under the observability dashboard's Countries table |
| Checks | gzip integrity, a size between 1 and 128 MiB, MaxMind DB metadata of type `DBIP-Country-Lite`; then the image smoke boots the server and requires `geoip database loaded` |
| Provenance | `dbip-country-lite.provenance.txt`, written beside the file: release, URL, SHA-256, fetch time, licence |

## Attribution

This product includes IP geolocation data from **DB-IP**
(<https://db-ip.com>): "IP to Country Lite", licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) and redistributed
unmodified. DB-IP provides the database as is, without warranties of any
kind; the licence carries the full disclaimer.

DB-IP's licence terms, quoted from
<https://db-ip.com/db/download/ip-to-country-lite>:

> The free IP to Country Lite database by DB-IP is licensed under a Creative
> Commons Attribution 4.0 International License. You are free to use this IP
> to Country Lite database in your application, provided you give
> attribution to DB-IP.com for the data. In the case of a web application,
> you must include a link back to DB-IP.com on pages that display or use
> results from the database.

The dashboard shows that link only when the server reports a DB-IP
database loaded (`geoip_database` in `/api/admin/stats/users`,
`ui/src/utils/geoipCredit.ts`). A deployment that supplies its own
database is credited by that database's own type, or not at all.

## Why DB-IP, and not GeoLite2

The image is a **public** package, so whatever it carries is redistributed
to everyone who pulls it. CC BY 4.0 permits that, given the credit above.
MaxMind's GeoLite End User License Agreement (updated 2026-02-12) does
not: §6 says you "will not disclose the Services to any third party
without notifying MaxMind of the anticipated disclosure and obtaining
MaxMind's prior written consent", and requires old versions to be destroyed
within 30 days of an update, which old image tags can never honour.
GeoLite2 therefore stays out of every published image. Before #1896 the
build host dropped `GeoLite2-Country.mmdb` here by hand; the GitHub lane
(FR-73) never did, which is why prod read every country as `unknown`.

## Your own database, or none

- **Your own** (a licensed GeoIP2 Country, or a GeoLite2 you are entitled
  to use): mount it and set `MESHHARBOR__STATS__GEOIP_MMDB=/path/to/it.mmdb`.
- **None**: set `MESHHARBOR__STATS__GEOIP_MMDB=` (empty). Lookups stop; the
  security freshness monitor warns that geographic zone evidence is unavailable.
- ⚠️ An environment variable outranks `config/*.toml`, and the image sets
  this one. `[stats] geoip_mmdb` in a config file cannot override it; set
  the variable.

## Analytics when it is absent

A build without the file (DB-IP unreachable during the build, or a source
build that skipped the script) produces an image whose analytics report
`country: unknown` and whose payload carries `geoip: false`, so the
dashboard says "no GeoIP database" rather than implying every user is in
one place. The fetch warns and the build goes on; the server warns at boot
and periodically. Analytics remains available, while missing data cannot
provide geographic zone security evidence.

## Security freshness and updates

The server checks the loaded reader on startup and every 24 hours. It warns if
metadata is missing or invalid, during the final 30 days of the 120-day
security validity window, and after expiry. Missing, invalid or expired data
cannot serve as geographic zone security evidence. The policy outcome depends
on `app.business_isolation`: `enforce` uses the evidence for enforcement;
`warn` can log and allow, and `off` can allow. These checks never log an IP
address and do not reload the database.

The monitor emits `tracing` WARN events, not a guaranteed external alert.
Subscriber filters, logging queues and downstream collectors can suppress or
drop events; operators must configure and verify their own alert pipeline.

The image workflows fetch a database when an image is built; this is not a
scheduled update of a running server. Refreshing a file on disk also does not
replace the reader already held in memory. Rebuild or provision a fresh image
or file, then restart the service; check the loaded dataset and warning logs.
A build alone does not deploy or restart the service.

Country granularity is what the analytics uses. City databases also exist
(much larger); adopting one would only make sense alongside a deliberate
decision to record finer-grained location, which is a privacy choice, not
a data-availability one.
