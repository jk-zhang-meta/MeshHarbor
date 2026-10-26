// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Layout for the server-topology map: where each server sits and how an
// edge between two of them is drawn. Pure, so it is unit-tested without a DOM.

/**
 * `CC:lon,lat` per ISO 3166-1 alpha-2 country: the centroid of the country's
 * largest polygon in Natural Earth 1:50m (world-atlas `countries-50m`), so an
 * overseas territory never drags its country into the sea. GeoIP is
 * country-level, so this is as precise as a server's position gets.
 */
const TABLE =
  'AD:1.6,42.5;AE:54.3,23.9;AF:65.9,33.8;AG:-61.8,17.1;AI:-63.1,18.2;AL:20.1,41.1;' +
  'AM:44.9,40.3;AO:17.6,-12.3;AQ:83,-84.7;AR:-64.7,-34.5;AS:-170.7,-14.3;AT:14.1,47.6;' +
  'AU:134.2,-25.6;AW:-70,12.5;AX:19.9,60.2;AZ:47.7,40.3;BA:17.8,44.2;BB:-59.6,13.2;' +
  'BD:90.2,23.9;BE:4.6,50.6;BF:-1.8,12.3;BG:25.2,42.8;BH:50.5,26;BI:29.9,-3.4;BJ:2.3,9.6;' +
  'BL:-62.8,17.9;BM:-64.8,32.3;BN:114.6,4.5;BO:-64.7,-16.7;BR:-53.2,-10.7;BS:-78,24.7;' +
  'BT:90.4,27.4;BW:23.8,-22.2;BY:28,53.5;BZ:-88.7,17.2;CA:-99,58.6;CD:23.6,-2.9;' +
  'CF:20.5,6.6;CG:15.2,-0.8;CH:8.2,46.8;CI:-5.6,7.6;CK:-159.8,-21.2;CL:-70.9,-34.4;' +
  'CM:12.7,5.7;CN:103.3,36.8;CO:-73.1,3.9;CR:-84.2,10;CU:-78.9,21.6;CV:-23.6,15.1;' +
  'CW:-69,12.2;CY:33,34.9;CZ:15.3,49.7;DE:10.4,51;DJ:42.6,11.7;DK:9.3,56.2;DM:-61.4,15.4;' +
  'DO:-70.5,18.9;DZ:2.6,28.1;EC:-78.4,-1.4;EE:25.8,58.7;EG:29.9,26.5;EH:-12.3,24.2;' +
  'ER:38.8,15.4;ES:-3.6,40.4;ET:39.6,8.6;FI:26.2,64.3;FJ:178,-17.8;FK:-58.8,-51.7;' +
  'FM:158.2,6.9;FO:-6.9,62.2;FR:2.5,46.6;GA:11.8,-0.6;GB:-2.4,53.8;GD:-61.7,12.1;' +
  'GE:43.5,42.2;GG:-2.6,49.5;GH:-1.2,7.9;GL:-41.8,73.1;GM:-15.4,13.5;GN:-10.9,10.4;' +
  'GQ:10.5,1.6;GR:22.6,39.5;GS:-36.7,-54.4;GT:-90.4,15.7;GU:144.8,13.4;GW:-14.9,12.1;' +
  'GY:-59,4.8;HK:114.1,22.4;HM:73.5,-53.1;HN:-86.6,14.8;HR:16.4,45.2;HT:-72.7,18.9;' +
  'HU:19.4,47.2;ID:114,-0.2;IE:-8.1,53.2;IL:35,31.5;IM:-4.5,54.2;IN:79.5,22.8;IO:72.4,-7.3;' +
  'IQ:43.8,33;IR:54.4,32.5;IS:-18.6,65;IT:12.3,43.5;JE:-2.1,49.2;JM:-77.3,18.2;' +
  'JO:36.8,31.2;JP:137.9,36.6;KE:37.8,0.6;KG:74.5,41.5;KH:104.9,12.7;KI:-157.4,1.9;' +
  'KM:43.3,-11.7;KN:-62.7,17.3;KP:127.2,40.1;KR:127.9,36.5;KW:47.6,29.3;KY:-81.3,19.3;' +
  'KZ:67.2,48.4;LA:103.8,18.5;LB:35.9,33.9;LC:-61,13.9;LI:9.5,47.1;LK:80.7,7.6;LR:-9.3,6.5;' +
  'LS:28.2,-29.6;LT:23.9,55.3;LU:6.1,49.8;LV:24.9,56.9;LY:18.1,27;MA:-8.7,29.8;MC:7.4,43.8;' +
  'MD:28.5,47.2;ME:19.2,42.8;MF:-63.1,18.1;MG:46.7,-19.3;MH:171.2,7.1;MK:21.7,41.6;' +
  'ML:-3.6,17.3;MM:96.5,21.1;MN:103.1,47;MO:113.5,22.2;MP:145.7,15.2;MR:-10.4,20.2;' +
  'MS:-62.2,16.7;MT:14.4,35.9;MU:57.6,-20.3;MV:73.5,4.2;MW:34.3,-13.2;MX:-102.2,23.9;' +
  'MY:114.7,3.6;MZ:35.6,-17.2;NA:17.2,-22.1;NC:165.5,-21.3;NE:9.3,17.4;NF:167.9,-29.1;' +
  'NG:8.1,9.6;NI:-85,12.8;NL:5.6,52.3;NO:12.2,63.8;NP:83.9,28.3;NR:166.9,-0.5;' +
  'NU:-169.9,-19;NZ:170.6,-43.9;OM:56.1,20.6;PA:-80.1,8.5;PE:-74.4,-9.1;PF:-149.4,-17.7;' +
  'PG:144.2,-6.6;PH:121.4,15.9;PK:69.2,29.9;PL:19.4,52.1;PM:-56.3,46.9;PN:-128.3,-24.4;' +
  'PR:-66.5,18.2;PS:35.2,31.9;PT:-8,39.7;PW:134.6,7.5;PY:-58.4,-23.2;QA:51.2,25.3;' +
  'RO:25,45.8;RS:20.8,44.2;RU:95.5,65.9;RW:29.9,-2;SA:44.7,24.1;SB:160.2,-9.6;SC:55.5,-4.7;' +
  'SD:29.9,16;SE:16.2,62.4;SG:103.8,1.4;SH:-5.7,-16;SI:14.8,46.1;SK:19.5,48.7;SL:-11.8,8.6;' +
  'SM:12.5,43.9;SN:-14.5,14.4;SO:45.7,4.7;SR:-55.9,4.1;SS:30.3,7.3;ST:6.6,0.2;' +
  'SV:-88.9,13.7;SX:-63.1,18.1;SY:38.5,35;SZ:31.5,-26.6;TC:-71.7,21.8;TD:18.6,15.3;' +
  'TF:69.5,-49.3;TG:1,8.5;TH:101,15.1;TJ:71,38.5;TL:125.9,-8.8;TM:59.4,39.1;TN:9.6,34.1;' +
  'TO:-175.2,-21.2;TR:35.4,39.1;TT:-61.3,10.4;TW:121,23.7;TZ:34.8,-6.3;UA:31.3,49.2;' +
  'UG:32.4,1.3;US:-98.8,39.9;UY:-56,-32.8;UZ:63.3,41.8;VA:12.4,41.9;VC:-61.2,13.3;' +
  'VE:-66.2,7.1;VG:-64.6,18.4;VI:-64.8,17.7;VN:106.3,16.5;VU:166.8,-15.2;WF:-178.1,-14.3;' +
  'WS:-172.4,-13.6;YE:47.5,15.9;ZA:25.2,-29;ZM:27.8,-13.5;ZW:29.9,-19'

export const COUNTRY_LONLAT: Readonly<Record<string, readonly [number, number]>> =
  Object.fromEntries(
    TABLE.split(';').map((e) => {
      const [cc, ll] = e.split(':')
      const [lon, lat] = ll.split(',').map(Number)
      return [cc, [lon, lat] as const]
    }),
  )

export function lonLatOf(country: string | null | undefined): readonly [number, number] | null {
  return (country && COUNTRY_LONLAT[country.toUpperCase()]) || null
}

export type Point = readonly [number, number]

/**
 * Screen positions for `servers`: at their country's centroid, several in one
 * country spread on a small ring around it so each stays clickable. Servers
 * with no known country come back in `unplaced`, in input order.
 */
export function placeServers<T extends { agent_id: string; country: string | null }>(
  servers: readonly T[],
  project: (lonLat: readonly [number, number]) => Point | null,
  ring = 11,
): { placed: Map<string, Point>; unplaced: T[] } {
  const byCountry = new Map<string, T[]>()
  const unplaced: T[] = []
  for (const s of servers) {
    const ll = lonLatOf(s.country)
    if (!ll || !project(ll)) {
      unplaced.push(s)
      continue
    }
    const cc = s.country!.toUpperCase()
    byCountry.set(cc, [...(byCountry.get(cc) ?? []), s])
  }
  const placed = new Map<string, Point>()
  for (const [cc, group] of byCountry) {
    const [x, y] = project(COUNTRY_LONLAT[cc])!
    group.forEach((s, i) => {
      if (group.length === 1) {
        placed.set(s.agent_id, [x, y])
        return
      }
      const angle = (i / group.length) * 2 * Math.PI - Math.PI / 2
      placed.set(s.agent_id, [x + ring * Math.cos(angle), y + ring * Math.sin(angle)])
    })
  }
  return { placed, unplaced }
}

/** One key per unordered pair, as the server stores it (a < b). */
export function edgeKey(a: string, b: string): string {
  return a < b ? `${a}:${b}` : `${b}:${a}`
}

/** A gentle arc from `p` to `q`, bowed to one side so stacked edges separate. */
export function arcPath(p: Point, q: Point, bow = 0.18): string {
  const [x1, y1] = p
  const [x2, y2] = q
  const mx = (x1 + x2) / 2 - (y2 - y1) * bow
  const my = (y1 + y2) / 2 + (x2 - x1) * bow
  const r = (n: number) => Math.round(n * 10) / 10
  return `M${r(x1)},${r(y1)} Q${r(mx)},${r(my)} ${r(x2)},${r(y2)}`
}
