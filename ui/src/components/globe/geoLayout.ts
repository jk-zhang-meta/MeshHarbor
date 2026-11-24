// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Pure geographic placement, zoom-expanding cluster spread, exact spherical
// SLERP great-circle arc geometry, and hairball-preventing arc visual state
// calculation for MeshGlobe. Zero DOM or WebGL dependencies — 100% unit-testable.
import { COUNTRY_LONLAT, lonLatOf } from '@/components/admin/serverTopology'
import { formatDeviceLocation } from '@/utils/deviceLocation'
import type {
  ArcVisualState,
  GeoPrecision,
  GlobeArc,
  GlobeCenter,
  GlobeNode,
  PlacedGlobeCenter,
  PlacedGlobeNode,
  ResolvedGeo,
} from './types'

export { COUNTRY_LONLAT, lonLatOf }

/**
 * Compact self-hosted city & province/state coordinate table `[lon, lat]` covering
 * major global hubs and Chinese municipalities/provinces/cities returned by
 * `GeoIp::lookup_location` (which prefers `zh-CN` names and falls back to `en`).
 * Keys are normalized lowercase strings with common administrative suffixes stripped.
 */
const CITY_REGION_TABLE: ReadonlyArray<readonly [readonly string[], readonly [number, number]]> = [
  // Mainland China municipalities & major cities / provinces
  [['beijing', '北京'], [116.41, 39.9]],
  [['shanghai', '上海'], [121.47, 31.23]],
  [['shenzhen', '深圳'], [114.06, 22.54]],
  [['guangzhou', '广州'], [113.26, 23.13]],
  [['dongguan', '东莞'], [113.75, 23.02]],
  [['foshan', '佛山'], [113.12, 23.02]],
  [['zhuhai', '珠海'], [113.58, 22.27]],
  [['hangzhou', '杭州'], [120.15, 30.28]],
  [['ningbo', '宁波'], [121.55, 29.87]],
  [['nanjing', '南京'], [118.8, 32.06]],
  [['suzhou', '苏州'], [120.58, 31.3]],
  [['wuxi', '无锡'], [120.31, 31.49]],
  [['chengdu', '成都'], [104.07, 30.67]],
  [['chongqing', '重庆'], [106.55, 29.56]],
  [['wuhan', '武汉'], [114.3, 30.59]],
  [['xian', "xi'an", '西安'], [108.94, 34.34]],
  [['tianjin', '天津'], [117.2, 39.08]],
  [['changsha', '长沙'], [112.94, 28.23]],
  [['zhengzhou', '郑州'], [113.62, 34.75]],
  [['qingdao', '青岛'], [120.38, 36.07]],
  [['jinan', '济南'], [117.0, 36.65]],
  [['dalian', '大连'], [121.61, 38.91]],
  [['shenyang', '沈阳'], [123.43, 41.8]],
  [['harbin', '哈尔滨'], [126.53, 45.8]],
  [['changchun', '长春'], [125.32, 43.82]],
  [['fuzhou', '福州'], [119.3, 26.07]],
  [['xiamen', '厦门'], [118.09, 24.48]],
  [['hefei', '合肥'], [117.23, 31.82]],
  [['kunming', '昆明'], [102.83, 24.88]],
  [['guiyang', '贵阳'], [106.63, 26.65]],
  [['nanning', '南宁'], [108.37, 22.82]],
  [['haikou', '海口'], [110.2, 20.04]],
  [['nanchang', '南昌'], [115.86, 28.68]],
  [['shijiazhuang', '石家庄'], [114.51, 38.04]],
  [['taiyuan', '太原'], [112.55, 37.87]],
  [['hohhot', '呼和浩特'], [111.75, 40.84]],
  [['lanzhou', '兰州'], [103.83, 36.06]],
  [['urumqi', '乌鲁木齐'], [87.62, 43.83]],
  [['lhasa', '拉萨'], [91.17, 29.65]],
  // Mainland China provinces (region-level fallback)
  [['guangdong', '广东'], [113.26, 23.13]],
  [['zhejiang', '浙江'], [120.15, 30.28]],
  [['jiangsu', '江苏'], [118.8, 32.06]],
  [['sichuan', '四川'], [104.07, 30.67]],
  [['hubei', '湖北'], [114.3, 30.59]],
  [['hunan', '湖南'], [112.94, 28.23]],
  [['fujian', '福建'], [119.3, 26.07]],
  [['shandong', '山东'], [117.0, 36.65]],
  [['henan', '河南'], [113.62, 34.75]],
  [['hebei', '河北'], [114.51, 38.04]],
  [['shaanxi', '陕西'], [108.94, 34.34]],
  [['anhui', '安徽'], [117.23, 31.82]],
  [['liaoning', '辽宁'], [123.43, 41.8]],
  [['jilin', '吉林'], [125.32, 43.82]],
  [['heilongjiang', '黑龙江'], [126.53, 45.8]],
  [['yunnan', '云南'], [102.83, 24.88]],
  [['guangxi', '广西'], [108.37, 22.82]],
  [['jiangxi', '江西'], [115.86, 28.68]],
  [['shanxi', '山西'], [112.55, 37.87]],
  [['guizhou', '贵州'], [106.63, 26.65]],
  [['hainan', '海南'], [110.2, 20.04]],
  [['xinjiang', '新疆'], [87.62, 43.83]],
  // East & Southeast Asia
  [['hong kong', 'hongkong', '香港', '中国香港'], [114.17, 22.32]],
  [['macau', 'macao', '澳门', '澳門', '中国澳门'], [113.54, 22.19]],
  [['taipei', '台北', '臺北'], [121.56, 25.03]],
  [['kaohsiung', '高雄'], [120.3, 22.62]],
  [['singapore', '新加坡'], [103.82, 1.35]],
  [['tokyo', '东京', '東京'], [139.69, 35.69]],
  [['osaka', '大阪'], [135.5, 34.69]],
  [['fukuoka', '福冈'], [130.4, 33.59]],
  [['seoul', '首尔', '首爾'], [126.98, 37.57]],
  [['busan', '釜山'], [129.07, 35.18]],
  [['bangkok', '曼谷'], [100.5, 13.76]],
  [['kuala lumpur', '吉隆坡'], [101.69, 3.14]],
  [['jakarta', '雅加达'], [106.85, -6.21]],
  [['manila', '马尼拉'], [120.98, 14.6]],
  [['ho chi minh', '胡志明'], [106.63, 10.82]],
  [['hanoi', '河内'], [105.85, 21.03]],
  [['mumbai', '孟买'], [72.88, 19.08]],
  [['bengaluru', 'bangalore', '班加罗尔'], [77.59, 12.97]],
  [['new delhi', 'delhi', '新德里'], [77.21, 28.61]],
  // North America
  [['ashburn', 'virginia', '弗吉尼亚'], [-77.49, 39.04]],
  [['new york', '纽约'], [-74.01, 40.71]],
  [['boston', '波士顿'], [-71.06, 42.36]],
  [['washington', '华盛顿'], [-77.04, 38.91]],
  [['miami', '迈阿密'], [-80.19, 25.76]],
  [['atlanta', '亚特兰大'], [-84.39, 33.75]],
  [['chicago', '芝加哥'], [-87.63, 41.88]],
  [['dallas', '达拉斯'], [-96.8, 32.78]],
  [['houston', '休斯顿'], [-95.37, 29.76]],
  [['denver', '丹佛'], [-104.99, 39.74]],
  [['seattle', '西雅图'], [-122.33, 47.61]],
  [['portland', 'oregon', '波特兰', '俄勒冈'], [-122.68, 45.52]],
  [['san francisco', '旧金山', '三藩市'], [-122.42, 37.77]],
  [['san jose', 'silicon valley', '圣何塞', '圣荷西', 'california', '加利福尼亚'], [-121.89, 37.34]],
  [['los angeles', '洛杉矶'], [-118.24, 34.05]],
  [['phoenix', '凤凰城'], [-112.07, 33.45]],
  [['toronto', '多伦多'], [-79.38, 43.65]],
  [['vancouver', '温哥华'], [-123.12, 49.28]],
  [['montreal', '蒙特利尔'], [-73.57, 45.5]],
  [['mexico city', '墨西哥城'], [-99.13, 19.43]],
  // Europe
  [['frankfurt', '法兰克福'], [8.68, 50.11]],
  [['berlin', '柏林'], [13.4, 52.52]],
  [['munich', '慕尼黑'], [11.58, 48.14]],
  [['london', '伦敦'], [-0.13, 51.51]],
  [['manchester', '曼彻斯特'], [-2.24, 53.48]],
  [['amsterdam', '阿姆斯特丹'], [4.9, 52.37]],
  [['paris', '巴黎'], [2.35, 48.86]],
  [['dublin', '都柏林'], [-6.26, 53.35]],
  [['zurich', '苏黎世'], [8.54, 47.37]],
  [['stockholm', '斯德哥尔摩'], [18.07, 59.33]],
  [['helsinki', '赫尔辛基'], [24.94, 60.17]],
  [['warsaw', '华沙'], [21.01, 52.23]],
  [['madrid', '马德里'], [-3.7, 40.42]],
  [['milan', '米兰'], [9.19, 45.46]],
  [['rome', '罗马'], [12.5, 41.9]],
  [['vienna', '维也纳'], [16.37, 48.21]],
  [['prague', '布拉格'], [14.44, 50.08]],
  [['sofia', '索非亚', '索菲亚'], [23.32, 42.7]],
  [['istanbul', '伊斯坦布尔'], [28.98, 41.01]],
  [['moscow', '莫斯科'], [37.62, 55.76]],
  // Oceania, Middle East, South America, Africa
  [['sydney', '悉尼'], [151.21, -33.87]],
  [['melbourne', '墨尔本'], [144.96, -37.81]],
  [['auckland', '奥克兰'], [174.76, -36.85]],
  [['dubai', '迪拜'], [55.27, 25.2]],
  [['tel aviv', '特拉维夫'], [34.78, 32.09]],
  [['sao paulo', 'são paulo', '圣保罗'], [-46.63, -23.55]],
  [['buenos aires', '布宜诺斯艾利斯'], [-58.38, -34.6]],
  [['johannesburg', '约翰内斯堡'], [28.05, -26.2]],
  [['cape town', '开普敦'], [18.42, -33.92]],
]

const CITY_REGION_MAP: ReadonlyMap<string, readonly [number, number]> = (() => {
  const m = new Map<string, readonly [number, number]>()
  for (const [aliases, ll] of CITY_REGION_TABLE) {
    for (const a of aliases) m.set(a, ll)
  }
  return m
})()

/** Coarse PoP region hints used ONLY when country/city GeoIP is unavailable. */
const RELAY_HOME_TABLE: Readonly<Record<string, readonly [number, number]>> = {
  cn: [113.26, 23.13],
  'cn-south': [113.26, 23.13],
  'cn-east': [121.47, 31.23],
  'cn-north': [116.41, 39.9],
  hk: [114.17, 22.32],
  'ap-east': [114.17, 22.32],
  sg: [103.82, 1.35],
  'ap-southeast': [103.82, 1.35],
  jp: [139.69, 35.69],
  'ap-northeast': [139.69, 35.69],
  kr: [126.98, 37.57],
  tw: [121.56, 25.03],
  'us-east': [-77.49, 39.04],
  'us-west': [-122.42, 37.77],
  'us-central': [-96.8, 32.78],
  us: [-98.8, 39.9],
  'eu-central': [8.68, 50.11],
  'eu-west': [-0.13, 51.51],
  'eu-north': [18.07, 59.33],
  eu: [10.4, 51.0],
  de: [8.68, 50.11],
  uk: [-0.13, 51.51],
  gb: [-0.13, 51.51],
  au: [151.21, -33.87],
  'ap-south': [72.88, 19.08],
  'sa-east': [-46.63, -23.55],
}

function normalizePlaceName(raw: string | null | undefined): string {
  if (!raw) return ''
  return raw
    .trim()
    .toLowerCase()
    .replace(/(特别行政区|特別行政區|自治区|自治區|省|市|区|區|县|縣)$/u, '')
    .replace(/\s+(city|province|municipality|prefecture|s\.?a\.?r\.?)$/iu, '')
    .trim()
}

function lookupCityOrRegion(raw: string | null | undefined): readonly [number, number] | null {
  const norm = normalizePlaceName(raw)
  if (!norm) return null
  const exact = CITY_REGION_MAP.get(norm)
  if (exact) return exact
  // Prefix check for strings like "guangdong sheng" or "tokyo-to"
  for (const [k, ll] of CITY_REGION_MAP) {
    if (k.length >= 3 && (norm.startsWith(k) || k.startsWith(norm))) return ll
  }
  return null
}

function lookupRelayHome(relayHome: string | null | undefined): readonly [number, number] | null {
  if (!relayHome) return null
  const raw = relayHome.trim().toLowerCase()
  if (!raw) return null
  if (RELAY_HOME_TABLE[raw]) return RELAY_HOME_TABLE[raw]
  // Match leading region prefix (e.g., "us-east-1" → "us-east", "hk-01" → "hk")
  for (const [k, ll] of Object.entries(RELAY_HOME_TABLE)) {
    if (raw === k || raw.startsWith(`${k}-`) || raw.startsWith(`${k}_`)) return ll
  }
  const cc = raw.slice(0, 2).toUpperCase()
  return lonLatOf(cc)
}

/**
 * Resolve a node to its finest already-known geographic coordinate.
 * Never fabricates a country/city when absent; unknown nodes return
 * `precision: 'unknown'` and an empty `locationLabel`.
 */
export function resolveNodeGeo(node: GlobeNode): ResolvedGeo {
  const loc = formatDeviceLocation({
    country_code: node.countryCode,
    country: node.country,
    region: node.region,
    city: node.city,
  })
  const locationLabel = loc.locationText || loc.countryCode

  if (
    typeof node.lat === 'number' &&
    typeof node.lon === 'number' &&
    Number.isFinite(node.lat) &&
    Number.isFinite(node.lon)
  ) {
    return {
      lon: node.lon,
      lat: Math.max(-85, Math.min(85, node.lat)),
      precision: 'coords',
      locationLabel,
      bucketKey: `coords:${node.lon.toFixed(2)},${node.lat.toFixed(2)}`,
    }
  }

  const cityLL = lookupCityOrRegion(node.city)
  if (cityLL) {
    return {
      lon: cityLL[0],
      lat: cityLL[1],
      precision: 'city',
      locationLabel,
      bucketKey: `city:${normalizePlaceName(node.city)}`,
    }
  }

  const regionLL = lookupCityOrRegion(node.region)
  if (regionLL) {
    return {
      lon: regionLL[0],
      lat: regionLL[1],
      precision: 'region',
      locationLabel,
      bucketKey: `region:${normalizePlaceName(node.region)}`,
    }
  }

  const countryLL = lonLatOf(loc.countryCode) ?? lookupCityOrRegion(node.country)
  if (countryLL) {
    const key = loc.countryCode || normalizePlaceName(node.country)
    return {
      lon: countryLL[0],
      lat: countryLL[1],
      precision: 'country',
      locationLabel,
      bucketKey: `country:${key}`,
    }
  }

  const relayLL = lookupRelayHome(node.relayHome)
  if (relayLL) {
    return {
      lon: relayLL[0],
      lat: relayLL[1],
      precision: 'relay_home',
      locationLabel: '',
      bucketKey: `relay:${(node.relayHome ?? '').trim().toLowerCase()}`,
    }
  }

  // Deterministic unlocated staging band over the Pacific equator so devices
  // without GeoIP stay visible and clickable with all peer arcs, while their
  // panel honestly reports location as unknown.
  return {
    lon: -158,
    lat: 4,
    precision: 'unknown',
    locationLabel: '',
    bucketKey: 'unknown',
  }
}

/**
 * Deterministic geo-spread offset (degrees `[dLon, dLat]`) for co-located nodes.
 * - `count <= 1`: zero offset (sits cleanly on its true geographic anchor).
 * - `count > 1`: golden-angle spiral / concentric ring around the anchor.
 * - `zoomLevel` in `[0, 1]` (0 = full planet overview, 1 = zoomed regional close-up):
 *   tightly clustered near the anchor at overview so devices don't drift into
 *   neighbouring countries, expanding cleanly as the user zooms in so every
 *   co-located device separates into an effortlessly clickable ring.
 */
export function computeClusterOffset(
  index: number,
  count: number,
  zoomLevel = 0,
  baseLat = 0,
): readonly [number, number] {
  if (count <= 1) return [0, 0]
  const z = Math.max(0, Math.min(1, zoomLevel))
  // Base radius grows smoothly with zoom (0.95° at overview → 2.6° zoomed in)
  // and scales gently with sqrt(count) for dense cities.
  const scale = (0.95 + z * 1.65) * (1 + Math.min(1.1, Math.sqrt(count - 1) * 0.24))
  // Single ring for <= 8 nodes; two-tier golden spiral for larger clusters.
  let angle: number
  let radial: number
  if (count <= 8) {
    angle = (index / count) * Math.PI * 2 - Math.PI / 2
    radial = scale
  } else {
    const golden = 2.399963229728653
    angle = index * golden
    radial = scale * (0.45 + 0.65 * Math.sqrt((index + 0.5) / count))
  }
  // Compensate longitude by cos(lat) so visual circles stay round away from equator.
  const cosLat = Math.max(0.25, Math.cos((baseLat * Math.PI) / 180))
  const dLat = Math.sin(angle) * radial
  const dLon = (Math.cos(angle) * radial) / cosLat
  return [dLon, dLat]
}

export interface Vec3Tuple {
  x: number
  y: number
  z: number
}

/** Convert geographic `(lat, lon)` in degrees to Three.js sphere Cartesian coordinates. */
export function latLonToVec3(lat: number, lon: number, radius = 1): Vec3Tuple {
  const phi = ((90 - lat) * Math.PI) / 180
  const theta = ((lon + 180) * Math.PI) / 180
  return {
    x: -radius * Math.sin(phi) * Math.cos(theta),
    y: radius * Math.cos(phi),
    z: radius * Math.sin(phi) * Math.sin(theta),
  }
}

/** Convert Three.js sphere Cartesian coordinates back to `(lat, lon)` in degrees. */
export function vec3ToLatLon(v: Vec3Tuple): { lat: number; lon: number } {
  const r = Math.hypot(v.x, v.y, v.z) || 1
  const lat = 90 - (Math.acos(Math.max(-1, Math.min(1, v.y / r))) * 180) / Math.PI
  // theta = atan2(z, -x) ∈ (-π, π]; lon = theta*180/π - 180 normalized to [-180, 180]
  let lon = (Math.atan2(v.z, -v.x) * 180) / Math.PI - 180
  if (lon < -180) lon += 360
  if (lon > 180) lon -= 360
  return { lat, lon }
}

/**
 * Place all nodes and the control-plane centre deterministically on the globe.
 * Nodes inside the same geographic bucket are sorted stably (online first, then
 * name, then id) so polls never shuffle positions.
 */
export function placeGlobeNodes(
  nodes: readonly GlobeNode[],
  center?: GlobeCenter | null,
  zoomLevel = 0,
): { nodes: PlacedGlobeNode[]; center: PlacedGlobeCenter | null } {
  const resolved = nodes.map((node) => ({ node, geo: resolveNodeGeo(node) }))
  const buckets = new Map<string, Array<{ node: GlobeNode; geo: ResolvedGeo }>>()
  for (const item of resolved) {
    const list = buckets.get(item.geo.bucketKey)
    if (list) list.push(item)
    else buckets.set(item.geo.bucketKey, [item])
  }

  const placed: PlacedGlobeNode[] = []
  for (const [, group] of buckets) {
    group.sort(
      (a, b) =>
        Number(b.node.online) - Number(a.node.online) ||
        a.node.name.localeCompare(b.node.name) ||
        a.node.id.localeCompare(b.node.id),
    )
    const count = group.length
    group.forEach(({ node, geo }, idx) => {
      // Unknown-location devices fan gently along a clean staging arc
      let lon = geo.lon
      let lat = geo.lat
      if (geo.precision === 'unknown' && count > 1) {
        const span = Math.min(28, 3.6 * (count - 1))
        const offset = -span / 2 + (span * idx) / (count - 1)
        lon = geo.lon + offset
        lat = geo.lat + Math.sin((idx / count) * Math.PI) * 3.5
      } else {
        const [dLon, dLat] = computeClusterOffset(idx, count, zoomLevel, geo.lat)
        lon = geo.lon + dLon
        lat = Math.max(-84, Math.min(84, geo.lat + dLat))
      }
      // Wrap longitude cleanly to [-180, 180]
      if (lon > 180) lon -= 360
      if (lon < -180) lon += 360

      placed.push({
        ...node,
        baseLon: geo.lon,
        baseLat: geo.lat,
        lon,
        lat,
        precision: geo.precision,
        locationLabel: geo.locationLabel,
        clusterSize: count,
        clusterIndex: idx,
      })
    })
  }

  // Keep output order deterministic across renders
  placed.sort((a, b) => a.id.localeCompare(b.id))

  let placedCenter: PlacedGlobeCenter | null = null
  if (center) {
    if (
      typeof center.lat === 'number' &&
      typeof center.lon === 'number' &&
      Number.isFinite(center.lat) &&
      Number.isFinite(center.lon)
    ) {
      placedCenter = { ...center, lon: center.lon, lat: center.lat, orbital: false }
    } else {
      const ccLL = lonLatOf(center.countryCode)
      if (ccLL) {
        placedCenter = { ...center, lon: ccLL[0], lat: ccLL[1], orbital: false }
      } else {
        // Compute spherical centroid of located devices (or gentle default view if none)
        const located = placed.filter((n) => n.precision !== 'unknown')
        if (located.length > 0) {
          let sx = 0
          let sy = 0
          let sz = 0
          for (const n of located) {
            const v = latLonToVec3(n.lat, n.lon, 1)
            sx += v.x
            sy += v.y
            sz += v.z
          }
          const mag = Math.hypot(sx, sy, sz)
          if (mag > 0.05) {
            const cLL = vec3ToLatLon({ x: sx / mag, y: sy / mag, z: sz / mag })
            // Slight northern offset so the orbital hub sits clearly above a tight cluster
            placedCenter = {
              ...center,
              lon: cLL.lon,
              lat: Math.max(-75, Math.min(75, cLL.lat + 6)),
              orbital: true,
            }
          } else {
            placedCenter = { ...center, lon: 105, lat: 24, orbital: true }
          }
        } else {
          placedCenter = { ...center, lon: 105, lat: 24, orbital: true }
        }
      }
    }
  }

  return { nodes: placed, center: placedCenter }
}

/**
 * Exact spherical linear interpolation (SLERP) great-circle arc points in 3D space.
 * Handles near-co-located endpoints (adds a clean readable mini-arch) AND exact
 * antipodal endpoints (picks a deterministic perpendicular great-circle plane so
 * arcs never dive through the planet core).
 */
export function buildGreatCircleArcPoints(
  fromLat: number,
  fromLon: number,
  toLat: number,
  toLon: number,
  segments = 36,
  surfaceRadius = 1.008,
  altitudeBoost = 0,
): Vec3Tuple[] {
  const a = latLonToVec3(fromLat, fromLon, 1)
  const b = latLonToVec3(toLat, toLon, 1)
  const dot = Math.max(-1, Math.min(1, a.x * b.x + a.y * b.y + a.z * b.z))
  const omega = Math.acos(dot)
  const sinO = Math.sin(omega)

  // Elevation scales cleanly with angular distance, with a crisp minimum arch for
  // nearby/co-located peers so short arcs stay visible and clickable.
  const archHeight = Math.min(0.42, 0.032 + (omega / Math.PI) * 0.34) + altitudeBoost

  // Deterministic perpendicular unit vector for near-antipodal pairs (omega ≈ π).
  let perp: Vec3Tuple | null = null
  if (omega > Math.PI - 1e-3) {
    const ref = Math.abs(a.y) < 0.9 ? { x: 0, y: 1, z: 0 } : { x: 1, y: 0, z: 0 }
    const cx = a.y * ref.z - a.z * ref.y
    const cy = a.z * ref.x - a.x * ref.z
    const cz = a.x * ref.y - a.y * ref.x
    const m = Math.hypot(cx, cy, cz) || 1
    perp = { x: cx / m, y: cy / m, z: cz / m }
  }

  const pts: Vec3Tuple[] = []
  for (let i = 0; i <= segments; i++) {
    const t = i / segments
    let ux: number
    let uy: number
    let uz: number
    if (omega < 1e-4) {
      ux = a.x
      uy = a.y
      uz = a.z
    } else if (perp) {
      const ang = t * Math.PI
      const ca = Math.cos(ang)
      const sa = Math.sin(ang)
      ux = a.x * ca + perp.x * sa
      uy = a.y * ca + perp.y * sa
      uz = a.z * ca + perp.z * sa
    } else {
      const w0 = Math.sin((1 - t) * omega) / sinO
      const w1 = Math.sin(t * omega) / sinO
      ux = w0 * a.x + w1 * b.x
      uy = w0 * a.y + w1 * b.y
      uz = w0 * a.z + w1 * b.z
    }
    const len = Math.hypot(ux, uy, uz) || 1
    const r = surfaceRadius + Math.sin(t * Math.PI) * archHeight
    pts.push({ x: (ux / len) * r, y: (uy / len) * r, z: (uz / len) * r })
  }
  return pts
}

export interface ArcFocusState {
  hoveredNodeId: string | null
  selectedNodeId: string | null
  hoveredArcKey: string | null
  selectedArcKey: string | null
}

/**
 * Compute per-arc opacity, emphasis, and pulse strength so dense meshes (~300 edges)
 * stay airy and scannable at rest, while hovering or selecting a node/link brings its
 * incident edges into sharp focus and dims unrelated links out of the way.
 */
export function computeArcVisualStates(
  arcs: readonly GlobeArc[],
  focus: ArcFocusState,
): ArcVisualState[] {
  const peerCount = arcs.filter((a) => a.kind !== 'control').length
  // Density-adaptive resting opacity prevents a 300-arc hairball.
  const basePeerOpacity =
    peerCount > 180 ? 0.17 : peerCount > 80 ? 0.24 : peerCount > 25 ? 0.34 : 0.52
  const activeArcKey = focus.hoveredArcKey ?? focus.selectedArcKey
  const activeNodeId = activeArcKey ? null : (focus.hoveredNodeId ?? focus.selectedNodeId)

  return arcs.map((arc) => {
    const isControl = arc.kind === 'control'
    const dashed = Boolean(arc.dashed || arc.stalled || arc.blocked || arc.enabled === false)

    if (activeArcKey) {
      const hit = arc.key === activeArcKey
      return {
        key: arc.key,
        opacity: hit ? 0.98 : 0.045,
        emphasis: hit ? 1.0 : 0.0,
        pulseStrength: hit ? (arc.blocked ? 0 : 1.0) : 0.05,
        dashed,
      }
    }

    if (activeNodeId) {
      const incident = arc.from === activeNodeId || arc.to === activeNodeId
      return {
        key: arc.key,
        opacity: incident ? (isControl ? 0.72 : 0.92) : 0.04,
        emphasis: incident ? 1.0 : 0.0,
        pulseStrength: incident ? (arc.blocked ? 0 : isControl ? 0.5 : 0.95) : 0.04,
        dashed,
      }
    }

    return {
      key: arc.key,
      opacity: isControl ? 0.22 : basePeerOpacity,
      emphasis: 0.5,
      pulseStrength: arc.blocked || isControl ? 0 : 0.68,
      dashed,
    }
  })
}
