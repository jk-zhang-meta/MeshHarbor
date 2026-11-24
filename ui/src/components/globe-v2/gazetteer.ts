// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Lazy-loaded offline gazetteer (Natural Earth 5.1.2 public domain + curated
// cloud/mesh hubs) and pure location resolution (FR-136 S4 / S6 / S7 / S11 / AC7).
//
// Rules:
// - `loadGazetteer()` uses dynamic `import('./data/gazetteer-v1.json')` cached
//   as a single promise so 0 B enters the main entry bundle.
// - `resolveFromGazetteer()` resolves strictly in deterministic precedence:
//   city > region > country > null. NEVER falls back to `relayHome`.
// - Neutral region naming overrides (TW/HK/MO) are enforced in both data and
//   runtime lookup so Taiwan, Hong Kong, and Macau are never labelled as countries
//   or "Republic of China" / "China, Taiwan".

export type GazetteerTuple = readonly [lon: number, lat: number, nameEn: string, nameZh: string]

export interface GazetteerV1 {
  version: 1
  /** ISO-2 uppercase -> [lon, lat, name_en, name_zh] */
  countries: Record<string, GazetteerTuple>
  /** "${CC}:${normalized_region_name}" -> [lon, lat, name_en, name_zh] */
  regions: Record<string, GazetteerTuple>
  /** "${CC}:${normalized_city_name}" -> [lon, lat, name_en, name_zh] */
  cities: Record<string, GazetteerTuple>
}

export type GazetteerPrecision = 'city' | 'region' | 'country'

export interface GazetteerQuery {
  countryCode?: string | null
  country?: string | null
  region?: string | null
  city?: string | null
}

export interface GazetteerResolution {
  lon: number
  lat: number
  precision: GazetteerPrecision
  labelEn: string
  labelZh: string
}

/** Neutral country/region overrides (FR-136 S6 / AC7). */
export const NEUTRAL_REGION_OVERRIDES: Readonly<
  Record<string, Readonly<{ en: string; zh: string }>>
> = {
  TW: { en: 'Taiwan', zh: '台湾' },
  HK: { en: 'Hong Kong', zh: '香港' },
  MO: { en: 'Macau', zh: '澳门' },
}

/** Required map data attribution strings (FR-136 S6). */
export const ATTRIBUTION_TEXT: Readonly<{ en: string; 'zh-CN': string }> = {
  en: 'Boundaries: Natural Earth (public domain); geoBoundaries (CC BY 4.0); © OpenStreetMap contributors (ODbL); UN OCHA (CC BY-IGO)',
  'zh-CN':
    '边界：Natural Earth（公有领域）；geoBoundaries（CC BY 4.0）；© OpenStreetMap 贡献者（ODbL）；UN OCHA（CC BY-IGO）',
}

// Keep synchronized verbatim with `TRAD_TO_SIMP` in scripts/globe/build-gazetteer.py
const TRAD_TO_SIMP: Readonly<Record<string, string>> = {
  臺: '台', 灣: '湾', 門: '门', 東: '东', 廣: '广', 爾: '尔',
  蘇: '苏', 慶: '庆', 漢: '汉', 陽: '阳', 長: '长', 鄭: '郑',
  濟: '济', 連: '连', 瀋: '沈', 濱: '滨', 寧: '宁', 廈: '厦',
  貴: '贵', 蘭: '兰', 烏: '乌', 魯: '鲁', 齊: '齐', 薩: '萨',
  陝: '陕', 遼: '辽', 龍: '龙', 華: '华', 國: '国', 區: '区',
  縣: '县', 島: '岛', 嶺: '岭', 紐: '纽', 約: '约', 舊: '旧',
  倫: '伦', 聖: '圣', 羅: '罗', 維: '维', 馬: '马', 亞: '亚',
  開: '开', 達: '达', 岡: '冈', 買: '买', 來: '来', 溫: '温',
  頓: '顿', 鳳: '凤', 茲: '兹', 圖: '图', 葉: '叶', 庫: '库',
  澤: '泽', 閩: '闽', 贛: '赣', 滬: '沪', 粵: '粤', 瓊: '琼',
  晉: '晋', 隴: '陇', 莊: '庄', 壯: '壮', 內: '内', 鐵: '铁',
  銀: '银', 揚: '扬', 紹: '绍', 興: '兴', 蕪: '芜', 濰: '潍',
  煙: '烟', 萊: '莱', 嶽: '岳', 婁: '娄', 義: '义', 綿: '绵',
  樂: '乐', 瀘: '泸', 賓: '宾', 資: '资', 銅: '铜', 畢: '毕',
  節: '节', 紅: '红', 麗: '丽', 寶: '宝', 雞: '鸡', 運: '运',
  臨: '临', 呂: '吕', 滄: '沧', 鄲: '郸', 張: '张', 撫: '抚',
  順: '顺', 營: '营', 錦: '锦', 盤: '盘', 蘆: '芦', 綏: '绥',
  鶴: '鹤', 崗: '岗', 雙: '双', 鴨: '鸭', 鎮: '镇', 鄉: '乡',
  餘: '余', 鷹: '鹰', 饒: '饶', 棗: '枣', 許: '许', 駐: '驻',
  荊: '荆', 黃: '黄', 隨: '随', 懷: '怀', 欽: '钦', 賀: '贺',
  鹽: '盐', 遷: '迁', 雲: '云', 萬: '万', 歷: '历', 麥: '麦',
  奧: '奥', 歐: '欧', 愛: '爱', 盧: '卢', 納: '纳', 韋: '韦',
  裡: '里', 緬: '缅', 韓: '韩', 鮮: '鲜', 臘: '腊', 聯: '联',
}

const RE_COMBINING = /[\u0300-\u036f]/g
const RE_APOSTROPHE = /['’`]/g
const RE_NON_WORD = /[^\p{L}\p{N}]+/gu
const RE_CJK_PREFIX = /^中国(?=(香港|澳门|台湾))/u
const RE_CJK_SUFFIX =
  /(特别行政区|维吾尔自治区|壮族自治区|回族自治区|自治区|自治州|自治县|地区|省|市|区|县|盟)$/u
const RE_EN_SUFFIX =
  /\s+(special administrative region|autonomous region|municipality|prefecture|metropolitan|metropolis|province|district|county|region|oblast|state|krai|city|sar)$/i

const ISO2_ALIASES: Readonly<Record<string, string>> = {
  UK: 'GB',
  TWN: 'TW',
  HKG: 'HK',
  MAC: 'MO',
  CHN: 'CN',
  USA: 'US',
}

function toSimplifiedChars(input: string): string {
  let out = ''
  for (const ch of input) {
    out += TRAD_TO_SIMP[ch] ?? ch
  }
  return out
}

/**
 * Normalize a country, region, or city label into the canonical gazetteer lookup key.
 * Strips accents, apostrophes, punctuation, Traditional CJK variants, and common
 * administrative suffixes (e.g., 省/市/特别行政区/City/Province).
 */
export function normalizeGeoKey(raw: string | null | undefined): string {
  if (!raw) return ''
  const trimmed = raw.trim()
  if (!trimmed || trimmed === '-' || trimmed === '—' || trimmed === '–') return ''

  let s = toSimplifiedChars(trimmed)
    .normalize('NFKD')
    .replace(RE_COMBINING, '')
    .toLowerCase()
    .replace(RE_APOSTROPHE, '')
    .replace(RE_NON_WORD, ' ')
    .trim()
    .replace(RE_CJK_PREFIX, '')
    .trim()

  for (let i = 0; i < 2; i++) {
    const cjk = s.replace(RE_CJK_SUFFIX, '').trim()
    if (cjk.length >= 2 && cjk !== s) {
      s = cjk
      continue
    }
    const en = s.replace(RE_EN_SUFFIX, '').trim()
    if (en.length >= 2 && en !== s) {
      s = en
      continue
    }
    break
  }

  return s
}

interface GazetteerIndex {
  countryByName: Map<string, string>
  cityByName: Map<string, { cc: string; tuple: GazetteerTuple }>
  regionByName: Map<string, { cc: string; tuple: GazetteerTuple }>
}

const indexCache = new WeakMap<GazetteerV1, GazetteerIndex>()

function getGazetteerIndex(gazetteer: GazetteerV1): GazetteerIndex {
  const cached = indexCache.get(gazetteer)
  if (cached) return cached

  const countryByName = new Map<string, string>()
  for (const [cc, tuple] of Object.entries(gazetteer.countries)) {
    const enKey = normalizeGeoKey(tuple[2])
    const zhKey = normalizeGeoKey(tuple[3])
    if (enKey && !countryByName.has(enKey)) countryByName.set(enKey, cc)
    if (zhKey && !countryByName.has(zhKey)) countryByName.set(zhKey, cc)
  }
  // Common country/region name aliases (never treating TW/HK/MO as "country")
  const extraCountryAliases: ReadonlyArray<readonly [string, string]> = [
    ['china', 'CN'],
    ['peoples republic of china', 'CN'],
    ['prc', 'CN'],
    ['中华人民共和国', 'CN'],
    ['united states of america', 'US'],
    ['usa', 'US'],
    ['uk', 'GB'],
    ['great britain', 'GB'],
    ['taiwan', 'TW'],
    ['台湾', 'TW'],
    ['hong kong', 'HK'],
    ['hongkong', 'HK'],
    ['香港', 'HK'],
    ['macau', 'MO'],
    ['macao', 'MO'],
    ['澳门', 'MO'],
    ['korea', 'KR'],
    ['republic of korea', 'KR'],
    ['russian federation', 'RU'],
  ]
  for (const [alias, cc] of extraCountryAliases) {
    if (gazetteer.countries[cc] && !countryByName.has(alias)) {
      countryByName.set(alias, cc)
    }
  }

  const cityByName = new Map<string, { cc: string; tuple: GazetteerTuple }>()
  for (const [key, tuple] of Object.entries(gazetteer.cities)) {
    const sep = key.indexOf(':')
    if (sep <= 0) continue
    const cc = key.slice(0, sep)
    const nameKey = key.slice(sep + 1)
    if (nameKey && !cityByName.has(nameKey)) {
      cityByName.set(nameKey, { cc, tuple })
    }
  }

  const regionByName = new Map<string, { cc: string; tuple: GazetteerTuple }>()
  for (const [key, tuple] of Object.entries(gazetteer.regions)) {
    const sep = key.indexOf(':')
    if (sep <= 0) continue
    const cc = key.slice(0, sep)
    const nameKey = key.slice(sep + 1)
    if (nameKey && !regionByName.has(nameKey)) {
      regionByName.set(nameKey, { cc, tuple })
    }
  }

  const built: GazetteerIndex = { countryByName, cityByName, regionByName }
  indexCache.set(gazetteer, built)
  return built
}

function resolveCountryCode(
  gazetteer: GazetteerV1,
  rawCode?: string | null,
  rawCountry?: string | null,
): string {
  const cleanedCode = (rawCode ?? '').trim().toUpperCase()
  if (cleanedCode) {
    const aliased = ISO2_ALIASES[cleanedCode] ?? cleanedCode
    if (/^[A-Z]{2}$/.test(aliased)) return aliased
  }
  const normCountry = normalizeGeoKey(rawCountry)
  if (!normCountry) return ''
  const upper = normCountry.toUpperCase()
  if (/^[A-Z]{2}$/.test(upper) && gazetteer.countries[upper]) return upper
  const idx = getGazetteerIndex(gazetteer)
  return idx.countryByName.get(normCountry) ?? ''
}

function formatResult(
  tuple: GazetteerTuple,
  precision: GazetteerPrecision,
  cc: string,
): GazetteerResolution {
  const override = precision === 'country' ? NEUTRAL_REGION_OVERRIDES[cc] : undefined
  return {
    lon: tuple[0],
    lat: tuple[1],
    precision,
    labelEn: override ? override.en : tuple[2],
    labelZh: override ? override.zh : tuple[3],
  }
}

/**
 * Pure deterministic location lookup against `GazetteerV1` (FR-136 S4 / S7).
 * Precedence: `city` > `region` > `country` > `null`.
 * When `countryCode` (or `country`) is provided, city & region matches are
 * strictly scoped to that country/region to prevent cross-country collisions.
 * NEVER uses `relayHome` and NEVER applies geographic scatter.
 */
export function resolveFromGazetteer(
  gazetteer: GazetteerV1,
  query: GazetteerQuery,
): GazetteerResolution | null {
  const cc = resolveCountryCode(gazetteer, query.countryCode, query.country)
  const normCity = normalizeGeoKey(query.city)
  const normRegion = normalizeGeoKey(query.region)

  // 1. City precision (scoped to `cc` whenever known)
  if (normCity) {
    if (cc) {
      const hit = gazetteer.cities[`${cc}:${normCity}`]
      if (hit) return formatResult(hit, 'city', cc)
    } else {
      const hit = getGazetteerIndex(gazetteer).cityByName.get(normCity)
      if (hit) return formatResult(hit.tuple, 'city', hit.cc)
    }
  }

  // 2. Region / state / province precision (scoped to `cc` whenever known)
  if (normRegion) {
    if (cc) {
      const regionHit = gazetteer.regions[`${cc}:${normRegion}`]
      if (regionHit) return formatResult(regionHit, 'region', cc)
      // Direct-administered municipality fallback (e.g. CN + region="Beijing", city=null)
      const cityAsRegion = gazetteer.cities[`${cc}:${normRegion}`]
      if (cityAsRegion) return formatResult(cityAsRegion, 'region', cc)
    } else {
      const hit = getGazetteerIndex(gazetteer).regionByName.get(normRegion)
      if (hit) return formatResult(hit.tuple, 'region', hit.cc)
    }
  }

  // 3. Country / region label point (NE LABEL_X / LABEL_Y + neutral overrides)
  if (cc) {
    const countryHit = gazetteer.countries[cc]
    if (countryHit) return formatResult(countryHit, 'country', cc)
  }

  return null
}

let cachedPromise: Promise<GazetteerV1> | null = null

/**
 * Lazily load `gazetteer-v1.json` as an async Vite chunk (0 B in main entry bundle).
 * Result is memoized in a module-level promise.
 */
export function loadGazetteer(): Promise<GazetteerV1> {
  if (!cachedPromise) {
    cachedPromise = import('./data/gazetteer-v1.json').then(
      (mod) => (mod.default ?? mod) as unknown as GazetteerV1,
    )
  }
  return cachedPromise
}
