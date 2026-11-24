// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Location resolution adapter for the MapLibre v2 globe (S4 / S7 / AC1 / AC14).
// - Defines the exact P1 `GazetteerV1` contract so P1's `gazetteer.ts` plugs in cleanly.
// - Auto-discovers `./gazetteer.ts` via `import.meta.glob` when present (zero build error
//   when absent during standalone P2/P3 development, zero bytes in main SPA entry).
// - Consumes P6 `lat` / `lon` / `accuracyRadiusKm` / `geoLevel` whenever present on devices.
// - Falls back to built-in city/region/country lookup when external gazetteer is not yet loaded.
// - NEVER uses `relayHome` for placement (S4 / AC14).

import { COUNTRY_LONLAT, lonLatOf } from '@/components/admin/serverTopology'
import { formatDeviceLocation } from '@/utils/deviceLocation'
import type { GlobeNode } from '@/components/globe/types'
import { formatNeutralRegionName } from './tokens'

export type V2GeoPrecision = 'coords' | 'city' | 'region' | 'country' | 'unknown'

/** Exact P1 gazetteer tuple: `[lon, lat, nameEn, nameZh]`. */
export type GazetteerTuple = readonly [number, number, string, string]

/** Exact P1 gazetteer JSON schema (`ui/src/components/globe-v2/data/gazetteer-v1.json`). */
export interface GazetteerV1 {
  version: 1
  countries: Record<string, GazetteerTuple>
  regions: Record<string, GazetteerTuple>
  cities: Record<string, GazetteerTuple>
}

export interface ResolvedV2Location {
  precision: V2GeoPrecision
  lon: number | null
  lat: number | null
  accuracyRadiusKm: number | null
  groupKey: string | null
  placeEn: string
  placeZh: string
  locationLabel: string
  countryCode: string
}

interface BuiltinPlace {
  aliases: readonly string[]
  ll: readonly [number, number]
  cc: string
  en: string
  zh: string
  level: 'city' | 'region'
}

const BUILTIN_PLACES: readonly BuiltinPlace[] = [
  // Mainland China cities
  { aliases: ['beijing', '北京'], ll: [116.41, 39.9], cc: 'CN', en: 'Beijing', zh: '北京', level: 'city' },
  { aliases: ['shanghai', '上海'], ll: [121.47, 31.23], cc: 'CN', en: 'Shanghai', zh: '上海', level: 'city' },
  { aliases: ['shenzhen', '深圳'], ll: [114.06, 22.54], cc: 'CN', en: 'Shenzhen', zh: '深圳', level: 'city' },
  { aliases: ['guangzhou', '广州'], ll: [113.26, 23.13], cc: 'CN', en: 'Guangzhou', zh: '广州', level: 'city' },
  { aliases: ['dongguan', '东莞'], ll: [113.75, 23.02], cc: 'CN', en: 'Dongguan', zh: '东莞', level: 'city' },
  { aliases: ['foshan', '佛山'], ll: [113.12, 23.02], cc: 'CN', en: 'Foshan', zh: '佛山', level: 'city' },
  { aliases: ['zhuhai', '珠海'], ll: [113.58, 22.27], cc: 'CN', en: 'Zhuhai', zh: '珠海', level: 'city' },
  { aliases: ['hangzhou', '杭州'], ll: [120.15, 30.28], cc: 'CN', en: 'Hangzhou', zh: '杭州', level: 'city' },
  { aliases: ['ningbo', '宁波'], ll: [121.55, 29.87], cc: 'CN', en: 'Ningbo', zh: '宁波', level: 'city' },
  { aliases: ['nanjing', '南京'], ll: [118.8, 32.06], cc: 'CN', en: 'Nanjing', zh: '南京', level: 'city' },
  { aliases: ['suzhou', '苏州'], ll: [120.58, 31.3], cc: 'CN', en: 'Suzhou', zh: '苏州', level: 'city' },
  { aliases: ['wuxi', '无锡'], ll: [120.31, 31.49], cc: 'CN', en: 'Wuxi', zh: '无锡', level: 'city' },
  { aliases: ['chengdu', '成都'], ll: [104.07, 30.67], cc: 'CN', en: 'Chengdu', zh: '成都', level: 'city' },
  { aliases: ['chongqing', '重庆'], ll: [106.55, 29.56], cc: 'CN', en: 'Chongqing', zh: '重庆', level: 'city' },
  { aliases: ['wuhan', '武汉'], ll: [114.3, 30.59], cc: 'CN', en: 'Wuhan', zh: '武汉', level: 'city' },
  { aliases: ['xian', "xi'an", '西安'], ll: [108.94, 34.34], cc: 'CN', en: "Xi'an", zh: '西安', level: 'city' },
  { aliases: ['tianjin', '天津'], ll: [117.2, 39.08], cc: 'CN', en: 'Tianjin', zh: '天津', level: 'city' },
  { aliases: ['changsha', '长沙'], ll: [112.94, 28.23], cc: 'CN', en: 'Changsha', zh: '长沙', level: 'city' },
  { aliases: ['zhengzhou', '郑州'], ll: [113.62, 34.75], cc: 'CN', en: 'Zhengzhou', zh: '郑州', level: 'city' },
  { aliases: ['qingdao', '青岛'], ll: [120.38, 36.07], cc: 'CN', en: 'Qingdao', zh: '青岛', level: 'city' },
  { aliases: ['jinan', '济南'], ll: [117.0, 36.65], cc: 'CN', en: 'Jinan', zh: '济南', level: 'city' },
  { aliases: ['dalian', '大连'], ll: [121.61, 38.91], cc: 'CN', en: 'Dalian', zh: '大连', level: 'city' },
  { aliases: ['shenyang', '沈阳'], ll: [123.43, 41.8], cc: 'CN', en: 'Shenyang', zh: '沈阳', level: 'city' },
  { aliases: ['harbin', '哈尔滨'], ll: [126.53, 45.8], cc: 'CN', en: 'Harbin', zh: '哈尔滨', level: 'city' },
  { aliases: ['changchun', '长春'], ll: [125.32, 43.82], cc: 'CN', en: 'Changchun', zh: '长春', level: 'city' },
  { aliases: ['fuzhou', '福州'], ll: [119.3, 26.07], cc: 'CN', en: 'Fuzhou', zh: '福州', level: 'city' },
  { aliases: ['xiamen', '厦门'], ll: [118.09, 24.48], cc: 'CN', en: 'Xiamen', zh: '厦门', level: 'city' },
  { aliases: ['hefei', '合肥'], ll: [117.23, 31.82], cc: 'CN', en: 'Hefei', zh: '合肥', level: 'city' },
  { aliases: ['kunming', '昆明'], ll: [102.83, 24.88], cc: 'CN', en: 'Kunming', zh: '昆明', level: 'city' },
  { aliases: ['guiyang', '贵阳'], ll: [106.63, 26.65], cc: 'CN', en: 'Guiyang', zh: '贵阳', level: 'city' },
  { aliases: ['nanning', '南宁'], ll: [108.37, 22.82], cc: 'CN', en: 'Nanning', zh: '南宁', level: 'city' },
  { aliases: ['haikou', '海口'], ll: [110.2, 20.04], cc: 'CN', en: 'Haikou', zh: '海口', level: 'city' },
  { aliases: ['nanchang', '南昌'], ll: [115.86, 28.68], cc: 'CN', en: 'Nanchang', zh: '南昌', level: 'city' },
  { aliases: ['shijiazhuang', '石家庄'], ll: [114.51, 38.04], cc: 'CN', en: 'Shijiazhuang', zh: '石家庄', level: 'city' },
  { aliases: ['taiyuan', '太原'], ll: [112.55, 37.87], cc: 'CN', en: 'Taiyuan', zh: '太原', level: 'city' },
  { aliases: ['hohhot', '呼和浩特'], ll: [111.75, 40.84], cc: 'CN', en: 'Hohhot', zh: '呼和浩特', level: 'city' },
  { aliases: ['lanzhou', '兰州'], ll: [103.83, 36.06], cc: 'CN', en: 'Lanzhou', zh: '兰州', level: 'city' },
  { aliases: ['urumqi', '乌鲁木齐'], ll: [87.62, 43.83], cc: 'CN', en: 'Urumqi', zh: '乌鲁木齐', level: 'city' },
  { aliases: ['lhasa', '拉萨'], ll: [91.17, 29.65], cc: 'CN', en: 'Lhasa', zh: '拉萨', level: 'city' },
  // Mainland China provinces (region centroids)
  { aliases: ['guangdong', '广东'], ll: [113.42, 23.34], cc: 'CN', en: 'Guangdong', zh: '广东省', level: 'region' },
  { aliases: ['zhejiang', '浙江'], ll: [120.1, 29.18], cc: 'CN', en: 'Zhejiang', zh: '浙江省', level: 'region' },
  { aliases: ['jiangsu', '江苏'], ll: [119.48, 32.98], cc: 'CN', en: 'Jiangsu', zh: '江苏省', level: 'region' },
  { aliases: ['sichuan', '四川'], ll: [102.71, 30.61], cc: 'CN', en: 'Sichuan', zh: '四川省', level: 'region' },
  { aliases: ['hubei', '湖北'], ll: [112.27, 30.98], cc: 'CN', en: 'Hubei', zh: '湖北省', level: 'region' },
  { aliases: ['hunan', '湖南'], ll: [111.71, 27.61], cc: 'CN', en: 'Hunan', zh: '湖南省', level: 'region' },
  { aliases: ['fujian', '福建'], ll: [117.98, 26.08], cc: 'CN', en: 'Fujian', zh: '福建省', level: 'region' },
  { aliases: ['shandong', '山东'], ll: [118.14, 36.34], cc: 'CN', en: 'Shandong', zh: '山东省', level: 'region' },
  { aliases: ['henan', '河南'], ll: [113.61, 33.88], cc: 'CN', en: 'Henan', zh: '河南省', level: 'region' },
  { aliases: ['hebei', '河北'], ll: [115.46, 39.55], cc: 'CN', en: 'Hebei', zh: '河北省', level: 'region' },
  { aliases: ['shaanxi', '陕西'], ll: [108.87, 35.19], cc: 'CN', en: 'Shaanxi', zh: '陕西省', level: 'region' },
  { aliases: ['anhui', '安徽'], ll: [117.22, 31.83], cc: 'CN', en: 'Anhui', zh: '安徽省', level: 'region' },
  { aliases: ['liaoning', '辽宁'], ll: [122.6, 41.3], cc: 'CN', en: 'Liaoning', zh: '辽宁省', level: 'region' },
  { aliases: ['jilin', '吉林'], ll: [126.18, 43.67], cc: 'CN', en: 'Jilin', zh: '吉林省', level: 'region' },
  { aliases: ['heilongjiang', '黑龙江'], ll: [127.76, 47.86], cc: 'CN', en: 'Heilongjiang', zh: '黑龙江省', level: 'region' },
  { aliases: ['yunnan', '云南'], ll: [101.49, 24.97], cc: 'CN', en: 'Yunnan', zh: '云南省', level: 'region' },
  { aliases: ['guangxi', '广西'], ll: [108.79, 23.83], cc: 'CN', en: 'Guangxi', zh: '广西', level: 'region' },
  { aliases: ['jiangxi', '江西'], ll: [115.72, 27.61], cc: 'CN', en: 'Jiangxi', zh: '江西省', level: 'region' },
  { aliases: ['shanxi', '山西'], ll: [112.29, 37.57], cc: 'CN', en: 'Shanxi', zh: '山西省', level: 'region' },
  { aliases: ['guizhou', '贵州'], ll: [106.87, 26.82], cc: 'CN', en: 'Guizhou', zh: '贵州省', level: 'region' },
  { aliases: ['hainan', '海南'], ll: [109.75, 19.2], cc: 'CN', en: 'Hainan', zh: '海南省', level: 'region' },
  { aliases: ['xinjiang', '新疆'], ll: [85.29, 41.12], cc: 'CN', en: 'Xinjiang', zh: '新疆', level: 'region' },
  // East & Southeast Asia
  { aliases: ['hong kong', 'hongkong', '香港', '中国香港'], ll: [114.17, 22.32], cc: 'HK', en: 'Hong Kong', zh: '香港', level: 'city' },
  { aliases: ['macau', 'macao', '澳门', '澳門', '中国澳门'], ll: [113.54, 22.19], cc: 'MO', en: 'Macau', zh: '澳门', level: 'city' },
  { aliases: ['taipei', '台北', '臺北'], ll: [121.56, 25.03], cc: 'TW', en: 'Taipei', zh: '台北', level: 'city' },
  { aliases: ['kaohsiung', '高雄'], ll: [120.3, 22.62], cc: 'TW', en: 'Kaohsiung', zh: '高雄', level: 'city' },
  { aliases: ['singapore', '新加坡'], ll: [103.82, 1.35], cc: 'SG', en: 'Singapore', zh: '新加坡', level: 'city' },
  { aliases: ['tokyo', '东京', '東京'], ll: [139.69, 35.69], cc: 'JP', en: 'Tokyo', zh: '东京', level: 'city' },
  { aliases: ['osaka', '大阪'], ll: [135.5, 34.69], cc: 'JP', en: 'Osaka', zh: '大阪', level: 'city' },
  { aliases: ['fukuoka', '福冈'], ll: [130.4, 33.59], cc: 'JP', en: 'Fukuoka', zh: '福冈', level: 'city' },
  { aliases: ['seoul', '首尔', '首爾'], ll: [126.98, 37.57], cc: 'KR', en: 'Seoul', zh: '首尔', level: 'city' },
  { aliases: ['busan', '釜山'], ll: [129.07, 35.18], cc: 'KR', en: 'Busan', zh: '釜山', level: 'city' },
  { aliases: ['bangkok', '曼谷'], ll: [100.5, 13.76], cc: 'TH', en: 'Bangkok', zh: '曼谷', level: 'city' },
  { aliases: ['kuala lumpur', '吉隆坡'], ll: [101.69, 3.14], cc: 'MY', en: 'Kuala Lumpur', zh: '吉隆坡', level: 'city' },
  { aliases: ['jakarta', '雅加达'], ll: [106.85, -6.21], cc: 'ID', en: 'Jakarta', zh: '雅加达', level: 'city' },
  { aliases: ['manila', '马尼拉'], ll: [120.98, 14.6], cc: 'PH', en: 'Manila', zh: '马尼拉', level: 'city' },
  { aliases: ['ho chi minh', '胡志明'], ll: [106.63, 10.82], cc: 'VN', en: 'Ho Chi Minh City', zh: '胡志明市', level: 'city' },
  { aliases: ['hanoi', '河内'], ll: [105.85, 21.03], cc: 'VN', en: 'Hanoi', zh: '河内', level: 'city' },
  { aliases: ['mumbai', '孟买'], ll: [72.88, 19.08], cc: 'IN', en: 'Mumbai', zh: '孟买', level: 'city' },
  { aliases: ['bengaluru', 'bangalore', '班加罗尔'], ll: [77.59, 12.97], cc: 'IN', en: 'Bengaluru', zh: '班加罗尔', level: 'city' },
  { aliases: ['new delhi', 'delhi', '新德里'], ll: [77.21, 28.61], cc: 'IN', en: 'New Delhi', zh: '新德里', level: 'city' },
  // North America
  { aliases: ['ashburn', 'virginia', '弗吉尼亚'], ll: [-77.49, 39.04], cc: 'US', en: 'Ashburn', zh: '阿什本', level: 'city' },
  { aliases: ['new york', '纽约'], ll: [-74.01, 40.71], cc: 'US', en: 'New York', zh: '纽约', level: 'city' },
  { aliases: ['boston', '波士顿'], ll: [-71.06, 42.36], cc: 'US', en: 'Boston', zh: '波士顿', level: 'city' },
  { aliases: ['washington', '华盛顿'], ll: [-77.04, 38.91], cc: 'US', en: 'Washington', zh: '华盛顿', level: 'city' },
  { aliases: ['miami', '迈阿密'], ll: [-80.19, 25.76], cc: 'US', en: 'Miami', zh: '迈阿密', level: 'city' },
  { aliases: ['atlanta', '亚特兰大'], ll: [-84.39, 33.75], cc: 'US', en: 'Atlanta', zh: '亚特兰大', level: 'city' },
  { aliases: ['chicago', '芝加哥'], ll: [-87.63, 41.88], cc: 'US', en: 'Chicago', zh: '芝加哥', level: 'city' },
  { aliases: ['dallas', '达拉斯'], ll: [-96.8, 32.78], cc: 'US', en: 'Dallas', zh: '达拉斯', level: 'city' },
  { aliases: ['houston', '休斯顿'], ll: [-95.37, 29.76], cc: 'US', en: 'Houston', zh: '休斯顿', level: 'city' },
  { aliases: ['denver', '丹佛'], ll: [-104.99, 39.74], cc: 'US', en: 'Denver', zh: '丹佛', level: 'city' },
  { aliases: ['seattle', '西雅图'], ll: [-122.33, 47.61], cc: 'US', en: 'Seattle', zh: '西雅图', level: 'city' },
  { aliases: ['portland', 'oregon', '波特兰', '俄勒冈'], ll: [-122.68, 45.52], cc: 'US', en: 'Portland', zh: '波特兰', level: 'city' },
  { aliases: ['san francisco', '旧金山', '三藩市'], ll: [-122.42, 37.77], cc: 'US', en: 'San Francisco', zh: '旧金山', level: 'city' },
  { aliases: ['san jose', 'silicon valley', '圣何塞', '圣荷西'], ll: [-121.89, 37.34], cc: 'US', en: 'San Jose', zh: '圣何塞', level: 'city' },
  { aliases: ['california', '加利福尼亚'], ll: [-119.42, 36.78], cc: 'US', en: 'California', zh: '加利福尼亚', level: 'region' },
  { aliases: ['los angeles', '洛杉矶'], ll: [-118.24, 34.05], cc: 'US', en: 'Los Angeles', zh: '洛杉矶', level: 'city' },
  { aliases: ['phoenix', '凤凰城'], ll: [-112.07, 33.45], cc: 'US', en: 'Phoenix', zh: '凤凰城', level: 'city' },
  { aliases: ['toronto', '多伦多'], ll: [-79.38, 43.65], cc: 'CA', en: 'Toronto', zh: '多伦多', level: 'city' },
  { aliases: ['vancouver', '温哥华'], ll: [-123.12, 49.28], cc: 'CA', en: 'Vancouver', zh: '温哥华', level: 'city' },
  { aliases: ['montreal', '蒙特利尔'], ll: [-73.57, 45.5], cc: 'CA', en: 'Montreal', zh: '蒙特利尔', level: 'city' },
  { aliases: ['mexico city', '墨西哥城'], ll: [-99.13, 19.43], cc: 'MX', en: 'Mexico City', zh: '墨西哥城', level: 'city' },
  // Europe
  { aliases: ['frankfurt', '法兰克福'], ll: [8.68, 50.11], cc: 'DE', en: 'Frankfurt', zh: '法兰克福', level: 'city' },
  { aliases: ['berlin', '柏林'], ll: [13.4, 52.52], cc: 'DE', en: 'Berlin', zh: '柏林', level: 'city' },
  { aliases: ['munich', '慕尼黑'], ll: [11.58, 48.14], cc: 'DE', en: 'Munich', zh: '慕尼黑', level: 'city' },
  { aliases: ['london', '伦敦'], ll: [-0.13, 51.51], cc: 'GB', en: 'London', zh: '伦敦', level: 'city' },
  { aliases: ['manchester', '曼彻斯特'], ll: [-2.24, 53.48], cc: 'GB', en: 'Manchester', zh: '曼彻斯特', level: 'city' },
  { aliases: ['amsterdam', '阿姆斯特丹'], ll: [4.9, 52.37], cc: 'NL', en: 'Amsterdam', zh: '阿姆斯特丹', level: 'city' },
  { aliases: ['paris', '巴黎'], ll: [2.35, 48.86], cc: 'FR', en: 'Paris', zh: '巴黎', level: 'city' },
  { aliases: ['dublin', '都柏林'], ll: [-6.26, 53.35], cc: 'IE', en: 'Dublin', zh: '都柏林', level: 'city' },
  { aliases: ['zurich', '苏黎世'], ll: [8.54, 47.37], cc: 'CH', en: 'Zurich', zh: '苏黎世', level: 'city' },
  { aliases: ['stockholm', '斯德哥尔摩'], ll: [18.07, 59.33], cc: 'SE', en: 'Stockholm', zh: '斯德哥尔摩', level: 'city' },
  { aliases: ['helsinki', '赫尔辛基'], ll: [24.94, 60.17], cc: 'FI', en: 'Helsinki', zh: '赫尔辛基', level: 'city' },
  { aliases: ['warsaw', '华沙'], ll: [21.01, 52.23], cc: 'PL', en: 'Warsaw', zh: '华沙', level: 'city' },
  { aliases: ['madrid', '马德里'], ll: [-3.7, 40.42], cc: 'ES', en: 'Madrid', zh: '马德里', level: 'city' },
  { aliases: ['milan', '米兰'], ll: [9.19, 45.46], cc: 'IT', en: 'Milan', zh: '米兰', level: 'city' },
  { aliases: ['rome', '罗马'], ll: [12.5, 41.9], cc: 'IT', en: 'Rome', zh: '罗马', level: 'city' },
  { aliases: ['vienna', '维也纳'], ll: [16.37, 48.21], cc: 'AT', en: 'Vienna', zh: '维也纳', level: 'city' },
  { aliases: ['prague', '布拉格'], ll: [14.44, 50.08], cc: 'CZ', en: 'Prague', zh: '布拉格', level: 'city' },
  { aliases: ['sofia', '索非亚', '索菲亚'], ll: [23.32, 42.7], cc: 'BG', en: 'Sofia', zh: '索菲亚', level: 'city' },
  { aliases: ['istanbul', '伊斯坦布尔'], ll: [28.98, 41.01], cc: 'TR', en: 'Istanbul', zh: '伊斯坦布尔', level: 'city' },
  { aliases: ['moscow', '莫斯科'], ll: [37.62, 55.76], cc: 'RU', en: 'Moscow', zh: '莫斯科', level: 'city' },
  // Oceania, Middle East, South America, Africa
  { aliases: ['sydney', '悉尼'], ll: [151.21, -33.87], cc: 'AU', en: 'Sydney', zh: '悉尼', level: 'city' },
  { aliases: ['melbourne', '墨尔本'], ll: [144.96, -37.81], cc: 'AU', en: 'Melbourne', zh: '墨尔本', level: 'city' },
  { aliases: ['auckland', '奥克兰'], ll: [174.76, -36.85], cc: 'NZ', en: 'Auckland', zh: '奥克兰', level: 'city' },
  { aliases: ['dubai', '迪拜'], ll: [55.27, 25.2], cc: 'AE', en: 'Dubai', zh: '迪拜', level: 'city' },
  { aliases: ['tel aviv', '特拉维夫'], ll: [34.78, 32.09], cc: 'IL', en: 'Tel Aviv', zh: '特拉维夫', level: 'city' },
  { aliases: ['sao paulo', 'são paulo', '圣保罗'], ll: [-46.63, -23.55], cc: 'BR', en: 'Sao Paulo', zh: '圣保罗', level: 'city' },
  { aliases: ['buenos aires', '布宜诺斯艾利斯'], ll: [-58.38, -34.6], cc: 'AR', en: 'Buenos Aires', zh: '布宜诺斯艾利斯', level: 'city' },
  { aliases: ['johannesburg', '约翰内斯堡'], ll: [28.05, -26.2], cc: 'ZA', en: 'Johannesburg', zh: '约翰内斯堡', level: 'city' },
  { aliases: ['cape town', '开普敦'], ll: [18.42, -33.92], cc: 'ZA', en: 'Cape Town', zh: '开普敦', level: 'city' },
]

const COUNTRY_NAMES_ZH: Readonly<Record<string, string>> = {
  CN: '中国',
  JP: '日本',
  KR: '韩国',
  SG: '新加坡',
  TW: '台湾',
  HK: '香港',
  MO: '澳门',
  US: '美国',
  CA: '加拿大',
  DE: '德国',
  GB: '英国',
  FR: '法国',
  NL: '荷兰',
  AU: '澳大利亚',
  BR: '巴西',
  IN: '印度',
  RU: '俄罗斯',
  ZA: '南非',
}

const COUNTRY_NAMES_EN: Readonly<Record<string, string>> = {
  CN: 'China',
  JP: 'Japan',
  KR: 'South Korea',
  SG: 'Singapore',
  TW: 'Taiwan',
  HK: 'Hong Kong',
  MO: 'Macau',
  US: 'United States',
  CA: 'Canada',
  DE: 'Germany',
  GB: 'United Kingdom',
  FR: 'France',
  NL: 'Netherlands',
  AU: 'Australia',
  BR: 'Brazil',
  IN: 'India',
  RU: 'Russia',
  ZA: 'South Africa',
}

const CITY_LOOKUP = new Map<string, BuiltinPlace[]>()
const REGION_LOOKUP = new Map<string, BuiltinPlace[]>()

for (const place of BUILTIN_PLACES) {
  const target = place.level === 'city' ? CITY_LOOKUP : REGION_LOOKUP
  for (const a of place.aliases) {
    const list = target.get(a)
    if (list) list.push(place)
    else target.set(a, [place])
  }
}

let activeExternalGazetteer: GazetteerV1 | null = null
let gazetteerLoadPromise: Promise<GazetteerV1 | null> | null = null

// Optional P1 gazetteer module auto-discovery: evaluates to `{}` until P1 lands
// `./gazetteer.ts`, then lazily loads it on globe mount with 0 bytes in main entry.
const optionalGazetteerModules = import.meta.glob('./gazetteer.ts')

export function setExternalGazetteer(gazetteer: GazetteerV1 | null): void {
  activeExternalGazetteer = gazetteer
}

export function getExternalGazetteer(): GazetteerV1 | null {
  return activeExternalGazetteer
}

/**
 * Lazily load P1's `./gazetteer.ts` module if present in the bundle.
 * Safe no-op returning `null` during standalone P2/P3 execution.
 */
export async function loadGazetteerIfPresent(): Promise<GazetteerV1 | null> {
  if (activeExternalGazetteer) return activeExternalGazetteer
  if (gazetteerLoadPromise) return gazetteerLoadPromise

  const loader = optionalGazetteerModules['./gazetteer.ts']
  if (!loader) return null

  gazetteerLoadPromise = loader()
    .then(async (mod) => {
      const m = mod as {
        loadGazetteer?: () => Promise<GazetteerV1>
        default?: GazetteerV1 | (() => Promise<GazetteerV1>)
        gazetteer?: GazetteerV1
      }
      let data: GazetteerV1 | null = null
      if (typeof m.loadGazetteer === 'function') {
        data = await m.loadGazetteer()
      } else if (typeof m.default === 'function') {
        data = await m.default()
      } else if (m.default && typeof m.default === 'object' && m.default.version === 1) {
        data = m.default
      } else if (m.gazetteer && m.gazetteer.version === 1) {
        data = m.gazetteer
      }
      if (data && data.version === 1) {
        activeExternalGazetteer = data
        return data
      }
      return null
    })
    .catch(() => null)

  return gazetteerLoadPromise
}

export function normalizePlaceName(raw: string | null | undefined): string {
  if (!raw) return ''
  return raw
    .trim()
    .toLowerCase()
    .replace(/(特别行政区|特別行政區|自治区|自治區|省|市|区|區|县|縣)$/u, '')
    .replace(/\s+(city|province|municipality|prefecture|s\.?a\.?r\.?)$/iu, '')
    .trim()
}

function lookupGazetteerBucket(
  bucket: Record<string, GazetteerTuple> | undefined,
  raw: string | null | undefined,
  countryCode: string,
): GazetteerTuple | null {
  if (!bucket) return null
  const norm = normalizePlaceName(raw)
  if (!norm) return null
  const trimmedLower = (raw ?? '').trim().toLowerCase()
  const ccUpper = countryCode.trim().toUpperCase()
  const candidates: string[] = []
  if (ccUpper) {
    candidates.push(`${ccUpper}:${norm}`)
    if (trimmedLower !== norm) candidates.push(`${ccUpper}:${trimmedLower}`)
  }
  candidates.push(norm)
  if (trimmedLower !== norm) candidates.push(trimmedLower)

  for (const key of candidates) {
    const hit = bucket[key]
    if (hit) return hit
  }
  return null
}

function findInBuiltinMap(
  map: Map<string, BuiltinPlace[]>,
  raw: string | null | undefined,
  countryCode: string,
): BuiltinPlace | null {
  const norm = normalizePlaceName(raw)
  if (!norm) return null
  const exact = map.get(norm)
  if (exact?.length) {
    if (countryCode) {
      const scoped = exact.find((p) => p.cc === countryCode)
      if (scoped) return scoped
    }
    return exact[0]!
  }
  for (const [k, list] of map) {
    if (k.length >= 3 && (norm.startsWith(k) || k.startsWith(norm))) {
      if (countryCode) {
        const scoped = list.find((p) => p.cc === countryCode)
        if (scoped) return scoped
      }
      return list[0]!
    }
  }
  return null
}

/**
 * Resolve a device's location strictly per S4 / S7:
 * 1. Explicit finite `lat`/`lon` (P6) -> `coords` (or `node.geoLevel` when explicitly specified)
 * 2. City lookup (P1 gazetteer -> built-in fallback, scoped by `countryCode`) -> `city`
 * 3. Province/state centroid (P1 gazetteer -> built-in fallback) -> `region`
 * 4. Country/region label point (P1 gazetteer -> Natural Earth fallback) -> `country`
 * 5. Unknown -> `unknown` (NEVER uses `relayHome`)
 */
export function resolveV2Location(
  node: GlobeNode,
  gazetteer: GazetteerV1 | null = activeExternalGazetteer,
): ResolvedV2Location {
  const loc = formatDeviceLocation({
    country_code: node.countryCode,
    country: node.country,
    region: node.region,
    city: node.city,
  })
  const cc = loc.countryCode
  const accuracyRadiusKm =
    typeof node.accuracyRadiusKm === 'number' &&
    Number.isFinite(node.accuracyRadiusKm) &&
    node.accuracyRadiusKm > 0
      ? Math.round(node.accuracyRadiusKm)
      : null

  // Tier 1: Explicit coordinates (P6 `lat`/`lon`/`accuracy_radius_km`/`geo_level`)
  if (
    typeof node.lat === 'number' &&
    typeof node.lon === 'number' &&
    Number.isFinite(node.lat) &&
    Number.isFinite(node.lon) &&
    node.geoLevel !== 'unknown'
  ) {
    const lat = Math.max(-85, Math.min(85, node.lat))
    const lon = node.lon
    const precision: Exclude<V2GeoPrecision, 'unknown'> =
      node.geoLevel === 'city' || node.geoLevel === 'region' || node.geoLevel === 'country'
        ? node.geoLevel
        : 'coords'

    const gazCity = lookupGazetteerBucket(gazetteer?.cities, node.city, cc)
    const builtinCity = findInBuiltinMap(CITY_LOOKUP, node.city, cc)
    const fallbackLabel = node.city?.trim() || node.region?.trim() || loc.locationText || cc
    const rawEn = gazCity?.[2] || builtinCity?.en || fallbackLabel
    const rawZh = gazCity?.[3] || builtinCity?.zh || fallbackLabel

    return {
      precision,
      lon,
      lat,
      accuracyRadiusKm: precision === 'coords' ? accuracyRadiusKm : null,
      groupKey: `${precision}:${lon.toFixed(2)},${lat.toFixed(2)}`,
      placeEn: formatNeutralRegionName(cc, rawEn, 'en'),
      placeZh: formatNeutralRegionName(cc, rawZh, 'zh-CN'),
      locationLabel: loc.locationText || formatNeutralRegionName(cc, rawEn, 'en'),
      countryCode: cc,
    }
  }

  // Tier 2: City lookup (P1 gazetteer first, then built-in fallback)
  const gazCity = lookupGazetteerBucket(gazetteer?.cities, node.city, cc)
  if (gazCity) {
    const [lon, lat, en, zh] = gazCity
    return {
      precision: 'city',
      lon,
      lat,
      accuracyRadiusKm: null,
      groupKey: `city:${lon.toFixed(2)},${lat.toFixed(2)}`,
      placeEn: formatNeutralRegionName(cc, en, 'en'),
      placeZh: formatNeutralRegionName(cc, zh || en, 'zh-CN'),
      locationLabel: loc.locationText || formatNeutralRegionName(cc, en, 'en'),
      countryCode: cc,
    }
  }

  const cityHit = findInBuiltinMap(CITY_LOOKUP, node.city, cc)
  if (cityHit) {
    const [lon, lat] = cityHit.ll
    const resolvedCc = cc || cityHit.cc
    return {
      precision: 'city',
      lon,
      lat,
      accuracyRadiusKm: null,
      groupKey: `city:${lon.toFixed(2)},${lat.toFixed(2)}`,
      placeEn: formatNeutralRegionName(resolvedCc, cityHit.en, 'en'),
      placeZh: formatNeutralRegionName(resolvedCc, cityHit.zh, 'zh-CN'),
      locationLabel: loc.locationText || formatNeutralRegionName(resolvedCc, cityHit.en, 'en'),
      countryCode: resolvedCc,
    }
  }

  // Tier 3: Region (province/state) centroid
  const gazRegion =
    lookupGazetteerBucket(gazetteer?.regions, node.region, cc) ??
    lookupGazetteerBucket(gazetteer?.cities, node.region, cc)
  if (gazRegion) {
    const [lon, lat, en, zh] = gazRegion
    return {
      precision: 'region',
      lon,
      lat,
      accuracyRadiusKm: null,
      groupKey: `region:${lon.toFixed(2)},${lat.toFixed(2)}`,
      placeEn: en,
      placeZh: zh || en,
      locationLabel: loc.locationText || en,
      countryCode: cc,
    }
  }

  const regionHit =
    findInBuiltinMap(REGION_LOOKUP, node.region, cc) ?? findInBuiltinMap(CITY_LOOKUP, node.region, cc)
  if (regionHit) {
    const [lon, lat] = regionHit.ll
    return {
      precision: 'region',
      lon,
      lat,
      accuracyRadiusKm: null,
      groupKey: `region:${lon.toFixed(2)},${lat.toFixed(2)}`,
      placeEn: regionHit.en,
      placeZh: regionHit.zh,
      locationLabel: loc.locationText || regionHit.en,
      countryCode: cc || regionHit.cc,
    }
  }

  // Tier 4: Country/region label point
  const gazCountry = cc ? gazetteer?.countries?.[cc] : undefined
  if (gazCountry) {
    const [lon, lat, en, zh] = gazCountry
    return {
      precision: 'country',
      lon,
      lat,
      accuracyRadiusKm: null,
      groupKey: `country:${lon.toFixed(2)},${lat.toFixed(2)}`,
      placeEn: formatNeutralRegionName(cc, en, 'en'),
      placeZh: formatNeutralRegionName(cc, zh || en, 'zh-CN'),
      locationLabel: loc.locationText || formatNeutralRegionName(cc, en, 'en'),
      countryCode: cc,
    }
  }

  const countryLL = lonLatOf(cc)
  if (countryLL) {
    const [lon, lat] = countryLL
    const rawEn = COUNTRY_NAMES_EN[cc] || node.country?.trim() || cc
    const rawZh = COUNTRY_NAMES_ZH[cc] || node.country?.trim() || cc
    return {
      precision: 'country',
      lon,
      lat,
      accuracyRadiusKm: null,
      groupKey: `country:${lon.toFixed(2)},${lat.toFixed(2)}`,
      placeEn: formatNeutralRegionName(cc, rawEn, 'en'),
      placeZh: formatNeutralRegionName(cc, rawZh, 'zh-CN'),
      locationLabel: loc.locationText || formatNeutralRegionName(cc, rawEn, 'en'),
      countryCode: cc,
    }
  }

  // Tier 5: Unknown — NEVER fall back to relayHome (S4 / AC14).
  return {
    precision: 'unknown',
    lon: null,
    lat: null,
    accuracyRadiusKm: null,
    groupKey: null,
    placeEn: '',
    placeZh: '',
    locationLabel: '',
    countryCode: '',
  }
}

export { COUNTRY_LONLAT }
