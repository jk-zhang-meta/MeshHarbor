#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 G ROX EOOD
#
# Reproducibly generate ui/src/components/globe-v2/data/gazetteer-v1.json from
# pinned Natural Earth 5.1.2 public-domain sources plus curated cloud/mesh hubs
# and neutral region overrides (FR-136 S4/S6/S11/AC7).
#
# Output schema (GazetteerV1):
#   {
#     "version": 1,
#     "countries": { "<ISO2>": [lon, lat, name_en, name_zh] },
#     "regions":   { "<ISO2>:<norm_key>": [lon, lat, name_en, name_zh] },
#     "cities":    { "<ISO2>:<norm_key>": [lon, lat, name_en, name_zh] }
#   }

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import sys
import unicodedata
from typing import Dict, List, Optional, Tuple

# Keep synchronized verbatim with `TRAD_TO_SIMP` in ui/src/components/globe-v2/gazetteer.ts
TRAD_TO_SIMP: Dict[str, str] = {
    '臺': '台', '灣': '湾', '門': '门', '東': '东', '廣': '广', '爾': '尔',
    '蘇': '苏', '慶': '庆', '漢': '汉', '陽': '阳', '長': '长', '鄭': '郑',
    '濟': '济', '連': '连', '瀋': '沈', '濱': '滨', '寧': '宁', '廈': '厦',
    '貴': '贵', '蘭': '兰', '烏': '乌', '魯': '鲁', '齊': '齐', '薩': '萨',
    '陝': '陕', '遼': '辽', '龍': '龙', '華': '华', '國': '国', '區': '区',
    '縣': '县', '島': '岛', '嶺': '岭', '紐': '纽', '約': '约', '舊': '旧',
    '倫': '伦', '聖': '圣', '羅': '罗', '維': '维', '馬': '马', '亞': '亚',
    '開': '开', '達': '达', '岡': '冈', '買': '买', '來': '来', '溫': '温',
    '頓': '顿', '鳳': '凤', '茲': '兹', '圖': '图', '葉': '叶', '庫': '库',
    '澤': '泽', '閩': '闽', '贛': '赣', '滬': '沪', '粵': '粤', '瓊': '琼',
    '晉': '晋', '隴': '陇', '莊': '庄', '壯': '壮', '內': '内', '鐵': '铁',
    '銀': '银', '揚': '扬', '紹': '绍', '興': '兴', '蕪': '芜', '濰': '潍',
    '煙': '烟', '萊': '莱', '嶽': '岳', '婁': '娄', '義': '义', '綿': '绵',
    '樂': '乐', '瀘': '泸', '賓': '宾', '資': '资', '銅': '铜', '畢': '毕',
    '節': '节', '紅': '红', '麗': '丽', '寶': '宝', '雞': '鸡', '運': '运',
    '臨': '临', '呂': '吕', '滄': '沧', '鄲': '郸', '張': '张', '撫': '抚',
    '順': '顺', '營': '营', '錦': '锦', '盤': '盘', '蘆': '芦', '綏': '绥',
    '鶴': '鹤', '崗': '岗', '雙': '双', '鴨': '鸭', '鎮': '镇', '鄉': '乡',
    '餘': '余', '鷹': '鹰', '饒': '饶', '棗': '枣', '許': '许', '駐': '驻',
    '荊': '荆', '黃': '黄', '隨': '随', '懷': '怀', '欽': '钦', '賀': '贺',
    '蕪': '芜', '馬': '马', '鹽': '盐', '遷': '迁', '雲': '云', '萬': '万',
    '歷': '历', '麥': '麦', '奧': '奥', '斯': '斯', '爾': '尔', '歐': '欧',
    '愛': '爱', '爾': '尔', '薩': '萨', '盧': '卢', '納': '纳', '韋': '韦',
    '萊': '莱', '亞': '亚', '裡': '里', '緬': '缅', '寮': '寮', '韓': '韩',
    '鮮': '鲜', '越': '越', '菲': '菲', '賓': '宾', '印': '印', '尼': '尼',
    '泰': '泰', '馬': '马', '來': '来', '西': '西', '亞': '亚', '新': '新',
    '加': '加', '坡': '坡', '澳': '澳', '大': '大', '利': '利', '亞': '亚',
    '紐': '纽', '西': '西', '蘭': '兰', '德': '德', '法': '法', '英': '英',
    '俄': '俄', '義': '义', '荷': '荷', '瑞': '瑞', '典': '典', '士': '士',
    '芬': '芬', '蘭': '兰', '挪': '挪', '威': '威', '丹': '丹', '麥': '麦',
    '波': '波', '捷': '捷', '克': '克', '匈': '匈', '牙': '牙', '利': '利',
    '保': '保', '羅': '罗', '希': '希', '臘': '腊', '土': '土', '耳': '耳',
    '其': '其', '烏': '乌', '克': '克', '蘭': '兰', '以': '以', '色': '色',
    '列': '列', '阿': '阿', '聯': '联', '酋': '酋', '沙': '沙', '特': '特',
    '埃': '埃', '及': '及', '南': '南', '非': '非', '巴': '巴', '西': '西',
    '墨': '墨', '哥': '哥', '智': '智', '秘': '秘', '魯': '鲁', '哥': '哥',
    '倫': '伦', '比': '比', '亞': '亚', '委': '委', '內': '内', '瑞': '瑞',
    '拉': '拉', '加': '加', '拿': '拿', '美': '美',
}
TRAD_TRANS = str.maketrans(TRAD_TO_SIMP)

RE_COMBINING = re.compile(r'[\u0300-\u036f]')
RE_APOSTROPHE = re.compile(r"['’`]")
RE_NON_WORD = re.compile(r'[^\w]+', re.UNICODE)
RE_CJK_PREFIX = re.compile(r'^中国(?=(香港|澳门|台湾))')
RE_CJK_SUFFIX = re.compile(
    r'(特别行政区|维吾尔自治区|壮族自治区|回族自治区|自治区|自治州|自治县|地区|省|市|区|县|盟)$'
)
RE_EN_SUFFIX = re.compile(
    r'\s+(special administrative region|autonomous region|municipality|prefecture|metropolitan|metropolis|province|district|county|region|oblast|state|krai|city|sar)$'
)

# Neutral region overrides (S6 / AC7) — NEVER label TW/HK/MO as "country" or "Republic of China"
NEUTRAL_COUNTRY_OVERRIDES: Dict[str, Tuple[str, str]] = {
    'TW': ('Taiwan', '台湾'),
    'HK': ('Hong Kong', '香港'),
    'MO': ('Macau', '澳门'),
}

# Concise canonical country/region display names
SHORT_COUNTRY_NAMES: Dict[str, Tuple[str, str]] = {
    'CN': ('China', '中国'),
    'US': ('United States', '美国'),
    'GB': ('United Kingdom', '英国'),
    'KR': ('South Korea', '韩国'),
    'KP': ('North Korea', '朝鲜'),
    'RU': ('Russia', '俄罗斯'),
    'AE': ('United Arab Emirates', '阿联酋'),
    'CZ': ('Czechia', '捷克'),
    'ZA': ('South Africa', '南非'),
    'TW': ('Taiwan', '台湾'),
    'HK': ('Hong Kong', '香港'),
    'MO': ('Macau', '澳门'),
}

# Curated major global cloud/mesh hubs & Chinese cities/provinces
# (aliases, lon, lat, cc, name_en, name_zh, level)
CURATED_PLACES: List[Tuple[Tuple[str, ...], float, float, str, str, str, str]] = [
    # Mainland China major cities & tech hubs
    (('beijing', '北京'), 116.41, 39.90, 'CN', 'Beijing', '北京', 'city'),
    (('shanghai', '上海'), 121.47, 31.23, 'CN', 'Shanghai', '上海', 'city'),
    (('shenzhen', '深圳'), 114.06, 22.54, 'CN', 'Shenzhen', '深圳', 'city'),
    (('guangzhou', 'canton', '广州'), 113.26, 23.13, 'CN', 'Guangzhou', '广州', 'city'),
    (('dongguan', '东莞'), 113.75, 23.02, 'CN', 'Dongguan', '东莞', 'city'),
    (('foshan', '佛山'), 113.12, 23.02, 'CN', 'Foshan', '佛山', 'city'),
    (('zhuhai', '珠海'), 113.58, 22.27, 'CN', 'Zhuhai', '珠海', 'city'),
    (('zhongshan', '中山'), 113.39, 22.52, 'CN', 'Zhongshan', '中山', 'city'),
    (('huizhou', '惠州'), 114.42, 23.11, 'CN', 'Huizhou', '惠州', 'city'),
    (('hangzhou', '杭州'), 120.15, 30.28, 'CN', 'Hangzhou', '杭州', 'city'),
    (('ningbo', '宁波'), 121.55, 29.87, 'CN', 'Ningbo', '宁波', 'city'),
    (('wenzhou', '温州'), 120.70, 28.00, 'CN', 'Wenzhou', '温州', 'city'),
    (('jiaxing', '嘉兴'), 120.76, 30.75, 'CN', 'Jiaxing', '嘉兴', 'city'),
    (('shaoxing', '绍兴'), 120.58, 30.00, 'CN', 'Shaoxing', '绍兴', 'city'),
    (('nanjing', '南京'), 118.80, 32.06, 'CN', 'Nanjing', '南京', 'city'),
    (('suzhou', '苏州'), 120.58, 31.30, 'CN', 'Suzhou', '苏州', 'city'),
    (('wuxi', '无锡'), 120.31, 31.49, 'CN', 'Wuxi', '无锡', 'city'),
    (('changzhou', '常州'), 119.97, 31.81, 'CN', 'Changzhou', '常州', 'city'),
    (('nantong', '南通'), 120.89, 31.98, 'CN', 'Nantong', '南通', 'city'),
    (('xuzhou', '徐州'), 117.28, 34.21, 'CN', 'Xuzhou', '徐州', 'city'),
    (('chengdu', '成都'), 104.07, 30.67, 'CN', 'Chengdu', '成都', 'city'),
    (('chongqing', '重庆'), 106.55, 29.56, 'CN', 'Chongqing', '重庆', 'city'),
    (('wuhan', '武汉'), 114.30, 30.59, 'CN', 'Wuhan', '武汉', 'city'),
    (('xian', "xi'an", '西安'), 108.94, 34.34, 'CN', "Xi'an", '西安', 'city'),
    (('tianjin', '天津'), 117.20, 39.08, 'CN', 'Tianjin', '天津', 'city'),
    (('changsha', '长沙'), 112.94, 28.23, 'CN', 'Changsha', '长沙', 'city'),
    (('zhengzhou', '郑州'), 113.62, 34.75, 'CN', 'Zhengzhou', '郑州', 'city'),
    (('qingdao', '青岛'), 120.38, 36.07, 'CN', 'Qingdao', '青岛', 'city'),
    (('jinan', '济南'), 117.00, 36.65, 'CN', 'Jinan', '济南', 'city'),
    (('yantai', '烟台'), 121.45, 37.46, 'CN', 'Yantai', '烟台', 'city'),
    (('dalian', '大连'), 121.61, 38.91, 'CN', 'Dalian', '大连', 'city'),
    (('shenyang', '沈阳'), 123.43, 41.80, 'CN', 'Shenyang', '沈阳', 'city'),
    (('harbin', '哈尔滨'), 126.53, 45.80, 'CN', 'Harbin', '哈尔滨', 'city'),
    (('changchun', '长春'), 125.32, 43.82, 'CN', 'Changchun', '长春', 'city'),
    (('fuzhou', '福州'), 119.30, 26.07, 'CN', 'Fuzhou', '福州', 'city'),
    (('xiamen', '厦门'), 118.09, 24.48, 'CN', 'Xiamen', '厦门', 'city'),
    (('quanzhou', '泉州'), 118.68, 24.87, 'CN', 'Quanzhou', '泉州', 'city'),
    (('hefei', '合肥'), 117.23, 31.82, 'CN', 'Hefei', '合肥', 'city'),
    (('kunming', '昆明'), 102.83, 24.88, 'CN', 'Kunming', '昆明', 'city'),
    (('guiyang', '贵阳'), 106.63, 26.65, 'CN', 'Guiyang', '贵阳', 'city'),
    (('nanning', '南宁'), 108.37, 22.82, 'CN', 'Nanning', '南宁', 'city'),
    (('haikou', '海口'), 110.20, 20.04, 'CN', 'Haikou', '海口', 'city'),
    (('sanya', '三亚'), 109.51, 18.25, 'CN', 'Sanya', '三亚', 'city'),
    (('nanchang', '南昌'), 115.86, 28.68, 'CN', 'Nanchang', '南昌', 'city'),
    (('shijiazhuang', '石家庄'), 114.51, 38.04, 'CN', 'Shijiazhuang', '石家庄', 'city'),
    (('langfang', '廊坊'), 116.68, 39.54, 'CN', 'Langfang', '廊坊', 'city'),
    (('baoding', '保定'), 115.46, 38.87, 'CN', 'Baoding', '保定', 'city'),
    (('taiyuan', '太原'), 112.55, 37.87, 'CN', 'Taiyuan', '太原', 'city'),
    (('hohhot', '呼和浩特'), 111.75, 40.84, 'CN', 'Hohhot', '呼和浩特', 'city'),
    (('lanzhou', '兰州'), 103.83, 36.06, 'CN', 'Lanzhou', '兰州', 'city'),
    (('yinchuan', '银川'), 106.23, 38.49, 'CN', 'Yinchuan', '银川', 'city'),
    (('xining', '西宁'), 101.78, 36.62, 'CN', 'Xining', '西宁', 'city'),
    (('urumqi', '乌鲁木齐'), 87.62, 43.83, 'CN', 'Urumqi', '乌鲁木齐', 'city'),
    (('lhasa', '拉萨'), 91.17, 29.65, 'CN', 'Lhasa', '拉萨', 'city'),
    (('zhangjiakou', '张家口'), 114.89, 40.82, 'CN', 'Zhangjiakou', '张家口', 'city'),
    (('ulanqab', 'wulanchabu', '乌兰察布'), 113.13, 40.99, 'CN', 'Ulanqab', '乌兰察布', 'city'),
    (('zhongwei', '中卫'), 105.20, 37.50, 'CN', 'Zhongwei', '中卫', 'city'),
    # Hong Kong, Macau, Taiwan
    (('hong kong', 'hongkong', '香港', '中国香港'), 114.17, 22.32, 'HK', 'Hong Kong', '香港', 'city'),
    (('macau', 'macao', '澳门', '中国澳门'), 113.54, 22.19, 'MO', 'Macau', '澳门', 'city'),
    (('taipei', '台北'), 121.56, 25.03, 'TW', 'Taipei', '台北', 'city'),
    (('new taipei', '新北'), 121.46, 25.01, 'TW', 'New Taipei', '新北', 'city'),
    (('taoyuan', '桃园'), 121.30, 24.99, 'TW', 'Taoyuan', '桃园', 'city'),
    (('taichung', '台中'), 120.68, 24.15, 'TW', 'Taichung', '台中', 'city'),
    (('tainan', '台南'), 120.21, 22.99, 'TW', 'Tainan', '台南', 'city'),
    (('kaohsiung', '高雄'), 120.30, 22.62, 'TW', 'Kaohsiung', '高雄', 'city'),
    (('hsinchu', '新竹'), 120.97, 24.80, 'TW', 'Hsinchu', '新竹', 'city'),
    # East & Southeast Asia / South Asia
    (('singapore', '新加坡'), 103.82, 1.35, 'SG', 'Singapore', '新加坡', 'city'),
    (('tokyo', '东京'), 139.69, 35.69, 'JP', 'Tokyo', '东京', 'city'),
    (('osaka', '大阪'), 135.50, 34.69, 'JP', 'Osaka', '大阪', 'city'),
    (('fukuoka', '福冈'), 130.40, 33.59, 'JP', 'Fukuoka', '福冈', 'city'),
    (('inzai', '印西'), 140.15, 35.83, 'JP', 'Inzai', '印西', 'city'),
    (('seoul', '首尔'), 126.98, 37.57, 'KR', 'Seoul', '首尔', 'city'),
    (('busan', '釜山'), 129.07, 35.18, 'KR', 'Busan', '釜山', 'city'),
    (('incheon', '仁川'), 126.71, 37.46, 'KR', 'Incheon', '仁川', 'city'),
    (('bangkok', '曼谷'), 100.50, 13.76, 'TH', 'Bangkok', '曼谷', 'city'),
    (('kuala lumpur', '吉隆坡'), 101.69, 3.14, 'MY', 'Kuala Lumpur', '吉隆坡', 'city'),
    (('jakarta', '雅加达'), 106.85, -6.21, 'ID', 'Jakarta', '雅加达', 'city'),
    (('manila', '马尼拉'), 120.98, 14.60, 'PH', 'Manila', '马尼拉', 'city'),
    (('ho chi minh', 'ho chi minh city', '胡志明', '胡志明市'), 106.63, 10.82, 'VN', 'Ho Chi Minh City', '胡志明市', 'city'),
    (('hanoi', '河内'), 105.85, 21.03, 'VN', 'Hanoi', '河内', 'city'),
    (('mumbai', 'bombay', '孟买'), 72.88, 19.08, 'IN', 'Mumbai', '孟买', 'city'),
    (('bengaluru', 'bangalore', '班加罗尔'), 77.59, 12.97, 'IN', 'Bengaluru', '班加罗尔', 'city'),
    (('new delhi', 'delhi', '新德里', '德里'), 77.21, 28.61, 'IN', 'New Delhi', '新德里', 'city'),
    (('hyderabad', '海得拉巴'), 78.49, 17.39, 'IN', 'Hyderabad', '海得拉巴', 'city'),
    (('chennai', '金奈'), 80.27, 13.08, 'IN', 'Chennai', '金奈', 'city'),
    (('pune', '浦那'), 73.86, 18.52, 'IN', 'Pune', '浦那', 'city'),
    # North America cloud/mesh hubs
    (('ashburn', '阿什本'), -77.49, 39.04, 'US', 'Ashburn', '阿什本', 'city'),
    (('reston', '雷斯顿'), -77.36, 38.96, 'US', 'Reston', '雷斯顿', 'city'),
    (('manassas', '马纳萨斯'), -77.48, 38.75, 'US', 'Manassas', '马纳萨斯', 'city'),
    (('new york', 'nyc', '纽约'), -74.01, 40.71, 'US', 'New York', '纽约', 'city'),
    (('newark', '纽瓦克'), -74.17, 40.74, 'US', 'Newark', '纽瓦克', 'city'),
    (('secaucus', '锡考克斯'), -74.06, 40.79, 'US', 'Secaucus', '锡考克斯', 'city'),
    (('boston', '波士顿'), -71.06, 42.36, 'US', 'Boston', '波士顿', 'city'),
    (('washington', 'washington dc', '华盛顿'), -77.04, 38.91, 'US', 'Washington', '华盛顿', 'city'),
    (('miami', '迈阿密'), -80.19, 25.76, 'US', 'Miami', '迈阿密', 'city'),
    (('atlanta', '亚特兰大'), -84.39, 33.75, 'US', 'Atlanta', '亚特兰大', 'city'),
    (('chicago', '芝加哥'), -87.63, 41.88, 'US', 'Chicago', '芝加哥', 'city'),
    (('columbus', '哥伦布'), -82.99, 39.96, 'US', 'Columbus', '哥伦布', 'city'),
    (('council bluffs', '康瑟尔布拉夫斯'), -95.86, 41.26, 'US', 'Council Bluffs', '康瑟尔布拉夫斯', 'city'),
    (('dallas', '达拉斯'), -96.80, 32.78, 'US', 'Dallas', '达拉斯', 'city'),
    (('houston', '休斯顿'), -95.37, 29.76, 'US', 'Houston', '休斯顿', 'city'),
    (('denver', '丹佛'), -104.99, 39.74, 'US', 'Denver', '丹佛', 'city'),
    (('seattle', '西雅图'), -122.33, 47.61, 'US', 'Seattle', '西雅图', 'city'),
    (('portland', '波特兰'), -122.68, 45.52, 'US', 'Portland', '波特兰', 'city'),
    (('boardman', '博德曼'), -119.70, 45.84, 'US', 'Boardman', '博德曼', 'city'),
    (('hillsboro', '希尔斯伯勒'), -122.99, 45.52, 'US', 'Hillsboro', '希尔斯伯勒', 'city'),
    (('the dalles', '达尔斯'), -121.18, 45.59, 'US', 'The Dalles', '达尔斯', 'city'),
    (('san francisco', '旧金山', '三藩市'), -122.42, 37.77, 'US', 'San Francisco', '旧金山', 'city'),
    (('san jose', 'silicon valley', '圣何塞', '圣荷西'), -121.89, 37.34, 'US', 'San Jose', '圣何塞', 'city'),
    (('santa clara', '圣克拉拉'), -121.95, 37.35, 'US', 'Santa Clara', '圣克拉拉', 'city'),
    (('fremont', '弗里蒙特'), -121.99, 37.55, 'US', 'Fremont', '弗里蒙特', 'city'),
    (('mountain view', '山景城'), -122.08, 37.39, 'US', 'Mountain View', '山景城', 'city'),
    (('palo alto', '帕洛阿尔托'), -122.14, 37.44, 'US', 'Palo Alto', '帕洛阿尔托', 'city'),
    (('los angeles', '洛杉矶'), -118.24, 34.05, 'US', 'Los Angeles', '洛杉矶', 'city'),
    (('phoenix', '凤凰城'), -112.07, 33.45, 'US', 'Phoenix', '凤凰城', 'city'),
    (('toronto', '多伦多'), -79.38, 43.65, 'CA', 'Toronto', '多伦多', 'city'),
    (('vancouver', '温哥华'), -123.12, 49.28, 'CA', 'Vancouver', '温哥华', 'city'),
    (('montreal', '蒙特利尔'), -73.57, 45.50, 'CA', 'Montreal', '蒙特利尔', 'city'),
    (('mexico city', '墨西哥城'), -99.13, 19.43, 'MX', 'Mexico City', '墨西哥城', 'city'),
    # Europe cloud/mesh hubs
    (('frankfurt', 'frankfurt am main', '法兰克福'), 8.68, 50.11, 'DE', 'Frankfurt', '法兰克福', 'city'),
    (('berlin', '柏林'), 13.40, 52.52, 'DE', 'Berlin', '柏林', 'city'),
    (('munich', 'munchen', '慕尼黑'), 11.58, 48.14, 'DE', 'Munich', '慕尼黑', 'city'),
    (('nuremberg', 'nurnberg', '纽伦堡'), 11.08, 49.45, 'DE', 'Nuremberg', '纽伦堡', 'city'),
    (('falkenstein', '法尔肯施泰因'), 12.37, 50.48, 'DE', 'Falkenstein', '法尔肯施泰因', 'city'),
    (('london', '伦敦'), -0.13, 51.51, 'GB', 'London', '伦敦', 'city'),
    (('slough', '斯劳'), -0.60, 51.51, 'GB', 'Slough', '斯劳', 'city'),
    (('manchester', '曼彻斯特'), -2.24, 53.48, 'GB', 'Manchester', '曼彻斯特', 'city'),
    (('amsterdam', '阿姆斯特丹'), 4.90, 52.37, 'NL', 'Amsterdam', '阿姆斯特丹', 'city'),
    (('paris', '巴黎'), 2.35, 48.86, 'FR', 'Paris', '巴黎', 'city'),
    (('marseille', '马赛'), 5.37, 43.30, 'FR', 'Marseille', '马赛', 'city'),
    (('gravelines', '格拉沃利讷'), 2.13, 50.99, 'FR', 'Gravelines', '格拉沃利讷', 'city'),
    (('roubaix', '鲁贝'), 3.17, 50.69, 'FR', 'Roubaix', '鲁贝', 'city'),
    (('dublin', '都柏林'), -6.26, 53.35, 'IE', 'Dublin', '都柏林', 'city'),
    (('zurich', '苏黎世'), 8.54, 47.37, 'CH', 'Zurich', '苏黎世', 'city'),
    (('stockholm', '斯德哥尔摩'), 18.07, 59.33, 'SE', 'Stockholm', '斯德哥尔摩', 'city'),
    (('helsinki', '赫尔辛基'), 24.94, 60.17, 'FI', 'Helsinki', '赫尔辛基', 'city'),
    (('warsaw', '华沙'), 21.01, 52.23, 'PL', 'Warsaw', '华沙', 'city'),
    (('madrid', '马德里'), -3.70, 40.42, 'ES', 'Madrid', '马德里', 'city'),
    (('milan', 'milano', '米兰'), 9.19, 45.46, 'IT', 'Milan', '米兰', 'city'),
    (('rome', 'roma', '罗马'), 12.50, 41.90, 'IT', 'Rome', '罗马', 'city'),
    (('vienna', 'wien', '维也纳'), 16.37, 48.21, 'AT', 'Vienna', '维也纳', 'city'),
    (('prague', 'praha', '布拉格'), 14.44, 50.08, 'CZ', 'Prague', '布拉格', 'city'),
    (('sofia', '索菲亚', '索非亚'), 23.32, 42.70, 'BG', 'Sofia', '索菲亚', 'city'),
    (('istanbul', '伊斯坦布尔'), 28.98, 41.01, 'TR', 'Istanbul', '伊斯坦布尔', 'city'),
    (('moscow', '莫斯科'), 37.62, 55.76, 'RU', 'Moscow', '莫斯科', 'city'),
    (('saint petersburg', 'st petersburg', '圣彼得堡'), 30.31, 59.93, 'RU', 'Saint Petersburg', '圣彼得堡', 'city'),
    # Oceania, Middle East, South America, Africa
    (('sydney', '悉尼'), 151.21, -33.87, 'AU', 'Sydney', '悉尼', 'city'),
    (('melbourne', '墨尔本'), 144.96, -37.81, 'AU', 'Melbourne', '墨尔本', 'city'),
    (('auckland', '奥克兰'), 174.76, -36.85, 'NZ', 'Auckland', '奥克兰', 'city'),
    (('dubai', '迪拜'), 55.27, 25.20, 'AE', 'Dubai', '迪拜', 'city'),
    (('tel aviv', '特拉维夫'), 34.78, 32.09, 'IL', 'Tel Aviv', '特拉维夫', 'city'),
    (('sao paulo', '圣保罗'), -46.63, -23.55, 'BR', 'Sao Paulo', '圣保罗', 'city'),
    (('rio de janeiro', '里约热内卢'), -43.17, -22.91, 'BR', 'Rio de Janeiro', '里约热内卢', 'city'),
    (('buenos aires', '布宜诺斯艾利斯'), -58.38, -34.60, 'AR', 'Buenos Aires', '布宜诺斯艾利斯', 'city'),
    (('johannesburg', '约翰内斯堡'), 28.05, -26.20, 'ZA', 'Johannesburg', '约翰内斯堡', 'city'),
    (('cape town', '开普敦'), 18.42, -33.92, 'ZA', 'Cape Town', '开普敦', 'city'),
]


def clean_zh(raw: Optional[str]) -> str:
    if not raw:
        return ''
    return raw.strip().translate(TRAD_TRANS)


def normalize_geo_key(raw: Optional[str]) -> str:
    if not raw:
        return ''
    s = raw.strip()
    if not s or s in ('-', '—', '–'):
        return ''
    s = s.translate(TRAD_TRANS)
    s = unicodedata.normalize('NFKD', s)
    s = RE_COMBINING.sub('', s)
    s = s.lower()
    s = RE_APOSTROPHE.sub('', s)
    s = RE_NON_WORD.sub(' ', s).strip()
    s = RE_CJK_PREFIX.sub('', s).strip()
    for _ in range(2):
        stripped = RE_CJK_SUFFIX.sub('', s).strip()
        if len(stripped) >= 2 and stripped != s:
            s = stripped
            continue
        stripped = RE_EN_SUFFIX.sub('', s).strip()
        if len(stripped) >= 2 and stripped != s:
            s = stripped
            continue
        break
    return s


def round_coord(lon: float, lat: float) -> Tuple[float, float]:
    clamped_lon = max(-180.0, min(180.0, float(lon)))
    clamped_lat = max(-85.0, min(85.0, float(lat)))
    return round(clamped_lon, 2), round(clamped_lat, 2)


def pick_iso2(p: dict) -> str:
    for key in ('ISO_A2', 'iso_a2', 'ISO_A2_EH'):
        val = str(p.get(key) or '').strip().upper()
        if len(val) == 2 and val.isalpha():
            return val
    return ''


def build_gazetteer(sources_dir: str, max_gz_bytes: int) -> Tuple[dict, dict]:
    a0_path = os.path.join(sources_dir, 'ne_10m_admin_0_countries.geojson')
    a1_path = os.path.join(sources_dir, 'ne_10m_admin_1_states_provinces.geojson')
    pp_path = os.path.join(sources_dir, 'ne_10m_populated_places.geojson')

    a0 = json.load(open(a0_path, encoding='utf-8'))
    a1 = json.load(open(a1_path, encoding='utf-8'))
    pp = json.load(open(pp_path, encoding='utf-8'))

    # 1. Countries (ISO-2 uppercase -> [lon, lat, name_en, name_zh])
    # Resolve ADM0_A3 -> ISO-2 table & pick main polygon (largest POP_EST / ADM0_DIF==0) per ISO-2
    a3_to_iso2: Dict[str, str] = {
        'TWN': 'TW', 'HKG': 'HK', 'MAC': 'MO', 'FRA': 'FR', 'NOR': 'NO', 'KOS': 'XK', 'XKX': 'XK',
    }
    country_candidates: Dict[str, Tuple[int, int, Tuple[float, float, str, str]]] = {}

    for f in a0['features']:
        p = f.get('properties') or {}
        a3 = str(p.get('ADM0_A3') or p.get('ISO_A3') or '').strip().upper()
        iso2 = a3_to_iso2.get(a3) or pick_iso2(p)
        if not iso2:
            continue
        if a3:
            a3_to_iso2.setdefault(a3, iso2)
        lx, ly = p.get('LABEL_X'), p.get('LABEL_Y')
        if lx is None or ly is None:
            continue
        lon, lat = round_coord(lx, ly)
        if iso2 in SHORT_COUNTRY_NAMES:
            name_en, name_zh = SHORT_COUNTRY_NAMES[iso2]
        else:
            name_en = str(p.get('NAME') or p.get('NAME_EN') or iso2).strip()
            name_zh = clean_zh(p.get('NAME_ZH')) or name_en
        if iso2 in NEUTRAL_COUNTRY_OVERRIDES:
            name_en, name_zh = NEUTRAL_COUNTRY_OVERRIDES[iso2]

        # Prefer primary sovereign/non-disputed entry (ADM0_DIF == 0) then larger population
        is_primary = 1 if (p.get('ADM0_DIF') in (0, None) or iso2 in ('TW', 'HK', 'MO')) else 0
        pop = int(p.get('POP_EST') or 0)
        prev = country_candidates.get(iso2)
        if prev is None or (is_primary, pop) > (prev[0], prev[1]):
            country_candidates[iso2] = (is_primary, pop, (lon, lat, name_en, name_zh))

    countries: Dict[str, List[object]] = {
        iso2: [v[0], v[1], v[2], v[3]]
        for iso2, (_, _, v) in sorted(country_candidates.items())
    }

    # 2. Regions (NE 10m admin-1 centroids -> "${CC}:${norm_key}")
    # Keep all admin-1 units for major/AC6 countries plus scalerank <= 5 globally;
    # attach Chinese keys for CJK + AC6/major countries and global scalerank <= 3 so
    # gzip stays comfortably within <= 150 KB while covering every GeoIP province/state.
    REGION_CORE_CC = {
        'CN', 'TW', 'HK', 'MO', 'JP', 'KR', 'SG', 'US', 'CA', 'DE', 'FR', 'GB',
        'IN', 'AU', 'BR', 'RU', 'ZA', 'NL', 'CH', 'IT', 'ES', 'PL', 'SE', 'IE',
        'ID', 'MY', 'TH', 'VN', 'PH', 'MX', 'AR', 'TR', 'AE', 'IL', 'NZ', 'UA', 'PK',
    }
    REGION_ZH_CC = {
        'CN', 'TW', 'HK', 'MO', 'JP', 'KR', 'SG', 'US', 'CA', 'DE', 'GB', 'FR',
        'IN', 'AU', 'BR', 'RU', 'ZA',
    }
    regions: Dict[str, List[object]] = {}
    region_rank: Dict[str, float] = {}

    for f in a1['features']:
        p = f.get('properties') or {}
        lon_raw, lat_raw = p.get('longitude'), p.get('latitude')
        if lon_raw is None or lat_raw is None:
            continue
        a3 = str(p.get('adm0_a3') or '').strip().upper()
        cc = a3_to_iso2.get(a3) or pick_iso2(p)
        if not cc:
            continue
        rank = float(p.get('scalerank') if p.get('scalerank') is not None else 9)
        # Skip ultra-fine micro-divisions (e.g. tiny parishes) outside major countries
        if cc not in REGION_CORE_CC and rank > 5:
            continue
        # UK/FR have 100-200 tiny subdivisions in NE admin-1; keep major/named ones
        if cc in ('GB', 'FR', 'PH', 'TH', 'ID', 'VN') and rank > 7:
            continue
        name_en = str(p.get('name_en') or p.get('name') or '').strip()
        name_alt = str(p.get('name') or '').strip()
        name_zh_raw = clean_zh(p.get('name_zh'))
        if not name_en and not name_zh_raw:
            continue
        lon, lat = round_coord(lon_raw, lat_raw)
        disp_en = name_en or name_zh_raw
        disp_zh = (name_zh_raw or disp_en) if (cc in REGION_ZH_CC or rank <= 3) else disp_en
        entry = [lon, lat, disp_en, disp_zh]

        keys_to_add = set()
        for candidate in (name_en, name_alt):
            nk = normalize_geo_key(candidate)
            if nk:
                keys_to_add.add(nk)
        if name_zh_raw and (cc in REGION_ZH_CC or rank <= 3):
            nk_zh = normalize_geo_key(name_zh_raw)
            if nk_zh:
                keys_to_add.add(nk_zh)

        # Add ISO 3166-2 short subdivision code (e.g. US-CA -> US:ca) for federal states
        iso_sub = str(p.get('iso_3166_2') or '').strip().upper()
        if cc in ('US', 'CA', 'AU', 'BR', 'DE', 'IN') and iso_sub.startswith(cc + '-'):
            sub = iso_sub[len(cc) + 1:].lower()
            if 1 <= len(sub) <= 3 and sub.isalpha():
                keys_to_add.add(sub)

        for nk in keys_to_add:
            full_key = f'{cc}:{nk}'
            if full_key not in regions or rank < region_rank[full_key]:
                regions[full_key] = entry
                region_rank[full_key] = rank

    # 3. Cities (NE 10m populated_places sorted by POP_MAX desc + curated global/CN hubs)
    pp_rows = []
    for f in pp['features']:
        p = f.get('properties') or {}
        g = f.get('geometry') or {}
        if g.get('type') != 'Point':
            continue
        coords = g.get('coordinates') or []
        if len(coords) < 2:
            continue
        a3 = str(p.get('ADM0_A3') or '').strip().upper()
        cc = a3_to_iso2.get(a3) or pick_iso2(p)
        if not cc:
            continue
        name_en = str(p.get('NAME_EN') or p.get('NAME') or p.get('NAMEASCII') or '').strip()
        name_short = str(p.get('NAME') or '').strip()
        name_ascii = str(p.get('NAMEASCII') or '').strip()
        name_zh = clean_zh(p.get('NAME_ZH')) or name_en
        if not name_en and not name_zh:
            continue
        pop = int(p.get('POP_MAX') or 0)
        sr = int(p.get('SCALERANK') if p.get('SCALERANK') is not None else 10)
        cap = int(p.get('ADM0CAP') or 0)
        lon, lat = round_coord(coords[0], coords[1])
        pp_rows.append((cap, pop, -sr, cc, lon, lat, name_en, name_short, name_ascii, name_zh))

    # Highest capital / population wins collisions on the same "${CC}:${norm_key}"
    pp_rows.sort(key=lambda r: (r[0], r[1], r[2]), reverse=True)

    CJK_CC = {'CN', 'TW', 'HK', 'MO', 'JP', 'KR', 'SG'}
    PRIORITY_CC = CJK_CC | {'US', 'CA', 'GB', 'DE', 'FR', 'NL', 'IN', 'AU', 'BR', 'RU', 'ZA', 'IT', 'ES', 'CH', 'IE', 'SE', 'PL'}

    def assemble_cities(
        min_pop_other: int,
        min_pop_prio: int,
        max_sr_other: int,
        zh_pop_threshold: int,
    ) -> Dict[str, List[object]]:
        cities: Dict[str, List[object]] = {}
        for cap, pop, neg_sr, cc, lon, lat, name_en, name_short, name_ascii, name_zh in pp_rows:
            sr = -neg_sr
            keep = (
                bool(cap)
                or (cc in CJK_CC)
                or (cc in PRIORITY_CC and (pop >= min_pop_prio or sr <= 6))
                or (pop >= min_pop_other)
                or (sr <= max_sr_other)
            )
            if not keep:
                continue
            display_en = name_short or name_en
            want_zh = cc in CJK_CC or bool(cap) or pop >= zh_pop_threshold or sr <= 3
            disp_zh = (name_zh or display_en) if want_zh else display_en
            entry = [lon, lat, display_en, disp_zh]
            alias_candidates = [display_en, name_ascii]
            if name_en != display_en and len(name_en) <= 24:
                alias_candidates.append(name_en)
            if want_zh and name_zh:
                alias_candidates.append(name_zh)
            for cand in alias_candidates:
                nk = normalize_geo_key(cand)
                if not nk:
                    continue
                full_key = f'{cc}:{nk}'
                if full_key not in cities:
                    cities[full_key] = entry

        # Apply curated places & aliases (authoritative for cloud/mesh hubs & clean CN names)
        for aliases, lon, lat, cc, name_en, name_zh, level in CURATED_PLACES:
            if level != 'city':
                continue
            r_lon, r_lat = round_coord(lon, lat)
            entry = [r_lon, r_lat, name_en, name_zh]
            for a in aliases:
                nk = normalize_geo_key(a)
                if nk:
                    cities[f'{cc}:{nk}'] = entry
        return cities

    # Target <= 130 KB at default gzip level 6 so `gzip -c | wc -c` stays comfortably <= 150 KB
    target_comfort = min(max_gz_bytes, 132_000)
    tiers = [
        (100_000, 50_000, 5, 350_000),
        (150_000, 75_000, 4, 500_000),
        (250_000, 100_000, 4, 750_000),
        (400_000, 150_000, 3, 1_000_000),
    ]
    chosen_payload = None
    chosen_stats = None
    for min_pop_other, min_pop_prio, max_sr_other, zh_pop in tiers:
        cities = assemble_cities(min_pop_other, min_pop_prio, max_sr_other, zh_pop)
        payload = {
            'version': 1,
            'countries': dict(sorted(countries.items())),
            'regions': dict(sorted(regions.items())),
            'cities': dict(sorted(cities.items())),
        }
        raw_bytes = (json.dumps(payload, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
        gz6_bytes = gzip.compress(raw_bytes, compresslevel=6)
        gz9_bytes = gzip.compress(raw_bytes, compresslevel=9)
        stats = {
            'tier': (min_pop_other, min_pop_prio, max_sr_other, zh_pop),
            'countries': len(payload['countries']),
            'regions': len(payload['regions']),
            'cities': len(payload['cities']),
            'raw_bytes': len(raw_bytes),
            'gz_bytes': len(gz6_bytes),
            'gz9_bytes': len(gz9_bytes),
        }
        chosen_payload = payload
        chosen_stats = stats
        if len(gz6_bytes) <= target_comfort:
            break

    assert chosen_payload is not None and chosen_stats is not None
    if chosen_stats['gz_bytes'] > max_gz_bytes:
        raise RuntimeError(
            f"gazetteer gzip size {chosen_stats['gz_bytes']} exceeds budget {max_gz_bytes} bytes"
        )
    return chosen_payload, chosen_stats


def main() -> int:
    parser = argparse.ArgumentParser(description='Build compact lazy gazetteer-v1.json from Natural Earth 5.1.2')
    parser.add_argument('--sources-dir', required=True, help='Directory containing pinned NE GeoJSON files')
    parser.add_argument('--output', required=True, help='Output path for gazetteer-v1.json')
    parser.add_argument('--max-gz-bytes', type=int, default=153600, help='Maximum gzipped size in bytes (default: 150 KiB)')
    args = parser.parse_args()

    payload, stats = build_gazetteer(args.sources_dir, args.max_gz_bytes)
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':')) + '\n'
    with open(args.output, 'w', encoding='utf-8') as fh:
        fh.write(raw)

    print(
        f"Built {args.output}: countries={stats['countries']}, regions={stats['regions']}, "
        f"cities={stats['cities']}, raw={stats['raw_bytes']} B, gzip={stats['gz_bytes']} B "
        f"(tier={stats['tier']})"
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
