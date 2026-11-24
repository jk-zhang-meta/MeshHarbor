#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 G ROX EOOD
#
# Build China's unified 3-tier internal administrative dataset (FR-136 P1):
#   1) Tagged mainland China ADM3 polygons (with parent UN OCHA ADM1/ADM2 codes)
#      strictly filtered to Natural Earth 10m de facto CHN (excluding TW/HK/MO
#      and territories outside NE de facto CHN), enabling mapshaper to extract
#      topologically identical, zero-overlap province (admin1), prefecture
#      (admin2_pref), and district/county (admin2) internal lines.
#   2) Point label layer `label_admin2` (PointOnSurface interior points) with
#      authentic Simplified Chinese (`name_zh`) and normalized English (`name_en`)
#      names for China's counties and districts.

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set, Tuple

from osgeo import ogr

ogr.UseExceptions()

CJK_RE = re.compile(r'[\u4e00-\u9fff]')
EN_CLEAN_RE = re.compile(r'[^a-z]+')
ZH_SUFFIX_1 = re.compile(r'(区|县|市|旗)$')
ZH_SUFFIX_LONG = re.compile(
    r'(自治县|自治旗|新区|矿区|特区|联合旗|左翼前旗|左翼中旗|左翼后旗|'
    r'右翼前旗|右翼中旗|右翼后旗|前旗|中旗|后旗|左旗|右旗)$'
)
ETHNIC_ZH_RE = re.compile(
    r'(蒙古族|藏族|回族|维吾尔族|苗族|彝族|壮族|布依族|朝鲜族|满族|侗族|瑶族|'
    r'白族|土家族|哈尼族|哈萨克族|傣族|黎族|傈僳族|佤族|畲族|拉祜族|水族|东乡族|'
    r'纳西族|景颇族|柯尔克孜族|土族|达斡尔族|仫佬族|羌族|布朗族|撒拉族|毛南族|'
    r'仡佬族|锡伯族|阿昌族|普米族|塔吉克族|怒族|鄂温克族|德昂族|保安族|裕固族|'
    r'京族|独龙族|鄂伦春族|各族|蒙古|回|藏|苗|彝|壮|满|侗|瑶|白|土家|黎|羌|傣|'
    r'拉祜|纳西|布依|东乡|撒拉|裕固|保安|毛南|仡佬|仫佬|怒|独龙|布朗|佤|哈尼|'
    r'傈僳|景颇|阿昌|普米|水族|畲|塔吉克|锡伯|鄂温克|鄂伦春|达斡尔|朝鲜|土)+$'
)
EN_ETHNIC_WORDS = {
    'manchu', 'mongol', 'mongolian', 'hui', 'tibetan', 'uyghur', 'uighur', 'miao',
    'yi', 'zhuang', 'bouyei', 'buyei', 'korean', 'dong', 'yao', 'bai', 'tujia',
    'hani', 'kazakh', 'kazak', 'dai', 'li', 'lisu', 'va', 'wa', 'she', 'lahu',
    'sui', 'shui', 'dongxiang', 'naxi', 'jingpo', 'kyrgyz', 'kirgiz', 'tu',
    'daur', 'mulam', 'qiang', 'blang', 'bulang', 'salar', 'maonan', 'gelao',
    'xibe', 'achang', 'pumi', 'tajik', 'nu', 'evenki', 'ewenki', 'oroqen',
    'deang', 'bonan', 'yugur', 'gin', 'derung', 'dulong', 'jino', 'various',
    'nationalities', 'ethnicities', 'and', 'of',
}
EN_SUFFIXES = (
    ' autonomous county', ' autonomous banner', ' new district', ' new area',
    ' mining district', ' forestry district', ' special district',
    ' district', ' county', ' city', ' banner', ' qu', ' xian', ' shi', ' qi',
    ' xinqu', ' zizhixian', ' zizhiqi', ' left', ' right', ' front', ' back',
    ' middle', ' rear', ' united',
)

# Common Chinese toponym polyphone overrides
TOPONYM_READINGS: Dict[str, List[str]] = {
    '单': ['shan', 'dan'], '解': ['xie', 'jie'], '繁': ['po', 'fan'],
    '番': ['pan', 'fan'], '泌': ['bi', 'mi'], '浚': ['xun', 'jun'],
    '尉': ['yu', 'wei'], '长': ['chang', 'zhang'], '重': ['chong', 'zhong'],
    '乐': ['le', 'yue', 'lao'], '朝': ['chao', 'zhao'], '宿': ['su', 'xiu'],
    '六': ['lu', 'liu'], '合': ['he', 'ge'], '蚌': ['beng', 'bang'],
    '涡': ['guo', 'wo'], '歙': ['she', 'xi'], '铅': ['yan', 'qian'],
    '都': ['du', 'dou'], '犍': ['qian', 'jian'], '荥': ['xing', 'ying'],
    '渑': ['mian', 'sheng'], '莘': ['shen', 'xin'], '费': ['fei', 'bi'],
    '阿': ['a', 'e'], '叶': ['ye', 'xie'], '蔚': ['yu', 'wei'],
    '柏': ['bai', 'bo'], '洞': ['tong', 'dong'], '大': ['da', 'dai'],
    '宕': ['tang', 'dang'], '石': ['shi', 'dan'],
}


def strip_tones(s: str) -> str:
    s = unicodedata.normalize('NFKD', s)
    s = ''.join(ch for ch in s if not unicodedata.combining(ch))
    return s.replace('ü', 'u').replace('v', 'u').lower().strip()


def load_pinyin_map(path: str) -> Dict[str, List[str]]:
    pmap: Dict[str, List[str]] = {}
    with open(path, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            code_part, rest = line.split(':', 1)
            cp = int(code_part.strip()[2:], 16)
            syls = [strip_tones(s) for s in rest.split('#', 1)[0].split(',') if strip_tones(s)]
            if syls:
                pmap[chr(cp)] = list(dict.fromkeys(syls))
    for ch, syls in TOPONYM_READINGS.items():
        cur = pmap.get(ch, [])
        pmap[ch] = syls + [s for s in cur if s not in syls]
    return pmap


def hanzi_pinyin_variants(zh: str, pmap: Dict[str, List[str]], max_v: int = 64) -> Set[str]:
    variants = ['']
    for ch in zh:
        syls = pmap.get(ch)
        if not syls:
            continue
        next_v: List[str] = []
        for v in variants:
            for s in syls[:4]:
                next_v.append(v + s)
                if len(next_v) >= max_v:
                    break
            if len(next_v) >= max_v:
                break
        variants = next_v
    return set(variants)


def norm_zh_stems(zh: str, pmap: Dict[str, List[str]]) -> Set[str]:
    s0 = re.sub(r'\[\d+\]', '', zh.strip())
    stems = {s0}
    if s0.endswith('林区') and len(s0) > 2:
        stems.add(s0[:-2])
    for rx in (ZH_SUFFIX_1, ZH_SUFFIX_LONG):
        s1 = rx.sub('', s0)
        if len(s1) >= 1:
            stems.add(s1)
            s2 = ETHNIC_ZH_RE.sub('', s1)
            if len(s2) >= 2:
                stems.add(s2)
    out: Set[str] = set()
    for st in stems:
        out |= hanzi_pinyin_variants(st, pmap)
    return out


def norm_en_stems(name: str) -> Set[str]:
    s = unicodedata.normalize('NFKD', name or '')
    s = ''.join(ch for ch in s if not unicodedata.combining(ch)).lower().strip()
    s = s.replace("'", '').replace('’', '').replace('-', ' ')
    s = re.sub(r'\s+', ' ', s)
    out: Set[str] = set()
    cur = s
    for _ in range(4):
        changed = False
        for suf in EN_SUFFIXES:
            if cur.endswith(suf) and len(cur) > len(suf) + 1:
                cur = cur[:-len(suf)].strip()
                changed = True
                break
        if not changed:
            break
    out.add(EN_CLEAN_RE.sub('', cur))
    toks = cur.split()
    while len(toks) > 1 and toks[-1] in EN_ETHNIC_WORDS:
        toks.pop()
    if toks:
        out.add(EN_CLEAN_RE.sub('', ''.join(toks)))
    if len(toks) >= 2:
        out.add(EN_CLEAN_RE.sub('', toks[0]))
    out.discard('')
    return out


def clean_en_title(raw: str) -> str:
    s = re.sub(r'\s+', ' ', (raw or '').strip())
    # Normalize trailing lowercase admin nouns (e.g. "Nanshan district" -> "Nanshan District")
    s = re.sub(r'\b(district|county|city|banner|new district|mining district)$',
               lambda m: m.group(1).title(), s, flags=re.IGNORECASE)
    return s


def norm_pref_key(zh: str) -> str:
    s = re.sub(r'\[\d+\]', '', (zh or '').strip())
    return re.sub(r'(自治州|地区|盟|市)$', '', s)


def compute_area_rank(area_deg2: float) -> int:
    # 1 = largest rural/prefecture-scale county, 5 = compact urban core district
    if area_deg2 >= 1.0:
        return 1
    if area_deg2 >= 0.25:
        return 2
    if area_deg2 >= 0.08:
        return 3
    if area_deg2 >= 0.02:
        return 4
    return 5


def main() -> int:
    parser = argparse.ArgumentParser(description='Build unified China ADM3 tagged polygons and label_admin2 points')
    parser.add_argument('--ne-admin0', required=True)
    parser.add_argument('--ocha-adm2-shp', required=True)
    parser.add_argument('--gb-adm3', required=True)
    parser.add_argument('--modood-cities', required=True)
    parser.add_argument('--modood-areas', required=True)
    parser.add_argument('--pinyin', required=True)
    parser.add_argument('--exonyms', required=True)
    parser.add_argument('--out-tagged', required=True)
    parser.add_argument('--out-labels', required=True)
    args = parser.parse_args()

    # 1. Load NE 10m de facto CHN mask (strictly excludes TW, HK, MO, Arunachal)
    ne0 = ogr.Open(args.ne_admin0)
    lyr0 = ne0.GetLayer(0)
    lyr0.SetAttributeFilter("ADM0_A3 = 'CHN'")
    chn_mask = None
    for feat in lyr0:
        g = feat.GetGeometryRef().Clone()
        chn_mask = g if chn_mask is None else chn_mask.Union(g)
    if chn_mask is None:
        raise RuntimeError('Failed to load NE 10m CHN polygon')

    # 2. Load OCHA ADM2 polygons (mainland only; record HK/MO separately for strict exclusion)
    ds_ocha = ogr.Open(args.ocha_adm2_shp)
    ocha_polys: List[Tuple[str, str, str, str, Tuple[float, float, float, float], ogr.Geometry]] = []
    hkmo_polys: List[Tuple[Tuple[float, float, float, float], ogr.Geometry]] = []
    for feat in ds_ocha.GetLayer(0):
        p1 = feat.GetField('ADM1_PCODE')
        g = feat.GetGeometryRef().Clone()
        if p1 in ('CN081', 'CN082'):
            hkmo_polys.append((g.GetEnvelope(), g))
            continue
        if p1 == 'CN071':
            continue
        a2z = re.sub(r'\[\d+\]', '', feat.GetField('ADM2_ZH') or '').strip()
        ocha_polys.append((p1, feat.GetField('ADM2_PCODE'), feat.GetField('ADM1_ZH') or '', a2z, g.GetEnvelope(), g))

    # 3. Load modood GB/T 2260 cities & areas + pinyin map + audited exonym overrides
    pmap = load_pinyin_map(args.pinyin)
    modood_cities = json.load(open(args.modood_cities, encoding='utf-8'))
    modood_areas = json.load(open(args.modood_areas, encoding='utf-8'))
    exonyms: Dict[str, List[str]] = json.load(open(args.exonyms, encoding='utf-8'))

    city_code_to_pref_key: Dict[str, str] = {}
    for c in modood_cities:
        city_code_to_pref_key[c['code']] = norm_pref_key(c['name'])

    SKIP_ZH = {'市辖区', '县', '省直辖县级行政区划', '自治区直辖县级行政区划'}
    areas_by_pref: Dict[Tuple[str, str], List[Tuple[str, Set[str]]]] = defaultdict(list)
    areas_by_prov: Dict[str, List[Tuple[str, Set[str]]]] = defaultdict(list)

    for a in modood_areas:
        zh = a['name'].strip()
        if zh in SKIP_ZH:
            continue
        stems = norm_zh_stems(zh, pmap)
        pcode = a['provinceCode']
        pref_k = city_code_to_pref_key.get(a['cityCode'], '')
        if pref_k:
            areas_by_pref[(pcode, pref_k)].append((zh, stems))
        areas_by_prov[pcode].append((zh, stems))

    for c in modood_cities:
        zh = c['name'].strip()
        if zh in SKIP_ZH:
            continue
        stems = norm_zh_stems(zh, pmap)
        pcode = c['provinceCode']
        areas_by_pref[(pcode, norm_pref_key(zh))].append((zh, stems))
        areas_by_prov[pcode].append((zh, stems))

    # 4. Process geoBoundaries-CHN-ADM3 polygons
    adm3 = json.load(open(args.gb_adm3, encoding='utf-8'))
    tagged_feats = []
    label_feats = []
    p1_set = set()
    p2_set = set()
    stats = Counter()

    def pick_best(cands: List[Tuple[str, Set[str]]], en_stems: Set[str], want_suf: str) -> Optional[str]:
        hits = [zh for zh, pset in cands if en_stems & pset]
        if not hits:
            return None
        if want_suf:
            pref = [h for h in hits if h.endswith(want_suf)]
            if pref:
                return pref[0]
        return hits[0]

    for feat in adm3['features']:
        raw_name = str((feat.get('properties') or {}).get('shapeName') or '').strip()
        geom_json = feat.get('geometry')
        if not geom_json:
            continue
        g = ogr.CreateGeometryFromJson(json.dumps(geom_json))
        if not g or g.IsEmpty():
            continue
        pt = g.PointOnSurface()
        px, py = pt.GetX(), pt.GetY()

        # Strictly exclude Hong Kong, Macau, Taiwan, and anything outside NE de facto CHN
        if any(
            env[0] - 0.03 <= px <= env[1] + 0.03
            and env[2] - 0.03 <= py <= env[3] + 0.03
            and (hg.Contains(pt) or hg.Distance(pt) < 0.015)
            for env, hg in hkmo_polys
        ):
            stats['excluded_hkmo'] += 1
            continue
        if not chn_mask.Contains(pt) and chn_mask.Distance(pt) > 0.05:
            stats['excluded_outside_ne_chn'] += 1
            continue

        if not g.IsValid():
            g = g.Buffer(0)
        ge = g.GetEnvelope()
        best_ocha = None
        best_area = -1.0
        for p1, p2, a1z, a2z, env, og in ocha_polys:
            if ge[1] < env[0] or ge[0] > env[1] or ge[3] < env[2] or ge[2] > env[3]:
                continue
            inter = g.Intersection(og)
            if inter and not inter.IsEmpty():
                a = inter.GetArea()
                if a > best_area:
                    best_area = a
                    best_ocha = (p1, p2, a1z, a2z)
        if best_ocha is None:
            best_d = 1e9
            for p1, p2, a1z, a2z, env, og in ocha_polys:
                if env[0] - 0.5 <= px <= env[1] + 0.5 and env[2] - 0.5 <= py <= env[3] + 0.5:
                    d = og.Distance(pt)
                    if d < best_d:
                        best_d = d
                        best_ocha = (p1, p2, a1z, a2z)
        if best_ocha is None:
            stats['no_ocha'] += 1
            continue

        p1, p2, a1z, a2z = best_ocha
        gb_prov = p1[3:5]
        p1_set.add(p1)
        p2_set.add(p2)

        # Resolve authentic Simplified Chinese name_zh & clean English name_en
        exo_key = f'{gb_prov}:{raw_name}'
        name_zh: Optional[str] = None
        name_en = clean_en_title(raw_name)

        if exo_key in exonyms:
            entry = exonyms[exo_key]
            name_zh = entry[0]
            if len(entry) > 1 and entry[1]:
                name_en = entry[1]
            stats['matched_exonym'] += 1
        elif CJK_RE.search(raw_name):
            # Fallback for any CJK-containing raw_name not already in exonyms
            name_zh = raw_name
            stats['matched_cjk_raw'] += 1
        else:
            en_stems = norm_en_stems(raw_name)
            en_low = raw_name.lower()
            want_suf = (
                '区' if 'district' in en_low else
                '县' if 'county' in en_low else
                '市' if 'city' in en_low else
                '旗' if 'banner' in en_low else ''
            )
            pref_k = norm_pref_key(a2z)
            # 1) Prefecture-scoped match (eliminates same-province homophone collisions)
            name_zh = pick_best(areas_by_pref.get((gb_prov, pref_k), []), en_stems, want_suf)
            if name_zh:
                stats['matched_pref'] += 1
            else:
                # 2) Province-scoped fallback
                name_zh = pick_best(areas_by_prov.get(gb_prov, []), en_stems, want_suf)
                if name_zh:
                    stats['matched_prov'] += 1
                else:
                    stats['unmatched_zh'] += 1
                    name_zh = name_en

        tagged_feats.append({
            'type': 'Feature',
            'geometry': geom_json,
            'properties': {
                'ocha_p1': p1,
                'ocha_p2': p2,
                'name_en': name_en,
                'name_zh': name_zh,
            },
        })

        label_feats.append({
            'type': 'Feature',
            'geometry': {
                'type': 'Point',
                'coordinates': [round(px, 4), round(py, 4)],
            },
            'properties': {
                'cc': 'CHN',
                'iso_a2': 'CN',
                'name_en': name_en,
                'name_zh': name_zh,
                'area_rank': compute_area_rank(g.GetArea()),
            },
        })

    os.makedirs(os.path.dirname(os.path.abspath(args.out_tagged)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.out_labels)), exist_ok=True)
    json.dump({'type': 'FeatureCollection', 'features': tagged_feats},
              open(args.out_tagged, 'w', encoding='utf-8'), ensure_ascii=False)
    json.dump({'type': 'FeatureCollection', 'features': label_feats},
              open(args.out_labels, 'w', encoding='utf-8'), ensure_ascii=False)

    total = len(label_feats)
    zh_ok = sum(1 for f in label_feats if CJK_RE.search(f['properties']['name_zh']))
    zh_pct = 100.0 * zh_ok / max(total, 1)
    print(
        f'  China ADM3 unified: polygons={total}, provinces={len(p1_set)}, '
        f'prefectures={len(p2_set)}, zh_labels={zh_ok}/{total} ({zh_pct:.2f}%), '
        f'stats={dict(stats)}'
    )

    assert len(p1_set) == 31, f'expected 31 mainland provinces, got {len(p1_set)}'
    assert len(p2_set) >= 330, f'expected >= 330 prefectures, got {len(p2_set)}'
    assert zh_pct >= 99.0, f'expected >= 99% Chinese district names, got {zh_pct:.2f}%'

    # Sanity-check flagship districts across Beijing, Shanghai, Shenzhen, Chengdu, Wuhan, Hangzhou
    zh_set = {f['properties']['name_zh'] for f in label_feats}
    for req in ('朝阳区', '海淀区', '浦东新区', '南山区', '福田区', '武侯区', '江汉区', '西湖区'):
        assert req in zh_set, f'flagship China district {req!r} missing from label_admin2'

    return 0


if __name__ == '__main__':
    sys.exit(main())
