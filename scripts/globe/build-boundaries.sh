#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 G ROX EOOD
#
# Reproducibly build:
#   1) ui/public/geo/mh-boundaries-v1.pmtiles (z0..z9, <= 40 MB, gitignored)
#   2) ui/src/components/globe-v2/data/gazetteer-v1.json (<= 150 KB gz)
# from pinned Natural Earth 5.1.2 (public domain), global geoBoundaries CGAZ
# ADM1/ADM2 (CC BY 4.0 / ODbL), geoBoundaries CHN ADM3 (OSM ODbL 1.0),
# UN OCHA COD-AB China 2020 (CC BY-IGO), and GB/T 2260 / pinyin tables
# listed in scripts/globe/SOURCES.lock.
#
# Policy (FR-136 S1 / S4 / S6 / S11 / AC6 / AC7 + China 4-level zoom):
# - Level 0 (`admin0`, z0..z9): de facto country boundary lines come ONLY from
#   Natural Earth (disputed segments cls="disputed", limits cls="limit";
#   international borders are NEVER taken from OSM/CGAZ/OCHA).
# - Level 1 (`admin1`, z2..z9):
#   - Outside China (`cc !== "CHN"`): global geoBoundaries CGAZ ADM1 internal
#     shared lines + Natural Earth 10m HK/MO patch, clipped to NE world mask.
#   - China (`cc === "CHN"`): 31 mainland provinces dissolved from unified
#     geoBoundaries CHN ADM3 topology, clipped strictly to NE de facto CHN mask
#     (excluding TW/HK/MO/territories outside NE CHN).
# - Level 2 (`admin2_pref`, z5..z9, `cc="CHN"`, `iso_a2="CN"`):
#   - China prefecture-level city internal lines (市界, ~358 prefecture units
#     across 31 mainland provinces), dissolved from the same unified topology
#     with `-split ocha_p1 -innerlines` so ZERO province/country borders leak.
# - Level 3 (`admin2`):
#   - Outside China (`cc !== "CHN"`, z5..z9): global geoBoundaries CGAZ ADM2
#     internal shared lines, clipped to NE world mask, ADM1-coincident segments
#     suppressed.
#   - China (`cc === "CHN"`, z7..z9): ~2,846 full-resolution modern mainland
#     China district and county internal lines (区县界), extracted via
#     `-split ocha_p2 -innerlines` from the exact same un-simplified planar
#     topology (zero double-lines with admin1 or admin2_pref; tippecanoe
#     simplifies per zoom with finest detail preserved at z9), clipped strictly
#     to NE de facto CHN mask minus HK/MO.
# - District/county labels (`label_admin2`, z8..z9): PointOnSurface interior
#   points for China's districts/counties with Simplified Chinese `name_zh` and
#   English `name_en` (`cc="CHN"`, `iso_a2="CN"`).
# - Neutral region overrides: TWN -> 台湾/Taiwan, HKG -> 香港/Hong Kong,
#   MAC -> 澳门/Macau (both override and primary fields sanitized).
# - The output .pmtiles binary is gitignored and never committed to git.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOCK_FILE="$SCRIPT_DIR/SOURCES.lock"

WORK_DIR="${GLOBE_BUILD_DIR:-${TMPDIR:-/tmp}/meshharbor-globe-build}"
SRC_DIR="$WORK_DIR/sources"
STAGE_DIR="$WORK_DIR/stage"
TILES_DIR="$WORK_DIR/tiles"
OUT_FILE="${GLOBE_OUT_PMTILES:-$REPO_ROOT/ui/public/geo/mh-boundaries-v1.pmtiles}"
GAZETTEER_OUT="${GLOBE_OUT_GAZETTEER:-$REPO_ROOT/ui/src/components/globe-v2/data/gazetteer-v1.json}"
MAX_ZOOM="${GLOBE_MAX_ZOOM:-9}"
ADM1_SIMPLIFY="${GLOBE_ADM1_SIMPLIFY:-5%}"
ADM2_SIMPLIFY="${GLOBE_ADM2_SIMPLIFY:-5%}"
MAX_PMTILES_BYTES="${GLOBE_MAX_PMTILES_BYTES:-40000000}"

MAPSHAPER_BIN="${MAPSHAPER_BIN:-$(command -v mapshaper || true)}"
MAPSHAPER_XL_BIN="${MAPSHAPER_XL_BIN:-$(command -v mapshaper-xl || true)}"
if [ -z "$MAPSHAPER_BIN" ]; then
  echo "error: mapshaper not found (set MAPSHAPER_BIN or add to PATH)" >&2
  exit 1
fi
if [ -z "$MAPSHAPER_XL_BIN" ]; then
  cand="$(dirname "$MAPSHAPER_BIN")/mapshaper-xl"
  if [ -x "$cand" ]; then
    MAPSHAPER_XL_BIN="$cand"
  fi
fi

run_mapshaper_xl() {
  local mem="$1"
  shift
  if [ -n "$MAPSHAPER_XL_BIN" ] && [ -x "$MAPSHAPER_XL_BIN" ]; then
    "$MAPSHAPER_XL_BIN" "$mem" "$@"
  else
    "$MAPSHAPER_BIN" "$@"
  fi
}

for bin in curl python3 tippecanoe tile-join sha256sum unzip; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "error: required build tool '$bin' not found in PATH" >&2
    exit 1
  fi
done

mkdir -p "$SRC_DIR" "$STAGE_DIR" "$TILES_DIR" "$(dirname "$OUT_FILE")"

echo "[1/8] Fetching & verifying pinned sources from SOURCES.lock..."
while read -r filename expected_sha url; do
  [[ -z "${filename:-}" || "$filename" == \#* ]] && continue
  dest="$SRC_DIR/$filename"
  if [ ! -s "$dest" ]; then
    echo "  downloading $filename"
    curl -fsSL -o "$dest" "$url"
  fi
  actual_sha="$(sha256sum "$dest" | awk '{print $1}')"
  if [ "$actual_sha" != "$expected_sha" ]; then
    echo "error: SHA-256 mismatch for $filename" >&2
    echo "  expected: $expected_sha" >&2
    echo "  actual:   $actual_sha" >&2
    exit 1
  fi
done < "$LOCK_FILE"

echo "[2/8] Building NE land, coastline, world/CHN/HKMO clip masks, and admin-0 de facto lines..."
"$MAPSHAPER_BIN" -i "$SRC_DIR/ne_50m_land.geojson" \
  -filter-fields "" \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/land_low.geojson"

"$MAPSHAPER_BIN" -i "$SRC_DIR/ne_10m_land.geojson" \
  -simplify 25% weighted keep-shapes \
  -filter-fields "" \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/land_high.geojson"

"$MAPSHAPER_BIN" -i "$STAGE_DIR/land_low.geojson" \
  -lines \
  -filter-fields "" \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/coast_low.geojson"

"$MAPSHAPER_BIN" -i "$STAGE_DIR/land_high.geojson" \
  -lines \
  -filter-fields "" \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/coast_high.geojson"

"$MAPSHAPER_BIN" -i "$SRC_DIR/ne_10m_admin_0_countries.geojson" \
  -dissolve \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/world_mask.geojson"

"$MAPSHAPER_BIN" -i "$SRC_DIR/ne_10m_admin_0_countries.geojson" \
  -filter 'ADM0_A3 === "CHN"' \
  -dissolve \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/chn_mask.geojson"

"$MAPSHAPER_BIN" -i "$SRC_DIR/ne_10m_admin_0_countries.geojson" \
  -filter 'ADM0_A3 === "HKG" || ADM0_A3 === "MAC"' \
  -dissolve \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/hkmo_mask.geojson"

python3 - "$SRC_DIR/ne_10m_admin_0_boundary_lines_land.geojson" "$STAGE_DIR/admin0.geojson" <<'PY'
import json, sys
from collections import Counter

src, dst = sys.argv[1], sys.argv[2]
data = json.load(open(src, encoding='utf-8'))
out_feats = []
counts = Counter()

def classify(fcla: str) -> str:
    s = (fcla or '').strip().lower()
    if s.startswith('international boundary'):
        return 'intl'
    if s.startswith('overlay limit') or s.startswith('lease limit'):
        return 'limit'
    return 'disputed'

for f in data['features']:
    p = f.get('properties') or {}
    cls = classify(p.get('FEATURECLA', ''))
    counts[cls] += 1
    out_feats.append({
        'type': 'Feature',
        'geometry': f['geometry'],
        'properties': {
            'cls': cls,
            'min_zoom': float(p.get('MIN_ZOOM') or 0),
        },
    })

json.dump({'type': 'FeatureCollection', 'features': out_feats}, open(dst, 'w', encoding='utf-8'))
print(f"  admin0 lines: {len(out_feats)} features ({dict(counts)})")
assert counts['disputed'] >= 60, f"expected >= 60 disputed segments, got {counts['disputed']}"
PY

echo "[3/8] Building China unified 3-tier topology (admin1 province, admin2_pref prefecture, admin2 district) + label_admin2..."
OCHA_CHN_DIR="$WORK_DIR/ocha_chn"
mkdir -p "$OCHA_CHN_DIR"
if [ ! -s "$OCHA_CHN_DIR/chn_admbnda_adm2_ocha_2020.shp" ]; then
  unzip -q -o "$SRC_DIR/chn_adm_ocha_2020_shp.zip" -d "$OCHA_CHN_DIR"
fi

python3 "$SCRIPT_DIR/build-chn-admin.py" \
  --ne-admin0 "$SRC_DIR/ne_10m_admin_0_countries.geojson" \
  --ocha-adm2-shp "$OCHA_CHN_DIR/chn_admbnda_adm2_ocha_2020.shp" \
  --gb-adm3 "$SRC_DIR/geoBoundaries-CHN-ADM3.geojson" \
  --modood-cities "$SRC_DIR/modood-cities.json" \
  --modood-areas "$SRC_DIR/modood-areas.json" \
  --pinyin "$SRC_DIR/pinyin.txt" \
  --exonyms "$SCRIPT_DIR/chn-district-exonyms.json" \
  --out-tagged "$STAGE_DIR/chn_adm3_tagged.geojson" \
  --out-labels "$STAGE_DIR/label_admin2.geojson"

# Clean full-resolution China ADM3 polygons ONCE without pre-simplification so
# all 3 internal line tiers share exact vertices and tippecanoe simplifies per zoom.
run_mapshaper_xl 6gb -i "$STAGE_DIR/chn_adm3_tagged.geojson" \
  -clean \
  -o format=topojson "$STAGE_DIR/chn_adm3_clean.topojson"

# Level 1 (China province internal borders: 省界)
run_mapshaper_xl 6gb -i "$STAGE_DIR/chn_adm3_clean.topojson" \
  -dissolve ocha_p1 \
  -innerlines \
  -each 'cc = "CHN"' \
  -clip "$STAGE_DIR/chn_mask.geojson" \
  -erase "$STAGE_DIR/hkmo_mask.geojson" \
  -filter 'this.partCount > 0' \
  -filter-fields cc \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/admin1_chn.geojson"

# Level 2 (China prefecture-level city internal borders: 市界)
run_mapshaper_xl 6gb -i "$STAGE_DIR/chn_adm3_clean.topojson" \
  -dissolve ocha_p2 copy-fields=ocha_p1 \
  -split ocha_p1 \
  -innerlines target=* \
  -each target=* 'cc = "CHN"' \
  -merge-layers target=* force \
  -clip "$STAGE_DIR/chn_mask.geojson" \
  -erase "$STAGE_DIR/hkmo_mask.geojson" \
  -filter 'this.partCount > 0' \
  -filter-fields cc \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/admin2_pref_raw.geojson"

# Level 3 (China district/county intra-prefecture internal borders: 区县界)
run_mapshaper_xl 6gb -i "$STAGE_DIR/chn_adm3_clean.topojson" \
  -split ocha_p2 \
  -innerlines target=* \
  -each target=* 'cc = "CHN"' \
  -merge-layers target=* force \
  -clip "$STAGE_DIR/chn_mask.geojson" \
  -erase "$STAGE_DIR/hkmo_mask.geojson" \
  -filter 'this.partCount > 0' \
  -filter-fields cc \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/admin2_chn_raw.geojson"

echo "[4/8] Building global geoBoundaries CGAZ ADM1 (non-CHN) + NE HK/MO patch..."
CGAZ_ADM1_DIR="$WORK_DIR/cgaz_adm1"
mkdir -p "$CGAZ_ADM1_DIR"
if [ ! -s "$CGAZ_ADM1_DIR/geoBoundariesCGAZ_ADM1.shp" ]; then
  unzip -q -o "$SRC_DIR/geoBoundariesCGAZ_ADM1.zip" -d "$CGAZ_ADM1_DIR"
fi

run_mapshaper_xl 6gb -i "$CGAZ_ADM1_DIR/geoBoundariesCGAZ_ADM1.shp" \
  -filter 'shapeGroup !== "CHN"' \
  -simplify "$ADM1_SIMPLIFY" weighted keep-shapes \
  -split shapeGroup \
  -innerlines target=* \
  -each target=* 'cc = this.layer_name' \
  -merge-layers target=* force \
  -clip "$STAGE_DIR/world_mask.geojson" \
  -erase "$STAGE_DIR/hkmo_mask.geojson" \
  -filter 'this.partCount > 0' \
  -filter-fields cc \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/admin1_cgaz_non_chn.geojson"

"$MAPSHAPER_BIN" -i "$SRC_DIR/ne_10m_admin_1_states_provinces.geojson" \
  -filter 'adm0_a3 === "HKG" || adm0_a3 === "MAC"' \
  -split adm0_a3 \
  -innerlines target=* \
  -each target=* 'cc = this.layer_name' \
  -merge-layers target=* force \
  -clip "$STAGE_DIR/world_mask.geojson" \
  -filter 'this.partCount > 0' \
  -filter-fields cc \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/admin1_hkmo.geojson"

"$MAPSHAPER_BIN" -i \
  "$STAGE_DIR/admin1_cgaz_non_chn.geojson" \
  "$STAGE_DIR/admin1_chn.geojson" \
  "$STAGE_DIR/admin1_hkmo.geojson" combine-files \
  -merge-layers target=* force \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/admin1_raw.geojson"

echo "[5/8] Building global geoBoundaries CGAZ ADM2 (non-CHN, $ADM2_SIMPLIFY) and finalizing admin1 / admin2_pref / admin2..."
CGAZ_ADM2_DIR="$WORK_DIR/cgaz_adm2"
mkdir -p "$CGAZ_ADM2_DIR"
if [ ! -s "$CGAZ_ADM2_DIR/geoBoundariesCGAZ_ADM2.shp" ]; then
  unzip -q -o "$SRC_DIR/geoBoundariesCGAZ_ADM2.zip" -d "$CGAZ_ADM2_DIR"
fi

run_mapshaper_xl 8gb -i "$CGAZ_ADM2_DIR/geoBoundariesCGAZ_ADM2.shp" \
  -filter 'shapeGroup !== "CHN"' \
  -simplify "$ADM2_SIMPLIFY" weighted keep-shapes \
  -split shapeGroup \
  -innerlines target=* \
  -each target=* 'cc = this.layer_name' \
  -merge-layers target=* force \
  -clip "$STAGE_DIR/world_mask.geojson" \
  -filter 'this.partCount > 0' \
  -filter-fields cc \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/admin2_non_chn_raw.geojson"

# Enrich admin1, admin2_pref, and admin2 with ISO-2 `iso_a2` (preserving ISO-3 `cc`),
# suppress coincident duplicate segments across tiers, and set per-feature tippecanoe
# minzoom (non-CHN admin2: z5..zMAX; CHN admin2 districts: z7..zMAX).
python3 - \
  "$SRC_DIR/ne_10m_admin_0_countries.geojson" \
  "$STAGE_DIR/admin1_raw.geojson" \
  "$STAGE_DIR/admin2_pref_raw.geojson" \
  "$STAGE_DIR/admin2_non_chn_raw.geojson" \
  "$STAGE_DIR/admin2_chn_raw.geojson" \
  "$STAGE_DIR/admin1.geojson" \
  "$STAGE_DIR/admin2_pref.geojson" \
  "$STAGE_DIR/admin2.geojson" \
  "$MAX_ZOOM" <<'PY'
import json, sys
from collections import Counter

(a0_path, a1_in, pref_in, a2_other_in, a2_chn_in,
 a1_out, pref_out, a2_out, max_zoom_str) = sys.argv[1:10]
max_zoom = int(max_zoom_str)

a0 = json.load(open(a0_path, encoding='utf-8'))
a3_to_a2 = {
    'TWN': 'TW', 'HKG': 'HK', 'MAC': 'MO', 'FRA': 'FR', 'NOR': 'NO',
    'KOS': 'XK', 'XKX': 'XK', 'CHN': 'CN',
}
for f in a0['features']:
    p = f.get('properties') or {}
    a3 = str(p.get('ADM0_A3') or p.get('ISO_A3') or '').strip().upper()
    i2 = str(p.get('ISO_A2') or '').strip().upper()
    eh = str(p.get('ISO_A2_EH') or '').strip().upper()
    iso2 = i2 if (len(i2) == 2 and i2.isalpha()) else (eh if (len(eh) == 2 and eh.isalpha()) else '')
    if a3 and iso2:
        a3_to_a2.setdefault(a3, iso2)

def seg_key(p1, p2, prec=3):
    q1 = (round(p1[0], prec), round(p1[1], prec))
    q2 = (round(p2[0], prec), round(p2[1], prec))
    if q1 == q2:
        return None
    return (q1, q2) if q1 < q2 else (q2, q1)

def collect_segs(geom, target_set, prec=3):
    lines = [geom['coordinates']] if geom['type'] == 'LineString' else (
        geom['coordinates'] if geom['type'] == 'MultiLineString' else []
    )
    for line in lines:
        for i in range(len(line) - 1):
            k = seg_key(line[i], line[i + 1], prec)
            if k is not None:
                target_set.add(k)

def strip_coincident(line, forbid_set, prec=3):
    runs = []
    cur = []
    suppressed = 0
    for i in range(len(line) - 1):
        k = seg_key(line[i], line[i + 1], prec)
        if k is not None and k in forbid_set:
            suppressed += 1
            if len(cur) >= 2:
                runs.append(cur)
            cur = []
        else:
            if not cur:
                cur = [line[i], line[i + 1]]
            else:
                cur.append(line[i + 1])
    if len(cur) >= 2:
        runs.append(cur)
    return runs, suppressed

# 1) admin1
a1_data = json.load(open(a1_in, encoding='utf-8'))
a1_segs_p3 = set()
a1_segs_p5 = set()
a1_cc_counts = Counter()
a1_feats = []
for f in a1_data['features']:
    g = f.get('geometry')
    if not g:
        continue
    cc = str((f.get('properties') or {}).get('cc') or '').strip().upper()
    props = {'cc': cc}
    if cc in a3_to_a2:
        props['iso_a2'] = a3_to_a2[cc]
    a1_cc_counts[cc] += 1
    a1_feats.append({'type': 'Feature', 'geometry': g, 'properties': props})
    collect_segs(g, a1_segs_p3, 3)
    if cc == 'CHN':
        collect_segs(g, a1_segs_p5, 5)
json.dump({'type': 'FeatureCollection', 'features': a1_feats}, open(a1_out, 'w', encoding='utf-8'))

# 2) admin2_pref (China prefecture-level city internal lines: 市界)
pref_data = json.load(open(pref_in, encoding='utf-8'))
pref_segs_p5 = set()
pref_feats = []
pref_suppressed = 0
for f in pref_data['features']:
    g = f.get('geometry')
    if not g:
        continue
    lines = [g['coordinates']] if g['type'] == 'LineString' else (
        g['coordinates'] if g['type'] == 'MultiLineString' else []
    )
    kept = []
    for line in lines:
        runs, s = strip_coincident(line, a1_segs_p5, 5)
        pref_suppressed += s
        kept.extend(runs)
    if not kept:
        continue
    geom = {'type': 'LineString', 'coordinates': kept[0]} if len(kept) == 1 else {
        'type': 'MultiLineString', 'coordinates': kept
    }
    collect_segs(geom, pref_segs_p5, 5)
    pref_feats.append({
        'type': 'Feature',
        'geometry': geom,
        'properties': {'cc': 'CHN', 'iso_a2': 'CN'},
    })
json.dump({'type': 'FeatureCollection', 'features': pref_feats}, open(pref_out, 'w', encoding='utf-8'))

# 3) admin2 (non-CHN z5..max_zoom + CHN districts z7..max_zoom)
forbid_chn_a2 = a1_segs_p5 | pref_segs_p5
a2_feats = []
a2_cc_counts = Counter()
a2_suppressed = 0

def ingest_admin2(src_path, forbid_set, min_zoom, prec=3):
    global a2_suppressed
    data = json.load(open(src_path, encoding='utf-8'))
    for f in data['features']:
        g = f.get('geometry')
        if not g:
            continue
        cc = str((f.get('properties') or {}).get('cc') or '').strip().upper()
        lines = [g['coordinates']] if g['type'] == 'LineString' else (
            g['coordinates'] if g['type'] == 'MultiLineString' else []
        )
        kept = []
        for line in lines:
            runs, s = strip_coincident(line, forbid_set, prec)
            a2_suppressed += s
            kept.extend(runs)
        if not kept:
            continue
        props = {'cc': cc}
        if cc in a3_to_a2:
            props['iso_a2'] = a3_to_a2[cc]
        geom = {'type': 'LineString', 'coordinates': kept[0]} if len(kept) == 1 else {
            'type': 'MultiLineString', 'coordinates': kept
        }
        a2_cc_counts[cc] += 1
        a2_feats.append({
            'type': 'Feature',
            'tippecanoe': {'minzoom': min_zoom, 'maxzoom': max_zoom},
            'geometry': geom,
            'properties': props,
        })

ingest_admin2(a2_other_in, a1_segs_p3, 5, prec=3)
ingest_admin2(a2_chn_in, forbid_chn_a2, 7, prec=5)

json.dump({'type': 'FeatureCollection', 'features': a2_feats}, open(a2_out, 'w', encoding='utf-8'))

ac6 = ('CHN', 'USA', 'IND', 'DEU', 'BRA', 'JPN', 'AUS', 'RUS', 'ZAF', 'TWN')
print(f"  admin1:      {len(a1_feats)} features across {len(a1_cc_counts)} units; AC6={ {k: a1_cc_counts[k] for k in ac6} }")
print(f"  admin2_pref: {len(pref_feats)} CHN prefecture lines (suppressed {pref_suppressed} ADM1-coincident segs)")
print(f"  admin2:      {len(a2_feats)} features across {len(a2_cc_counts)} units (suppressed {a2_suppressed} coincident segs); AC6={ {k: a2_cc_counts[k] for k in ac6} }")
assert len(pref_feats) >= 500, f"expected >= 500 China prefecture lines, got {len(pref_feats)}"
for k in ac6:
    assert a1_cc_counts[k] > 0, f"AC6 country {k} missing from admin1"
    assert a2_cc_counts[k] > 0, f"AC6 country {k} missing from admin2"
PY

echo "[6/8] Building label point layers (admin0, admin1, place) with neutral region overrides (TWN/HKG/MAC)..."
python3 - \
  "$SRC_DIR/ne_10m_admin_0_countries.geojson" \
  "$SRC_DIR/ne_10m_admin_1_states_provinces.geojson" \
  "$SRC_DIR/ne_10m_populated_places.geojson" \
  "$STAGE_DIR/label_admin0.geojson" \
  "$STAGE_DIR/label_admin1.geojson" \
  "$STAGE_DIR/label_place.geojson" <<'PY'
import json, sys

a0_in, a1_in, pp_in, a0_out, a1_out, pp_out = sys.argv[1:7]

OVERRIDES = {
    'TWN': ('台湾', 'Taiwan'),
    'HKG': ('香港', 'Hong Kong'),
    'MAC': ('澳门', 'Macau'),
}

SHORT_A0 = {
    'CHN': ('中国', 'China'),
    'USA': ('美国', 'United States'),
    'GBR': ('英国', 'United Kingdom'),
    'KOR': ('韩国', 'South Korea'),
    'PRK': ('朝鲜', 'North Korea'),
    'ARE': ('阿联酋', 'United Arab Emirates'),
    'TWN': ('台湾', 'Taiwan'),
    'HKG': ('香港', 'Hong Kong'),
    'MAC': ('澳门', 'Macau'),
}

TRAD_TO_SIMP = str.maketrans({
    '臺': '台', '灣': '湾', '門': '门', '東': '东', '廣': '广', '爾': '尔',
    '蘇': '苏', '慶': '庆', '漢': '汉', '陽': '阳', '長': '长', '鄭': '郑',
    '濟': '济', '連': '连', '瀋': '沈', '濱': '滨', '寧': '宁', '廈': '厦',
    '貴': '贵', '蘭': '兰', '烏': '乌', '魯': '鲁', '齊': '齐', '薩': '萨',
    '陝': '陕', '遼': '辽', '龍': '龙', '華': '华', '國': '国', '區': '区',
    '縣': '县', '島': '岛', '嶺': '岭', '紐': '纽', '約': '约', '舊': '旧',
    '倫': '伦', '聖': '圣', '羅': '罗', '維': '维', '馬': '马', '亞': '亚',
    '開': '开', '達': '达', '岡': '冈', '買': '买', '來': '来', '溫': '温',
    '頓': '顿', '鳳': '凤', '茲': '兹', '圖': '图', '葉': '叶', '庫': '库',
    '澤': '泽', '韓': '韩', '鮮': '鲜', '歐': '欧', '愛': '爱', '聯': '联',
})

def clean_zh(s: str) -> str:
    if not s:
        return ''
    return s.translate(TRAD_TO_SIMP).strip()

def pick_iso2(p: dict) -> str:
    for k in ('ISO_A2', 'iso_a2', 'ISO_A2_EH'):
        v = str(p.get(k) or '').strip().upper()
        if len(v) == 2 and v.isalpha():
            return v
    return ''

a3_to_a2 = {'TWN': 'TW', 'HKG': 'HK', 'MAC': 'MO', 'FRA': 'FR', 'NOR': 'NO', 'KOS': 'XK', 'XKX': 'XK'}

# label_admin0
a0 = json.load(open(a0_in, encoding='utf-8'))
feats_a0 = []
for f in a0['features']:
    p = f.get('properties') or {}
    lx, ly = p.get('LABEL_X'), p.get('LABEL_Y')
    if lx is None or ly is None:
        continue
    code = str(p.get('ADM0_A3') or p.get('ISO_A3') or '').strip().upper()
    iso2 = a3_to_a2.get(code) or pick_iso2(p)
    if code and iso2:
        a3_to_a2.setdefault(code, iso2)
    name_en = str(p.get('NAME') or p.get('NAME_EN') or '').strip()
    name_zh = clean_zh(p.get('NAME_ZH') or name_en)
    props = {
        'code': code,
        'iso_a2': iso2,
        'name_en': SHORT_A0[code][1] if code in SHORT_A0 else name_en,
        'name_zh': SHORT_A0[code][0] if code in SHORT_A0 else name_zh,
        'min_label': float(p.get('MIN_LABEL') or 2.0),
        'max_label': float(p.get('MAX_LABEL') or 7.0),
        'labelrank': int(p.get('LABELRANK') if p.get('LABELRANK') is not None else 6),
        'scalerank': int(p.get('scalerank') if p.get('scalerank') is not None else 3),
        'pop': int(p.get('POP_EST') or 0),
    }
    if code in OVERRIDES:
        props['name_zh_override'] = OVERRIDES[code][0]
        props['name_en_override'] = OVERRIDES[code][1]
    feats_a0.append({
        'type': 'Feature',
        'geometry': {'type': 'Point', 'coordinates': [float(lx), float(ly)]},
        'properties': props,
    })
json.dump({'type': 'FeatureCollection', 'features': feats_a0}, open(a0_out, 'w', encoding='utf-8'))

# label_admin1
a1 = json.load(open(a1_in, encoding='utf-8'))
feats_a1 = []
for f in a1['features']:
    p = f.get('properties') or {}
    lon, lat = p.get('longitude'), p.get('latitude')
    if lon is None or lat is None:
        continue
    name_en = str(p.get('name_en') or p.get('name') or '').strip()
    name_zh = clean_zh(p.get('name_zh') or name_en)
    if not name_en and not name_zh:
        continue
    code = str(p.get('adm0_a3') or '').strip().upper()
    iso2 = a3_to_a2.get(code) or pick_iso2(p)
    feats_a1.append({
        'type': 'Feature',
        'geometry': {'type': 'Point', 'coordinates': [float(lon), float(lat)]},
        'properties': {
            'cc': code,
            'iso_a2': iso2,
            'name_en': name_en or name_zh,
            'name_zh': name_zh or name_en,
            'min_label': float(p.get('min_label') or 5.0),
            'scalerank': int(p.get('scalerank') if p.get('scalerank') is not None else 6),
        },
    })
json.dump({'type': 'FeatureCollection', 'features': feats_a1}, open(a1_out, 'w', encoding='utf-8'))

# label_place
pp = json.load(open(pp_in, encoding='utf-8'))
feats_pp = []
for f in pp['features']:
    p = f.get('properties') or {}
    g = f.get('geometry')
    if not g or g.get('type') != 'Point':
        continue
    min_z = float(p.get('MIN_ZOOM') if p.get('MIN_ZOOM') is not None else 7.0)
    if min_z > 8.5:
        continue
    name_en = str(p.get('NAME_EN') or p.get('NAME') or '').strip()
    name_zh = clean_zh(p.get('NAME_ZH') or name_en)
    if not name_en and not name_zh:
        continue
    code = str(p.get('ADM0_A3') or '').strip().upper()
    iso2 = a3_to_a2.get(code) or pick_iso2(p)
    feats_pp.append({
        'type': 'Feature',
        'geometry': g,
        'properties': {
            'cc': code,
            'iso_a2': iso2,
            'name_en': name_en or name_zh,
            'name_zh': name_zh or name_en,
            'min_zoom': min_z,
            'scalerank': int(p.get('SCALERANK') if p.get('SCALERANK') is not None else 8),
            'pop': int(p.get('POP_MAX') or 0),
        },
    })
json.dump({'type': 'FeatureCollection', 'features': feats_pp}, open(pp_out, 'w', encoding='utf-8'))
print(f"  labels: admin0={len(feats_a0)}, admin1={len(feats_a1)}, place={len(feats_pp)}")
PY

if [ "${GLOBE_SKIP_GAZETTEER:-0}" != "1" ]; then
  echo "[7/8] Generating lazy gazetteer ($GAZETTEER_OUT)..."
  python3 "$SCRIPT_DIR/build-gazetteer.py" \
    --sources-dir "$SRC_DIR" \
    --output "$GAZETTEER_OUT"
else
  echo "[7/8] Skipping gazetteer generation (GLOBE_SKIP_GAZETTEER=1)"
fi

echo "[8/8] Tiling layers with tippecanoe & joining into $OUT_FILE (maxzoom=$MAX_ZOOM)..."
COMMON_FLAGS=(--force --no-feature-limit --no-tile-size-limit --detect-shared-borders)

# Run from WORK_DIR with relative paths so host paths never leak into PMTiles metadata
(
  cd "$WORK_DIR"
  tippecanoe "${COMMON_FLAGS[@]}" -Z0 -z2 -l land_low    -o tiles/land_low.pmtiles    stage/land_low.geojson
  tippecanoe "${COMMON_FLAGS[@]}" -Z3 -z"$MAX_ZOOM" -l land_high   -o tiles/land_high.pmtiles   stage/land_high.geojson
  tippecanoe "${COMMON_FLAGS[@]}" -Z0 -z2 -l coast_low   -o tiles/coast_low.pmtiles   stage/coast_low.geojson
  tippecanoe "${COMMON_FLAGS[@]}" -Z3 -z"$MAX_ZOOM" -l coast_high  -o tiles/coast_high.pmtiles  stage/coast_high.geojson
  tippecanoe "${COMMON_FLAGS[@]}" -Z0 -z"$MAX_ZOOM" -l admin0      -o tiles/admin0.pmtiles      stage/admin0.geojson
  tippecanoe "${COMMON_FLAGS[@]}" --simplify-only-low-zooms -Z2 -z"$MAX_ZOOM" -l admin1      -o tiles/admin1.pmtiles      stage/admin1.geojson
  tippecanoe "${COMMON_FLAGS[@]}" --simplify-only-low-zooms -Z5 -z"$MAX_ZOOM" -l admin2_pref -o tiles/admin2_pref.pmtiles stage/admin2_pref.geojson
  tippecanoe "${COMMON_FLAGS[@]}" --simplify-only-low-zooms -Z5 -z"$MAX_ZOOM" -l admin2      -o tiles/admin2.pmtiles      stage/admin2.geojson
  tippecanoe --force --no-feature-limit --no-tile-size-limit -r1 -Z0 -z"$MAX_ZOOM" -l label_admin0 -o tiles/label_admin0.pmtiles stage/label_admin0.geojson
  tippecanoe --force --no-feature-limit --no-tile-size-limit -r1 -Z3 -z"$MAX_ZOOM" -l label_admin1 -o tiles/label_admin1.pmtiles stage/label_admin1.geojson
  tippecanoe --force --no-feature-limit --no-tile-size-limit -r1 -Z3 -z"$MAX_ZOOM" -l label_place  -o tiles/label_place.pmtiles  stage/label_place.geojson
  tippecanoe --force --no-feature-limit --no-tile-size-limit -r1 -Z8 -z"$MAX_ZOOM" -l label_admin2 -o tiles/label_admin2.pmtiles stage/label_admin2.geojson

  tile-join --force --no-tile-size-limit \
    -n "mh-boundaries-v1" \
    -N "MeshHarbor Neutral De Facto Boundaries (Natural Earth 5.1.2 + geoBoundaries CC BY 4.0 + OpenStreetMap ODbL + UN OCHA CC BY-IGO)" \
    -o tiles/mh-boundaries-v1.pmtiles \
    tiles/land_low.pmtiles \
    tiles/land_high.pmtiles \
    tiles/coast_low.pmtiles \
    tiles/coast_high.pmtiles \
    tiles/admin0.pmtiles \
    tiles/admin1.pmtiles \
    tiles/admin2_pref.pmtiles \
    tiles/admin2.pmtiles \
    tiles/label_admin0.pmtiles \
    tiles/label_admin1.pmtiles \
    tiles/label_place.pmtiles \
    tiles/label_admin2.pmtiles
)

cp -f "$TILES_DIR/mh-boundaries-v1.pmtiles" "$OUT_FILE"

SHA="$(sha256sum "$OUT_FILE" | awk '{print $1}')"
SIZE="$(stat -c%s "$OUT_FILE")"
if [ "$SIZE" -gt "$MAX_PMTILES_BYTES" ]; then
  echo "error: $OUT_FILE size $SIZE bytes exceeds budget $MAX_PMTILES_BYTES bytes" >&2
  exit 1
fi
printf "%s  %s\n" "$SHA" "$(basename "$OUT_FILE")" > "${OUT_FILE}.sha256"
echo "Built $OUT_FILE ($SIZE bytes, sha256=$SHA)"
