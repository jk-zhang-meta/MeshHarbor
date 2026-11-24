#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 G ROX EOOD
#
# Reproducibly build ui/public/geo/mh-boundaries-v1.pmtiles from pinned
# Natural Earth 5.1.2 (public domain) + geoBoundaries CGAZ ADM2 (CC BY 4.0)
# sources listed in scripts/globe/SOURCES.lock.
#
# Policy (FR-136 S1/S6):
# - Admin-0 de facto boundary lines come ONLY from Natural Earth
#   (disputed segments flagged cls="disputed" for dashed [3,2], limits
#   cls="limit" for dotted [0,2]; claim lines are NEVER included).
# - Admin-1 internal shared lines come from NE 10m admin-1 (incl. HK/MO),
#   clipped to NE world land mask so no country line is duplicated.
# - Admin-2 (P0 sample: China CHN) uses geoBoundaries CGAZ internal shared
#   lines ONLY (`-split shapeGroup -innerlines`, clipped to NE world mask;
#   NEVER takes international borders from CGAZ).
# - Neutral region overrides: TWN -> 台湾/Taiwan, HKG -> 香港/Hong Kong,
#   MAC -> 澳门/Macau.
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
MAX_ZOOM="${GLOBE_MAX_ZOOM:-6}"

MAPSHAPER_BIN="${MAPSHAPER_BIN:-$(command -v mapshaper || true)}"
if [ -z "$MAPSHAPER_BIN" ]; then
  echo "error: mapshaper not found (set MAPSHAPER_BIN or add to PATH)" >&2
  exit 1
fi
for bin in curl python3 ogr2ogr tippecanoe tile-join sha256sum unzip; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "error: required build tool '$bin' not found in PATH" >&2
    exit 1
  fi
done

mkdir -p "$SRC_DIR" "$STAGE_DIR" "$TILES_DIR" "$(dirname "$OUT_FILE")"

echo "[1/6] Fetching & verifying pinned sources from SOURCES.lock..."
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

echo "[2/6] Building NE land, coastline, world clip mask, and admin-0 de facto lines..."
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

python3 - "$SRC_DIR/ne_10m_admin_0_boundary_lines_land.geojson" "$STAGE_DIR/admin0.geojson" <<'PY'
import json, sys

src, dst = sys.argv[1], sys.argv[2]
data = json.load(open(src, encoding='utf-8'))
out_feats = []

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
    out_feats.append({
        'type': 'Feature',
        'geometry': f['geometry'],
        'properties': {
            'cls': cls,
            'min_zoom': float(p.get('MIN_ZOOM') or 0),
        },
    })

json.dump({'type': 'FeatureCollection', 'features': out_feats}, open(dst, 'w', encoding='utf-8'))
print(f"  admin0 lines: {len(out_feats)} features")
PY

echo "[3/6] Building NE admin-1 internal shared lines (incl. HK/MO) clipped to NE world mask..."
"$MAPSHAPER_BIN" -i "$SRC_DIR/ne_10m_admin_1_states_provinces.geojson" \
  -simplify 12% weighted keep-shapes \
  -split adm0_a3 \
  -innerlines \
  -merge-layers target=* force \
  -clip "$STAGE_DIR/world_mask.geojson" \
  -filter-fields "" \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/admin1.geojson"

echo "[4/6] Building geoBoundaries CGAZ China (CHN) ADM2 internal shared lines ONLY..."
CGAZ_DIR="$WORK_DIR/cgaz_adm2"
mkdir -p "$CGAZ_DIR"
if [ ! -s "$CGAZ_DIR/geoBoundariesCGAZ_ADM2.shp" ]; then
  unzip -q -o "$SRC_DIR/geoBoundariesCGAZ_ADM2.zip" -d "$CGAZ_DIR"
fi
rm -f "$STAGE_DIR/chn_adm2_poly.geojson"
ogr2ogr -f GeoJSON -where "shapeGroup='CHN'" \
  "$STAGE_DIR/chn_adm2_poly.geojson" \
  "$CGAZ_DIR/geoBoundariesCGAZ_ADM2.shp"

"$MAPSHAPER_BIN" -i "$STAGE_DIR/chn_adm2_poly.geojson" \
  -simplify 8% weighted keep-shapes \
  -split shapeGroup \
  -innerlines \
  -merge-layers target=* force \
  -clip "$STAGE_DIR/world_mask.geojson" \
  -each 'cc="CHN"' \
  -filter-fields cc \
  -o format=geojson geojson-type=FeatureCollection "$STAGE_DIR/admin2.geojson"

echo "[5/6] Building label point layers with neutral region overrides (TWN/HKG/MAC)..."
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
}

TRAD_TO_SIMP = {
    '臺北': '台北',
    '澳門': '澳门',
    '東京': '东京',
    '首爾': '首尔',
    '臺灣': '台湾',
    '廣東': '广东',
}

def clean_zh(s: str) -> str:
    if not s:
        return ''
    for k, v in TRAD_TO_SIMP.items():
        s = s.replace(k, v)
    return s.strip()

# label_admin0
a0 = json.load(open(a0_in, encoding='utf-8'))
feats_a0 = []
for f in a0['features']:
    p = f.get('properties') or {}
    lx, ly = p.get('LABEL_X'), p.get('LABEL_Y')
    if lx is None or ly is None:
        continue
    code = (p.get('ADM0_A3') or p.get('ISO_A3') or '').strip().upper()
    name_en = (p.get('NAME') or p.get('NAME_EN') or '').strip()
    name_zh = clean_zh(p.get('NAME_ZH') or name_en)
    props = {
        'code': code,
        'name_en': SHORT_A0[code][1] if code in SHORT_A0 else name_en,
        'name_zh': SHORT_A0[code][0] if code in SHORT_A0 else name_zh,
        'min_label': float(p.get('MIN_LABEL') or 2.0),
        'max_label': float(p.get('MAX_LABEL') or 7.0),
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
    name_en = (p.get('name_en') or p.get('name') or '').strip()
    name_zh = clean_zh(p.get('name_zh') or name_en)
    if not name_en and not name_zh:
        continue
    code = (p.get('adm0_a3') or '').strip().upper()
    feats_a1.append({
        'type': 'Feature',
        'geometry': {'type': 'Point', 'coordinates': [float(lon), float(lat)]},
        'properties': {
            'cc': code,
            'name_en': name_en or name_zh,
            'name_zh': name_zh or name_en,
            'min_label': float(p.get('min_label') or 5.0),
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
    min_z = float(p.get('MIN_ZOOM') or 7.0)
    # P0 z0..z6 focus: keep cities visible by z7+ overzoom
    if min_z > 7.5:
        continue
    name_en = (p.get('NAME_EN') or p.get('NAME') or '').strip()
    name_zh = clean_zh(p.get('NAME_ZH') or name_en)
    if not name_en and not name_zh:
        continue
    code = (p.get('ADM0_A3') or '').strip().upper()
    props = {
        'cc': code,
        'name_en': name_en or name_zh,
        'name_zh': name_zh or name_en,
        'min_zoom': min_z,
        'pop': int(p.get('POP_MAX') or 0),
    }
    feats_pp.append({
        'type': 'Feature',
        'geometry': g,
        'properties': props,
    })
json.dump({'type': 'FeatureCollection', 'features': feats_pp}, open(pp_out, 'w', encoding='utf-8'))
print(f"  labels: admin0={len(feats_a0)}, admin1={len(feats_a1)}, place={len(feats_pp)}")
PY

echo "[6/6] Tiling layers with tippecanoe & joining into $OUT_FILE (maxzoom=$MAX_ZOOM)..."
COMMON_FLAGS=(--force --no-feature-limit --no-tile-size-limit --detect-shared-borders)

tippecanoe "${COMMON_FLAGS[@]}" -Z0 -z2 -l land_low  -o "$TILES_DIR/land_low.pmtiles"  "$STAGE_DIR/land_low.geojson"
tippecanoe "${COMMON_FLAGS[@]}" -Z3 -z"$MAX_ZOOM" -l land_high -o "$TILES_DIR/land_high.pmtiles" "$STAGE_DIR/land_high.geojson"
tippecanoe "${COMMON_FLAGS[@]}" -Z0 -z2 -l coast_low  -o "$TILES_DIR/coast_low.pmtiles"  "$STAGE_DIR/coast_low.geojson"
tippecanoe "${COMMON_FLAGS[@]}" -Z3 -z"$MAX_ZOOM" -l coast_high -o "$TILES_DIR/coast_high.pmtiles" "$STAGE_DIR/coast_high.geojson"
tippecanoe "${COMMON_FLAGS[@]}" -Z0 -z"$MAX_ZOOM" -l admin0 -o "$TILES_DIR/admin0.pmtiles" "$STAGE_DIR/admin0.geojson"
tippecanoe "${COMMON_FLAGS[@]}" -Z2 -z"$MAX_ZOOM" -l admin1 -o "$TILES_DIR/admin1.pmtiles" "$STAGE_DIR/admin1.geojson"
tippecanoe "${COMMON_FLAGS[@]}" -Z5 -z"$MAX_ZOOM" -l admin2 -o "$TILES_DIR/admin2.pmtiles" "$STAGE_DIR/admin2.geojson"
tippecanoe --force --no-feature-limit --no-tile-size-limit -r1 -Z0 -z"$MAX_ZOOM" -l label_admin0 -o "$TILES_DIR/label_admin0.pmtiles" "$STAGE_DIR/label_admin0.geojson"
tippecanoe --force --no-feature-limit --no-tile-size-limit -r1 -Z3 -z"$MAX_ZOOM" -l label_admin1 -o "$TILES_DIR/label_admin1.pmtiles" "$STAGE_DIR/label_admin1.geojson"
tippecanoe --force --no-feature-limit --no-tile-size-limit -r1 -Z3 -z"$MAX_ZOOM" -l label_place  -o "$TILES_DIR/label_place.pmtiles"  "$STAGE_DIR/label_place.geojson"

tile-join --force --no-tile-size-limit \
  -n "mh-boundaries-v1" \
  -N "MeshHarbor Neutral De Facto Boundaries (Natural Earth 5.1.2 + geoBoundaries CGAZ CHN ADM2)" \
  -o "$OUT_FILE" \
  "$TILES_DIR/land_low.pmtiles" \
  "$TILES_DIR/land_high.pmtiles" \
  "$TILES_DIR/coast_low.pmtiles" \
  "$TILES_DIR/coast_high.pmtiles" \
  "$TILES_DIR/admin0.pmtiles" \
  "$TILES_DIR/admin1.pmtiles" \
  "$TILES_DIR/admin2.pmtiles" \
  "$TILES_DIR/label_admin0.pmtiles" \
  "$TILES_DIR/label_admin1.pmtiles" \
  "$TILES_DIR/label_place.pmtiles"

SHA="$(sha256sum "$OUT_FILE" | awk '{print $1}')"
SIZE="$(stat -c%s "$OUT_FILE")"
printf "%s  %s\n" "$SHA" "$(basename "$OUT_FILE")" > "${OUT_FILE}.sha256"
echo "Built $OUT_FILE ($SIZE bytes, sha256=$SHA)"
