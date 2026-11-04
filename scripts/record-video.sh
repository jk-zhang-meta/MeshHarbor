#!/bin/bash
# Record and convert the MeshHarbor intro video
#
# Prerequisites:
#   - API running (cargo run) at port 5001
#   - Frontend running (cd ui && bun run dev) proxied at port 5000
#   - Playwright installed (cd ui && bun install && bunx playwright install chromium)
#   - ffmpeg installed (for MP4 conversion + music mixing)
#   - Node.js v22+ via fnm (Playwright requires real Node, not bun's wrapper)
#
# Usage:
#   ./scripts/record-video.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
UI_DIR="$PROJECT_DIR/ui"
OUTPUT_DIR="$UI_DIR/e2e/video/output"
ASSETS_DIR="$UI_DIR/e2e/video/assets"
MUSIC_FILE="$ASSETS_DIR/bg-music.mp3"

# Use real Node.js via fnm (not bun's wrapper) for Playwright compatibility
if [ -d "$HOME/.local/share/fnm" ]; then
  export PATH="$HOME/.local/share/fnm:$PATH"
  eval "$(fnm env)"
  fnm use --install-if-missing lts 2>/dev/null || fnm use default 2>/dev/null
fi

echo "=== MeshHarbor Intro Video Recording ==="
echo "Node: $(which node) ($(node -e 'console.log(process.version)'))"
echo ""

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Run the Playwright recording (test saves WebM to output dir automatically)
echo "[1/3] Recording video with Playwright..."
cd "$UI_DIR"
E2E_BASE_URL="${E2E_BASE_URL:-http://localhost:5000}" E2E_API_URL="${E2E_API_URL:-http://localhost:5001}" node ./node_modules/.bin/playwright test \
  e2e/video/record-intro.spec.ts \
  --config=playwright.video.config.ts \
  --reporter=list 2>&1 || true

# Check for the saved WebM
WEBM_FILE="$OUTPUT_DIR/meshharbor-intro.webm"

if [ ! -f "$WEBM_FILE" ]; then
  echo "ERROR: No video file found at $WEBM_FILE"
  echo "Check that the test ran successfully and video recording is enabled."
  exit 1
fi

echo "Found recording: $WEBM_FILE ($(du -h "$WEBM_FILE" | cut -f1))"

# Convert to MP4 with ffmpeg, optionally mixing in background music
MP4_FILE="$OUTPUT_DIR/meshharbor-intro.mp4"

if command -v ffmpeg &>/dev/null; then
  if [ -f "$MUSIC_FILE" ]; then
    echo "[2/3] Converting to MP4 with background music..."

    # Get video duration in seconds for music fade-out
    DURATION=$(ffprobe -v error -show_entries format=duration \
      -of default=noprint_wrappers=1:nokey=1 "$WEBM_FILE" 2>/dev/null | cut -d. -f1)
    FADE_START=$((DURATION - 3))
    if [ "$FADE_START" -lt 0 ]; then
      FADE_START=0
    fi

    ffmpeg -y -i "$WEBM_FILE" -stream_loop -1 -i "$MUSIC_FILE" \
      -c:v libx264 \
      -preset slow \
      -crf 18 \
      -pix_fmt yuv420p \
      -filter_complex "[1:a]volume=0.15,afade=t=in:st=0:d=2,afade=t=out:st=${FADE_START}:d=3[music]" \
      -map 0:v -map "[music]" \
      -shortest \
      -movflags +faststart \
      "$MP4_FILE" 2>/dev/null

    echo "[3/3] Done!"
    echo ""
    echo "=== Output ==="
    echo "WebM: $WEBM_FILE"
    echo "MP4:  $MP4_FILE ($(du -h "$MP4_FILE" | cut -f1))"
    echo "Music: $MUSIC_FILE (mixed at 15% volume with fade in/out)"
  else
    echo "[2/3] Converting to MP4 (no music file found)..."
    echo "  To add background music, place an MP3 at: $MUSIC_FILE"

    ffmpeg -y -i "$WEBM_FILE" \
      -c:v libx264 \
      -preset slow \
      -crf 18 \
      -pix_fmt yuv420p \
      -movflags +faststart \
      "$MP4_FILE" 2>/dev/null

    echo "[3/3] Done!"
    echo ""
    echo "=== Output ==="
    echo "WebM: $WEBM_FILE"
    echo "MP4:  $MP4_FILE ($(du -h "$MP4_FILE" | cut -f1))"
  fi

  echo ""
  echo "Upload to YouTube, then update README.md with the video link."
else
  echo "[2/3] ffmpeg not found — skipping MP4 conversion."
  echo ""
  echo "=== Done ==="
  echo "WebM: $WEBM_FILE"
  echo ""
  echo "To convert manually:"
  echo "  ffmpeg -i \"$WEBM_FILE\" -c:v libx264 -crf 18 -pix_fmt yuv420p \"$MP4_FILE\""
fi
