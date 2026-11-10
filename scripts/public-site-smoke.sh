#!/usr/bin/env bash
#
# public-site-smoke.sh — assert how the public site is SERVED (FR-87, #1776).
#
#   scripts/public-site-smoke.sh <base-url> [<repo-dir> [<git-rev>]]
#   scripts/public-site-smoke.sh http://localhost:8080 .           # the hosted-image smoke
#   scripts/public-site-smoke.sh https://meshharbor.itachi.fans . <deployed-sha> # production, after a roll
#   scripts/public-site-smoke.sh --blog https://meshharbor.itachi.fans           # the blog lane (FR-91),
#                                                                    # after every publish
#
#   With <repo-dir> (a clone with FULL history), every docs page's sitemap
#   <lastmod> is also compared with `git log -1 --format=%cs` for its file at
#   <git-rev> (default HEAD) — the deployed commit, when checking production.
#
# WHY THIS EXISTS
#   The static site (docs, blog, the homepage) is where search engines meet
#   meshharbor.itachi.fans, and every defect FR-87 fixes was invisible from inside the build:
#     - `/docs` redirected to `http://` (a scheme downgrade);
#     - unknown paths answered 200 with the SPA shell (soft 404s);
#     - `/docs/x` and `/docs/x/` both answered 200 (duplicate URLs);
#     - a single `add_header` in an nginx location silently drops every
#       security header for that location — the one mistake that looks like a
#       harmless cache tweak in review;
#     - every page's <lastmod> was the build date, because production builds
#       have no git history (P2);
#     - docs.css and search.js were served `immutable` for a year under names
#       that never changed (P2).
#   This script checks the SERVED behaviour, so it runs against a real nginx:
#   the image in CI, production after every promote.
#
# Exit 0 = every check passed. Exit 1 = at least one failed (each is printed).
# Exit 2 = usage error.

set -u

# FR-91 (#1880): `--blog <base-url> [<docs-base-url>]` checks the blog lane —
# the `meshharbor-blog` server that `bun docs/build.ts --blog-only` feeds — instead
# of the whole site. In production both arguments are https://meshharbor.itachi.fans (the
# edge routes /blog/ to the lane and /docs/ to the pod); against two local
# servers, the second names the one that serves /docs/.
BLOG_MODE=0
if [ "${1:-}" = "--blog" ]; then
  BLOG_MODE=1
  shift
fi

BASE="${1:-}"
[ -n "$BASE" ] || { echo "usage: $0 <base-url> [<repo-dir> [<git-rev>]]  |  $0 --blog <base-url> [<docs-base-url>]" >&2; exit 2; }
BASE="${BASE%/}"
REPO="${2:-}"
REV="${3:-HEAD}"

FAIL=0
ok()   { printf '  \342\234\223 %s\n' "$1"; }
bad()  { printf '  \342\234\227 %s\n' "$1"; FAIL=1; }

# HEAD request → headers, lower-cased names, CR stripped. `-k` so a local
# self-signed front works; production is real TLS anyway.
headers() { curl -ksS -m 15 -I "$1" 2>/dev/null | tr -d '\r' | sed -E 's/^([A-Za-z0-9-]+):/\L\1:/'; }
status()  { curl -ksS -m 15 -o /dev/null -w '%{http_code}' "$1" 2>/dev/null; }
header()  { headers "$1" | grep -i "^$2:" | head -1 | sed -E 's/^[^:]+:[[:space:]]*//'; }
# A redirect's status and its Location, from ONE response: "<code> <location>".
# Read by two requests, a blip on the second reported "301 with no Location"
# against production, twice on 2026-09-29: the check failing, not the site.
# A failed request is "000", which says what happened.
redirect() {
  local h code loc
  h="$(headers "$1")"
  code="$(printf '%s\n' "$h" | awk '$1 ~ /^HTTP\// { c = $2 } END { print c }')"
  loc="$(printf '%s\n' "$h" | grep -i '^location:' | head -1 | sed -E 's/^[^:]+:[[:space:]]*//')"
  printf '%s %s\n' "${code:-000}" "$loc"
}

# The security headers every HTML page must carry exactly as `/` does. Sorted
# so the comparison is order-independent; values compared verbatim.
SEC='content-security-policy|strict-transport-security|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|x-xss-protection'
secset() { headers "$1" | grep -Ei "^($SEC):" | sort; }

# ── FR-91: the blog lane ────────────────────────────────────────────────────
# What a publisher runs after every publish, against the SERVED site: the lane
# must be the blog FR-87 built — same headers, same caching, same URLs, real
# 404s — and must load nothing from the image's /docs/assets/, whose hashed
# names change with every image the lane does not follow.
if [ "$BLOG_MODE" = "1" ]; then
  DOCS_BASE="${2:-$BASE}"
  DOCS_BASE="${DOCS_BASE%/}"
  echo "public-site smoke (blog lane) against $BASE, docs at $DOCS_BASE"

  code="$(status "$BASE/blog/")"
  [ "$code" = "200" ] && ok "/blog/ -> 200" || bad "/blog/ -> $code (want 200)"

  read -r code loc <<< "$(redirect "$BASE/blog")"
  if [ "$code" = "301" ] && [ "$loc" = "/blog/" ]; then
    ok "/blog -> 301 Location: $loc (relative, slash form)"
  else
    bad "/blog -> $code Location: '${loc:-none}' (want 301 to '/blog/', relative)"
  fi

  sm="$(curl -ksS -m 15 "$BASE/sitemap-blog.xml" 2>/dev/null | tr -d '\r')"
  if printf '%s' "$sm" | grep -q '<urlset' && printf '%s' "$sm" | grep -q '/blog/</loc>'; then
    ok "/sitemap-blog.xml is a urlset naming /blog/"
  else
    bad "/sitemap-blog.xml is not the blog's urlset"
  fi
  # A post to look at: the first one the sitemap names.
  post="$(printf '%s\n' "$sm" | grep -oE '<loc>[^<]+/blog/[^<]+/</loc>' | head -1 | sed -E 's#</?loc>##g; s#^https?://[^/]+##')"
  if [ -z "$post" ]; then
    bad "/sitemap-blog.xml names no post"
  else
    html="$(curl -ksS -m 15 "$BASE$post" 2>/dev/null)"
    if [ "$(status "$BASE$post")" = "200" ] && printf '%s' "$html" | grep -q "<link rel=\"canonical\" href=\"https://meshharbor.itachi.fans$post\">" \
       && printf '%s' "$html" | grep -q '"@type":"BlogPosting"'; then
      ok "$post -> 200, its own canonical, BlogPosting JSON-LD"
    else
      bad "$post -> not a published post (status, canonical or BlogPosting missing)"
    fi
  fi

  ct="$(header "$BASE/blog/feed.xml" content-type)"
  case "$ct" in
    application/atom+xml*) ok "/blog/feed.xml Content-Type: $ct" ;;
    *) bad "/blog/feed.xml Content-Type: '${ct:-none}' (want application/atom+xml)" ;;
  esac

  path=/blog/fr91-smoke-missing/
  code="$(status "$BASE$path")"
  if [ "$code" != "404" ]; then
    bad "$path -> $code (want 404; a 200 here is a soft 404)"
  elif curl -ksS -m 15 "$BASE$path" 2>/dev/null | grep -q '<h1 class="page-title">Page not found'; then
    ok "$path -> 404, the site's 404 page"
  else
    bad "$path -> 404, but not the site's 404 page (is blog/404.html missing?)"
  fi

  for p in /blog/ ${post:-}; do
    cc="$(header "$BASE$p" cache-control)"
    case "$cc" in
      *no-cache*) ok "$p Cache-Control: $cc" ;;
      *) bad "$p Cache-Control: '${cc:-none}' (want no-cache)" ;;
    esac
  done

  # The security headers, byte for byte as the docs send them: one include
  # (files/security-headers.conf) on two servers can still drift if either
  # server stops including it or a location declares an `add_header`.
  DOCS_SET="$(secset "$DOCS_BASE/docs/")"
  if [ -z "$DOCS_SET" ]; then
    bad "$DOCS_BASE/docs/ carries none of the security headers — cannot compare"
  else
    for p in /blog/ ${post:-} /blog/feed.xml; do
      got="$(secset "$BASE$p")"
      if [ "$got" = "$DOCS_SET" ]; then
        ok "$p security headers == /docs/ ($(printf '%s\n' "$got" | wc -l | tr -d ' ') headers)"
      else
        bad "$p security headers differ from /docs/:"
        diff <(printf '%s\n' "$DOCS_SET") <(printf '%s\n' "$got") | sed 's/^/      /'
      fi
    done
  fi

  # Every asset the lane's pages load is its own, content-hashed and loading.
  for p in /blog/ ${post:-}; do
    html="$(curl -ksS -m 20 "$BASE$p" 2>/dev/null)"
    foreign="$(printf '%s' "$html" | grep -oE '(href|src|data-search-index)="/docs/assets/[^"]+"' | head -3 | tr '\n' ' ')"
    refs="$(printf '%s' "$html" | grep -oE '(href|src|data-search-index)="/blog/assets/[^"]+"' | sed -E 's/^[^"]+"//; s/"$//' | sort -u)"
    n="$(printf '%s\n' "$refs" | grep -c .)"
    plain="$(printf '%s\n' "$refs" | grep -vE '\.[0-9a-f]{10}\.[a-z0-9]+$' | grep . | tr '\n' ' ')"
    missing=""
    for r in $refs; do [ "$(status "$BASE$r")" = "200" ] || missing="$missing $r"; done
    if [ -n "$foreign" ]; then
      bad "$p loads files from the image's /docs/assets/: $foreign"
    elif [ "$n" -lt 3 ]; then
      bad "$p names only $n /blog/assets/ files (want the theme's css + js + search index at least)"
    elif [ -n "$plain" ]; then
      bad "$p names unhashed assets: $plain"
    elif [ -n "$missing" ]; then
      bad "$p names assets that do not load:$missing"
    else
      ok "$p: $n assets, all under /blog/assets/, content-hashed and loading"
    fi
  done

  if [ "$FAIL" = "0" ]; then echo "public-site smoke (blog lane): all checks passed"; else echo "public-site smoke (blog lane): FAILED"; fi
  exit "$FAIL"
fi

echo "public-site smoke against $BASE"

# 1. Relative redirects, one URL per page.
for path in /docs /docs/start /links; do
  read -r code loc <<< "$(redirect "$BASE$path")"
  if [ "$code" = "301" ] && [ "${loc#/}" != "$loc" ] && [ "$loc" = "$path/" ]; then
    ok "$path -> 301 Location: $loc (relative, slash form)"
  else
    bad "$path -> $code Location: '${loc:-none}' (want 301 to '$path/', relative)"
  fi
done

# 2. Real 404s, never the SPA shell — and the site's own 404 page, which
#    offers search and the sections, not nginx's bare one.
for path in /docs/fr87-smoke-missing/ /blog/fr87-smoke-missing/ /links/fr88-smoke-missing/; do
  code="$(status "$BASE$path")"
  if [ "$code" != "404" ]; then
    bad "$path -> $code (want 404; a 200 here is a soft 404)"
  elif curl -ksS -m 15 "$BASE$path" 2>/dev/null | grep -q '<h1 class="page-title">Page not found'; then
    ok "$path -> 404, the site's 404 page"
  else
    bad "$path -> 404, but not the site's 404 page (is dist/docs/404.html missing?)"
  fi
done

# 3. HTML is revalidated, so it is never the stale half of a hashed-asset pair.
#    The SPA shell too: every app route is index.html through `location /`,
#    and a shell cached without a Cache-Control kept drawing the previous
#    build after a promote, its chunks already 404s (2026-10-20).
for p in /docs/ /login /tenant/smoke-check/devices; do
  cc="$(header "$BASE$p" cache-control)"
  case "$cc" in
    *no-cache*) ok "$p Cache-Control: $cc" ;;
    *) bad "$p Cache-Control: '${cc:-none}' (want no-cache)" ;;
  esac
done

# 4. Security headers identical to `/` on every static page family.
ROOT_SET="$(secset "$BASE/")"
if [ -z "$ROOT_SET" ]; then
  bad "/ carries none of the security headers — cannot compare"
else
  # `/login` is the SPA shell (`location /`), which carries `expires` and must
  # never gain an `add_header` that would drop the set.
  pages="/docs/ /docs/start/ /links/ /login"
  [ "$(status "$BASE/blog/")" = "200" ] && pages="$pages /blog/"
  for path in $pages; do
    got="$(secset "$BASE$path")"
    if [ "$got" = "$ROOT_SET" ]; then
      ok "$path security headers == / ($(printf '%s\n' "$got" | wc -l | tr -d ' ') headers)"
    else
      bad "$path security headers differ from /:"
      diff <(printf '%s\n' "$ROOT_SET") <(printf '%s\n' "$got") | sed 's/^/      /'
    fi
  done
fi

# 5. The blog, when it exists: its feed is Atom. When it does not: a real 404.
blog="$(status "$BASE/blog/")"
if [ "$blog" = "200" ]; then
  ct="$(header "$BASE/blog/feed.xml" content-type)"
  case "$ct" in
    application/atom+xml*) ok "/blog/feed.xml Content-Type: $ct" ;;
    *) bad "/blog/feed.xml Content-Type: '${ct:-none}' (want application/atom+xml)" ;;
  esac
elif [ "$blog" = "404" ]; then
  ok "/blog/ -> 404 (no posts published yet; not a soft 404)"
else
  bad "/blog/ -> $blog (want 200 with posts, or 404 without)"
fi

# 5b. `/` (P6): the static homepage without a session cookie — what every guest
#     and crawler gets — and the SPA with one, exactly as before. `/home/` is
#     internal, and the SPA's old marketing routes 301 to the one page.
home="$(curl -ksS -m 15 "$BASE/" 2>/dev/null)"
if printf '%s' "$home" | grep -q '<h1 class="home-hero__title">' && printf '%s' "$home" | grep -q '"@type":"WebSite"'; then
  ok "/ without a cookie -> the static homepage (H1 + WebSite JSON-LD)"
else
  bad "/ without a cookie -> not the static homepage (a crawler would read the SPA shell)"
fi
if curl -ksS -m 15 -H 'Cookie: access_token=smoke' "$BASE/" 2>/dev/null | grep -q 'id="app"'; then
  ok "/ with a session cookie -> the SPA"
else
  bad "/ with a session cookie -> not the SPA (signed-in users would lose the app at /)"
fi
APP_SET="$(curl -ksS -m 15 -I -H 'Cookie: access_token=smoke' "$BASE/" 2>/dev/null | tr -d '\r' | sed -E 's/^([A-Za-z0-9-]+):/\L\1:/' | grep -Ei "^($SEC):" | sort)"
if [ -n "$APP_SET" ] && [ "$APP_SET" = "$(secset "$BASE/")" ]; then
  ok "/ security headers identical with and without the cookie"
else
  bad "/ security headers differ between the SPA and the static homepage"
fi
cc="$(header "$BASE/" cache-control)"
case "$cc" in
  *no-cache*) ok "/ Cache-Control: $cc" ;;
  *) bad "/ Cache-Control: '${cc:-none}' (want no-cache)" ;;
esac
code="$(status "$BASE/home/")"
[ "$code" = "404" ] && ok "/home/ -> 404 (the homepage has one URL, /)" || bad "/home/ -> $code (a second URL for the homepage)"
# FR-88: the query string rides along, or a published `/pricing?utm_source=…`
# link reaches the homepage without its campaign. Read line by line, never
# word-split: an unquoted `?` is a glob.
while read -r from to; do
  read -r code loc <<< "$(redirect "$BASE$from")"
  if [ "$code" = "301" ] && [ "$loc" = "$to" ]; then
    ok "$from -> 301 Location: $loc"
  else
    bad "$from -> $code Location: '${loc:-none}' (want 301 to '$to')"
  fi
done <<'PAIRS'
/landing /
/pricing /#pricing
/landing?utm_source=smoke&utm_campaign=fr88 /?utm_source=smoke&utm_campaign=fr88
/pricing?utm_source=smoke /?utm_source=smoke#pricing
PAIRS

# 5c. FR-88 P2 — the link hub, and one short path per channel profile that
#     302s to it WITH the channel as the campaign source. A short path that
#     fell through to `location /` would answer 200 with the SPA shell, which
#     is why the status and the exact Location are both checked.
hub="$(curl -ksS -m 15 "$BASE/links/" 2>/dev/null)"
if printf '%s' "$hub" | grep -q '<h1 class="links-title">' && printf '%s' "$hub" | grep -q 'content="noindex, follow"'; then
  ok "/links/ -> the link hub (H1, noindex)"
else
  bad "/links/ -> not the link hub (is dist/links/index.html missing?)"
fi
cc="$(header "$BASE/links/" cache-control)"
case "$cc" in
  *no-cache*) ok "/links/ Cache-Control: $cc" ;;
  *) bad "/links/ Cache-Control: '${cc:-none}' (want no-cache)" ;;
esac
while read -r from to; do
  read -r code loc <<< "$(redirect "$BASE$from")"
  if [ "$code" = "302" ] && [ "$loc" = "$to" ]; then
    ok "$from -> 302 Location: $loc"
  else
    bad "$from -> $code Location: '${loc:-none}' (want 302 to '$to')"
  fi
done <<'PAIRS'
/yt /links/?utm_source=youtube&utm_medium=bio&utm_campaign=profile
/tt /links/?utm_source=tiktok&utm_medium=bio&utm_campaign=profile
/x /links/?utm_source=x&utm_medium=bio&utm_campaign=profile
/fb /links/?utm_source=facebook&utm_medium=bio&utm_campaign=profile
PAIRS

# 5d. The IndexNow key (P7): an engine verifies a submission by fetching
#     /<key>.txt, so the file must be served exactly as committed. A missing
#     one would not 404: `location /` answers it with the SPA shell. Needs the
#     repo, where the key file is named.
if [ -n "$REPO" ]; then
  for f in $(git -C "$REPO" ls-tree --name-only "$REV" ui/public/ 2>/dev/null | grep -E '/[0-9a-f]{32}\.txt$'); do
    key="$(basename "$f" .txt)"
    got="$(curl -ksS -m 15 "$BASE/$key.txt" 2>/dev/null)"
    if [ "$got" = "$key" ]; then
      ok "/$key.txt serves the IndexNow key"
    else
      bad "/$key.txt does not serve the IndexNow key (engines would reject every submission)"
    fi
  done
fi

# 6. Every asset a page names is content-hashed — the only kind of name for
#    which nginx's one-year `immutable` is true — and actually loads. Every
#    image reserves its box (width + height). The og:image is absolute and
#    keeps a stable name on purpose (the SPA's index.html points at it), so
#    it is not matched here. `/` (no cookie) is the static homepage (P6).
for path in / /docs/ /docs/start/quickstart/ /links/; do
  html="$(curl -ksS -m 20 "$BASE$path" 2>/dev/null)"
  refs="$(printf '%s' "$html" | grep -oE '(href|src|data-search-index)="/docs/assets/[^"]+"' | sed -E 's/^[^"]+"//; s/"$//' | sort -u)"
  n="$(printf '%s\n' "$refs" | grep -c .)"
  plain="$(printf '%s\n' "$refs" | grep -vE '\.[0-9a-f]{10}\.[a-z0-9]+$' | grep . | tr '\n' ' ')"
  missing=""
  for r in $refs; do [ "$(status "$BASE$r")" = "200" ] || missing="$missing $r"; done
  imgs="$(printf '%s' "$html" | grep -oE '<img [^>]*>')"
  unsized="$(printf '%s\n' "$imgs" | grep . | grep -vE ' width="[0-9]+"' ; printf '%s\n' "$imgs" | grep . | grep -vE ' height="[0-9]+"')"
  if [ "$n" -lt 3 ]; then
    bad "$path names only $n /docs/assets/ files (want the theme's css + js + search index at least)"
  elif [ -n "$plain" ]; then
    bad "$path names unhashed assets: $plain"
  elif [ -n "$missing" ]; then
    bad "$path names assets that do not load:$missing"
  elif [ -n "$unsized" ]; then
    bad "$path has an <img> without width and height: $(printf '%s' "$unsized" | head -1)"
  else
    ok "$path: $n assets, all content-hashed and loading; $(printf '%s\n' "$imgs" | grep -c .) image(s), all sized"
  fi
done

# 7. <lastmod> is when the CONTENT changed, from git — never the build date.
#    Needs a clone with full history; skipped (and said so) without one.
if [ -z "$REPO" ]; then
  echo "  - lastmod vs git: skipped (no <repo-dir> given)"
elif [ "$(git -C "$REPO" rev-parse --is-shallow-repository 2>/dev/null)" != "false" ]; then
  bad "lastmod vs git: $REPO is not a clone with full history"
else
  # "path lastmod" per <url>, following a sitemap index to its children
  # (fetched from BASE, whatever origin their <loc> names). "-" = undated.
  sitemap_pairs() {
    local body; body="$(curl -ksS -m 20 "$1" 2>/dev/null | tr -d '\r')"
    if printf '%s' "$body" | grep -q '<sitemapindex'; then
      for p in $(printf '%s' "$body" | grep -oE '<loc>[^<]+</loc>' | sed -E 's#</?loc>##g; s#^https?://[^/]+##'); do
        sitemap_pairs "$BASE$p"
      done
    else
      printf '%s\n' "$body" | awk '
        /<loc>/     { l = $0; sub(/.*<loc>https?:\/\/[^\/]+/, "", l); sub(/<\/loc>.*/, "", l) }
        /<lastmod>/ { m = $0; sub(/.*<lastmod>/, "", m); sub(/<\/lastmod>.*/, "", m) }
        /<\/url>/   { print l, (m == "" ? "-" : m); l = ""; m = "" }'
    fi
  }
  SITEMAP="$(sitemap_pairs "$BASE/sitemap.xml")"
  compared=0; wrong=""
  while read -r file day; do
    git -C "$REPO" cat-file -e "$REV:$file" 2>/dev/null || continue            # deleted since
    git -C "$REPO" show "$REV:$file" | sed -n '2,/^---/p' | grep -q '^updated:' && continue  # overridden
    rel="${file#ui/docs/content/}"; rel="${rel%.md}"
    case "$rel" in
      index) url=/docs/ ;;
      */index) url="/docs/${rel%/index}/" ;;
      *) url="/docs/$rel/" ;;
    esac
    got="$(printf '%s\n' "$SITEMAP" | awk -v u="$url" '$1 == u { print $2; exit }')"
    compared=$((compared + 1))
    [ "$got" = "$day" ] || wrong="$wrong\n      $url: sitemap ${got:-absent}, git $day"
  done < <(git -C "$REPO" -c core.quotePath=false log "$REV" --format=__C__%cs --name-only -- ui/docs/content \
             | awk '/^__C__/ { d = substr($0, 6); next } NF && !($0 in s) { s[$0] = 1; print $0, d }')
  if [ "$compared" -lt 10 ]; then
    bad "lastmod vs git: only $compared docs files compared (want at least 10)"
  elif [ -n "$wrong" ]; then
    bad "lastmod vs git at $REV: $(printf '%b' "$wrong" | grep -c .) of $compared pages differ:$(printf '%b' "$wrong" | head -6)"
  else
    ok "lastmod == git (at $REV) for all $compared docs pages"
  fi
fi

if [ "$FAIL" = "0" ]; then echo "public-site smoke: all checks passed"; else echo "public-site smoke: FAILED"; fi
exit "$FAIL"
