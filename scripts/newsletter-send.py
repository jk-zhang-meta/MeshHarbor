#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 G ROX EOOD
"""FR-58 — drive the newsletter admin API from an issue's canonical .md source.

The .md lives in the private annex (roomler-ai-news:news/NN-slug.md; war stories in fixes/)
with YAML-ish frontmatter (slug, subject, preheader, hero, hero_alt, cta_text,
cta_url) followed by the markdown body. This script is deliberately
stdlib-only (urllib, json, re, getpass) so it runs anywhere python3 exists —
WSL, mars, a laptop — with zero pip.

Commands:
  push <file.md>        create the issue, or update it while still a draft
  preview <slug>        fetch the rendered email HTML to ./<slug>-preview.html
  test-send <slug> --to you@example.com
  send <slug> [--retry-stale]     start (or resume) the real fan-out
  status <slug>         issue status + per-recipient counts
  list                  all issues

Auth: a platform-admin bearer token, from (in order) --token, the
ROOMLER_TOKEN env var, or an interactive login prompt (email + password,
never echoed, nothing persisted).

Server: --server (default https://roomler.ai).

Examples:
  ./scripts/newsletter-send.py push  ../meshharbor-ai-news/news/01-three-products-one-daemon.md
  ./scripts/newsletter-send.py preview three-products-one-daemon
  ./scripts/newsletter-send.py test-send three-products-one-daemon --to me@example.com
  ./scripts/newsletter-send.py send three-products-one-daemon
  ./scripts/newsletter-send.py status three-products-one-daemon
"""

import argparse
import getpass
import json
import os
import re
import sys
import urllib.error
import urllib.request

FRONTMATTER_KEYS = {
    "slug": "slug",
    "subject": "subject",
    "preheader": "preheader",
    "hero": "hero_url",
    "hero_alt": "hero_alt",
    "cta_text": "cta_text",
    "cta_url": "cta_url",
}


def parse_issue_md(path):
    """--- key: value … --- body. Values may be bare or double-quoted."""
    text = open(path, encoding="utf-8").read()
    m = re.match(r"\A---\r?\n(.*?)\r?\n---\r?\n(.*)\Z", text, re.S)
    if not m:
        sys.exit(f"{path}: no frontmatter block (--- … ---) found")
    meta, body = {}, m.group(2).strip() + "\n"
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        km = re.match(r"([A-Za-z_]+):\s*(.*)$", line)
        if not km:
            continue
        key, val = km.group(1), km.group(2).strip()
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1]
        if key in FRONTMATTER_KEYS and val:
            meta[FRONTMATTER_KEYS[key]] = val
    for required in ("slug", "subject", "preheader"):
        if required not in meta:
            sys.exit(f"{path}: frontmatter is missing `{required}`")
    meta["body_md"] = body
    return meta


class Api:
    def __init__(self, server, token):
        self.base = server.rstrip("/")
        self.token = token

    def call(self, method, path, body=None, raw=False):
        req = urllib.request.Request(
            self.base + path,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
        )
        req.add_header("Authorization", f"Bearer {self.token}")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
                return resp.status, data if raw else json.loads(data or b"null")
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            # 404 on every admin route also means "not a platform admin" —
            # the gate hides the surface on purpose. Say so.
            hint = (
                "\n(hint: 404 here also means the token's user is not in "
                "ROOMLER__STATS__PLATFORM_ADMINS — the gate hides the surface)"
                if e.status == 404
                else ""
            )
            sys.exit(f"{method} {path} → {e.status}: {detail}{hint}")


def login(server):
    email = input("email: ").strip()
    password = getpass.getpass("password (not stored): ")
    req = urllib.request.Request(
        server.rstrip("/") + "/api/auth/login",
        method="POST",
        data=json.dumps({"email": email, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"login failed: {e.status} {e.read().decode(errors='replace')}")
    token = body.get("access_token") or (body.get("tokens") or {}).get("access_token")
    if not token:
        sys.exit(
            "login answered without an access token in the body — mint one "
            "manually and pass it via ROOMLER_TOKEN"
        )
    return token


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("command", choices=["push", "preview", "test-send", "send", "status", "list"])
    p.add_argument("target", nargs="?", help="issue .md file (push) or slug")
    p.add_argument("--server", default=os.environ.get("ROOMLER_SERVER", "https://roomler.ai"))
    p.add_argument("--token", default=os.environ.get("ROOMLER_TOKEN"))
    p.add_argument("--to", help="test-send recipient")
    p.add_argument("--retry-stale", action="store_true", help="send: re-attempt stale claimed rows")
    args = p.parse_args()

    if args.command != "list" and not args.target:
        p.error(f"`{args.command}` needs a target")

    token = args.token or login(args.server)
    api = Api(args.server, token)

    if args.command == "push":
        meta = parse_issue_md(args.target)
        slug = meta["slug"]
        try:
            status, _created = api.call("POST", "/api/admin/newsletter/issues", meta)
            print(f"created draft `{slug}` ({status})")
        except SystemExit as e:
            # 409 = the slug exists — update the draft instead. Anything else
            # (404 not-an-admin, 422 validation) propagates with its message.
            if "409" not in str(e):
                raise
            body = {k: v for k, v in meta.items() if k != "slug"}
            api.call("PUT", f"/api/admin/newsletter/issues/{slug}", body)
            print(f"updated draft `{slug}`")
        print(f"next: preview {slug} · test-send {slug} --to you@… · send {slug}")

    elif args.command == "preview":
        _, html = api.call("GET", f"/api/admin/newsletter/issues/{args.target}/preview", raw=True)
        out = f"{args.target}-preview.html"
        with open(out, "wb") as f:
            f.write(html)
        print(f"wrote {out} — open it in a browser; these are the exact send bytes")

    elif args.command == "test-send":
        if not args.to:
            sys.exit("test-send needs --to you@example.com")
        _, r = api.call(
            "POST",
            f"/api/admin/newsletter/issues/{args.target}/test-send",
            {"email": args.to},
        )
        print(json.dumps(r, indent=1))

    elif args.command == "send":
        _, r = api.call(
            "POST",
            f"/api/admin/newsletter/issues/{args.target}/send",
            {"retry_stale": args.retry_stale},
        )
        print(json.dumps(r, indent=1))
        print(f"poll: {sys.argv[0]} status {args.target}")

    elif args.command == "status":
        _, r = api.call("GET", f"/api/admin/newsletter/issues/{args.target}/status")
        print(json.dumps(r, indent=1))

    elif args.command == "list":
        _, r = api.call("GET", "/api/admin/newsletter/issues")
        for i in r:
            print(f"{i['status']:>10}  {i['slug']}  {i.get('sent_at') or ''}")


if __name__ == "__main__":
    main()
