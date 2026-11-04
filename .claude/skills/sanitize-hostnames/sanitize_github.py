#!/usr/bin/env python3
"""Sweep real machine names out of the GitHub issue/PR/comment/release text.

The repo is only half the exposure. FR issues carry the field-verification
logs -- which is exactly where a debugging session writes down the name of the
machine it was debugging -- so the same names live in issue bodies, PR
descriptions and the step-log comments, all of it world-readable on a public
repo. #805 (FR-19) alone named two corp laptops in its step log.

Reuses `sanitize.py`'s map loader and regex builder on purpose: a second
implementation of longest-key-first whole-word matching is a second thing that
can drift from the map. Everything here is fetch -> apply -> PATCH-if-changed.

Note the ONE asymmetry with the repo sweep: the GitHub issues API returns pull
requests as well as issues, so a single pass over `/issues` covers both titles
and bodies. Review comments live under `/pulls/comments` and are fetched
separately (this repo has none today, but a future review would land there).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sanitize import apply_text, build_regex, load_map, residual_scan  # noqa: E402


def gh(args, parse=True):
    out = subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        raise RuntimeError("gh %s failed: %s" % (" ".join(args[:3]), out.stderr.strip()[:400]))
    return json.loads(out.stdout) if parse else out.stdout


def paginate(endpoint, repo):
    """Stream every page as newline-delimited JSON.

    `--paginate --jq '.[]'` rather than `--slurp`: slurp is the tidier flag but
    only exists in recent gh, and this has to run under whichever gh the box
    happens to have (the WSL one here is older than the Windows one).
    """
    out = gh(["api", "repos/%s/%s" % (repo, endpoint), "--paginate", "--jq", ".[]"],
             parse=False)
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def sweep(repo, pairs, keep, apply_changes):
    rx = build_regex(pairs)
    safe = {v.lower() for _, v in pairs}
    edits, scanned, residue = [], 0, set()

    # (endpoint to fetch, PATCH path template, which text fields to rewrite)
    surfaces = [
        ("issues?state=all&per_page=100", "issues/%s", ("title", "body"), "number"),
        ("issues/comments?per_page=100", "issues/comments/%s", ("body",), "id"),
        ("pulls/comments?per_page=100", "pulls/comments/%s", ("body",), "id"),
        ("releases?per_page=100", "releases/%s", ("name", "body"), "id"),
    ]

    for endpoint, patch_tpl, fields, key in surfaces:
        label = endpoint.split("?")[0]
        items = paginate(endpoint, repo)
        scanned += len(items)
        for item in items:
            changed = {}
            for f in fields:
                text = item.get(f) or ""
                new, hits = apply_text(text, pairs, rx)
                if hits:
                    changed[f] = new
                residue |= residual_scan(new if hits else text, pairs, safe, keep)
            if changed:
                edits.append((label, patch_tpl % item[key], item[key], changed))
        print("  scanned %-18s %4d items" % (label, len(items)))

    print("\n%s: %d of %d items" % ("editing" if apply_changes else "would edit",
                                    len(edits), scanned))
    for label, path, key, changed in edits:
        print("  %-18s %-12s %s" % (label, key, ", ".join(changed)))
        if apply_changes:
            args = ["api", "-X", "PATCH", "repos/%s/%s" % (repo, path)]
            for f, v in changed.items():
                args += ["-f", "%s=%s" % (f, v)]
            gh(args)

    # The residual scan matters more here than in the tree: GitHub text is
    # written by hand in the middle of a field test, so it carries spellings
    # (concatenations, typos) that never appear in reviewed source.
    print("residual: %s" % (", ".join(sorted(residue)) if residue else "none"))
    return 1 if residue else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--map", required=True, type=Path)
    ap.add_argument("--repo", default="jk-zhang-meta/MeshHarbor")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--apply", action="store_true")
    g.add_argument("--check", action="store_true")
    args = ap.parse_args()

    pairs, keep = load_map(args.map)
    print("map: %d replacements\nrepo: %s\n" % (len(pairs), args.repo))
    return sweep(args.repo, pairs, keep, apply_changes=args.apply)


if __name__ == "__main__":
    sys.exit(main())
