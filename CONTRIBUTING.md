# Contributing

Thanks for considering it. This file covers the two things that are specific to
this repo — the licence split and the CLA — plus the checks your PR has to pass.
Everything else about how the codebase works lives in
[`CLAUDE.md`](CLAUDE.md) and [`docs/README.md`](docs/README.md).

## Which licence your PR falls under

Roomler is split-licensed, and **the licence follows the directory you touch**:

| You edited… | Your contribution is |
|---|---|
| `crates/api`, `services`, `db`, `config`, `derp-relay`, `tests`, `ui/src` | AGPL-3.0-only |
| `agents/*`, `crates/agent-core`, `meshharbor-setup-core`, `tunnel-core`, `remote_control`, `localapi`, `tcp-turn-conn` | MPL-2.0 |
| `docs/` | CC-BY-4.0 |
| `crates/vendored/*` | upstream's licence — do not add our headers |

You never have to work this out by hand: every source file carries an
`SPDX-License-Identifier` header, and CI checks it. If you add a file, run:

```bash
scripts/apply-spdx.sh
```

The classification itself lives in one place,
[`scripts/licence-classes.sh`](scripts/licence-classes.sh).

⚠️ **One rule is load-bearing:** a crate compiled into both the server and a
shipped agent binary must be MPL, never AGPL — otherwise the agent becomes
effectively AGPL, which is a procurement blocker for the people who install it.
CI asserts this by walking the dependency graph of every shipped binary, so a
new edge that violates it fails the build rather than shipping quietly. See
[LICENSING.md](LICENSING.md).

## Contributor Licence Agreement

We ask contributors to sign a [CLA](docs/CLA.md) granting G ROX EOOD the right
to relicense contributions. This is what keeps the commercial exception in
[COMMERCIAL.md](COMMERCIAL.md) possible — without it, dual licensing becomes
impossible the moment the first outside contribution lands, and the project
loses its only revenue mechanism.

The bot will prompt you on your first PR.

## Before you open a PR

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
scripts/apply-spdx.sh --check

cd ui && bun run build && bun run test:unit
```

Backend changes that touch models, services or routes also want
`cargo test -p meshharbor-tests` (needs MongoDB on `:27019` and Redis on `:6379`).

## Substantial changes need a Functional Requirement first

Anything bigger than a one-PR fix — a new capability, a protocol change, a
performance arc — gets an FR **before** the implementation: a spec in
`docs/fr/FR-N-<slug>.md` and a tracking issue. Claim the number by adding your
row to [`docs/fr/README.md`](docs/fr/README.md) **in the same commit as the
spec**; that registry, not a scan of the directory, is what prevents two people
claiming the same number. The protocol and its history are in that file.

## Reporting security issues

Not here — see [SECURITY.md](SECURITY.md).

## If `Licence split integrity` fails on your PR

Almost always this: you added a source file and it has no SPDX header. Run

```bash
scripts/apply-spdx.sh
```

and commit the result. It is idempotent — it only touches files that need it, and
it derives the licence from the directory, so you do not have to know which one
applies.

If it reports **UNCLASSIFIED**, your file is somewhere the split does not describe
yet. Add its directory to `scripts/licence-classes.sh` rather than working around
the check: an unclassified path used to be a silent skip, which meant a directory
rename could drop a whole binary out of the sweep while the check still said OK.
