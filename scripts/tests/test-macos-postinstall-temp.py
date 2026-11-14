#!/usr/bin/env python3
"""Exercise only the installer's temporary-file prologue, never the installer."""
import argparse
import pathlib
import subprocess

p = argparse.ArgumentParser()
p.add_argument('--mac-host', required=True)
args = p.parse_args()
source = (pathlib.Path(__file__).resolve().parents[2] /
          'agents/meshharbord/packaging/macos/postinstall').read_text()
assert '/tmp/meshharbor-bootstrap.err' not in source
assert '/tmp/meshharbor-update-bootstrap.err' not in source
assert source.count('2>"$INSTALL_TMP/') == 3
header = source.split('\nCONSOLE_USER=', 1)[0]
assert 'INSTALL_TMP=$(mktemp -d /private/tmp/meshharbor-install.XXXXXX)' in header
assert 'trap \'rm -rf "$INSTALL_TMP"\' EXIT' in header
# No bundle, config, launchctl, privilege, UI, or actual postinstall calls.
probe = '''
set -eu
captured=$(
''' + header + '''
test "$(stat -f %Lp "$INSTALL_TMP")" = 700
test "$(stat -f %u "$INSTALL_TMP")" = "$(id -u)"
sh -c 'echo expected-error >&2; exit 1' 2>"$INSTALL_TMP/bootstrap.err" && exit 91
test "$(cat "$INSTALL_TMP/bootstrap.err")" = expected-error
sh -c 'echo update-error >&2; exit 1' 2>"$INSTALL_TMP/update-bootstrap.err" && exit 92
test "$(cat "$INSTALL_TMP/update-bootstrap.err")" = update-error
printf '%s' "$INSTALL_TMP"
)
test ! -e "$captured"
echo 'PASS private mode700 owned capture directory, both error paths, EXIT cleanup'
'''
r = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=20',
                    args.mac_host, '/bin/bash -s'], input=probe, text=True,
                   capture_output=True, timeout=40)
print(r.stdout, end='')
print(r.stderr, end='')
print('EXIT', r.returncode)
raise SystemExit(r.returncode)
