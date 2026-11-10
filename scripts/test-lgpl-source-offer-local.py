#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Offline CLI regression using two disposable, independent Git repositories."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


SCRIPT = Path(__file__).with_name('lgpl-source-offer-local.py').resolve()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    with tempfile.TemporaryDirectory(prefix='meshharbor-source-offer-test-') as tmp:
        root = Path(tmp)
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1',
                   GIT_TERMINAL_PROMPT='0', GIT_NO_LAZY_FETCH='1')
        for key in ('GIT_DIR', 'GIT_COMMON_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE',
                    'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES',
                    'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS', 'GIT_TEMPLATE_DIR'):
            env.pop(key, None)

        def git(repo, *args):
            return subprocess.check_output(
                ['git', '-c', 'core.hooksPath=' + os.devnull, '-C', str(repo), *args],
                env=env, stderr=subprocess.PIPE).decode().strip()

        def commit(repo):
            git(repo, 'add', '.')
            git(repo, '-c', 'user.name=Synthetic Fixture',
                '-c', 'user.email=synthetic@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-qm', 'synthetic fixture')
            return git(repo, 'rev-parse', 'HEAD')

        port_repo = root / 'vcpkg'
        build_repo = root / 'original-build'
        for repo in (port_repo, build_repo):
            repo.mkdir()
            git(repo, 'init', '-q', '--template=')
        port_dir = port_repo / 'ports/ffmpeg'
        port_dir.mkdir(parents=True)
        (port_dir / 'portfile.cmake').write_text('# synthetic port\n')
        (port_dir / 'port.patch').write_text('synthetic upstream port patch\n')
        baseline = commit(port_repo)
        recipes = build_repo / '.github/workflows'
        recipes.mkdir(parents=True)
        windows = (f"$baseline = '{baseline}'\n"
                   '# https://github.com/FFmpeg/FFmpeg/archive/refs/tags/n9.0.1.tar.gz\n')
        (recipes / 'vendor-ffmpeg-windows.yml').write_text(windows)
        (recipes / 'vendor-ffmpeg-macos.yml').write_text("default: 'n9.0.1'\n")
        patch_dir = build_repo / '.github/ffmpeg-patches'
        patch_dir.mkdir()
        patch = b'synthetic external-build patch\n'
        (patch_dir / 'external.patch').write_bytes(patch)
        build_ref = commit(build_repo)
        assert build_ref != baseline

        upstream = root / 'ffmpeg-n9.0.1.tar.gz'
        with tarfile.open(upstream, 'w:gz') as tar:
            data = b'synthetic upstream source\n'
            member = tarfile.TarInfo('FFmpeg-n9.0.1/README')
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))

        def run(output, ref=build_ref, source_hash=None):
            result = subprocess.run(
                [sys.executable, str(SCRIPT), '--build-repo', str(build_repo),
                 '--build-ref', ref, '--ffmpeg-source', str(upstream),
                 '--ffmpeg-sha256', source_hash or sha(upstream),
                 '--vcpkg-repo', str(port_repo), '--output', str(output)],
                cwd=root, env=env, capture_output=True, text=True, timeout=30)
            return result

        output = root / 'good'
        result = run(output)
        assert result.returncode == 0, result.stderr
        expected = {
            'ffmpeg-n9.0.1.tar.gz': upstream.read_bytes(),
            'patches/external.patch': patch,
            'vcpkg-port-ffmpeg/portfile.cmake': b'# synthetic port\n',
            'vcpkg-port-ffmpeg/port.patch': b'synthetic upstream port patch\n',
            'recipe/vendor-ffmpeg-windows.yml': windows.encode(),
            'recipe/vendor-ffmpeg-macos.yml': b"default: 'n9.0.1'\n",
        }
        receipt = json.loads((output / 'SOURCE-INPUTS.json').read_text())
        assert receipt['vendor_build_ref'] == build_ref
        assert receipt['vcpkg_baseline'] == baseline
        assert receipt['published'] is False and receipt['binary_provenance_verified'] is False
        with tarfile.open(output / 'ffmpeg-n9.0.1-corresponding-source.tar.xz') as tar:
            archived = {m.name.removeprefix('./'): tar.extractfile(m).read()
                        for m in tar.getmembers() if m.isfile()}
        assert set(archived) == set(receipt['files'])
        for name, content in archived.items():
            assert hashlib.sha256(content).hexdigest() == receipt['files'][name]['sha256']
        for name, content in expected.items():
            assert archived[name] == content, name
        inputs = (output / 'ffmpeg-n9.0.1-corresponding-source.inputs.txt').read_text()
        assert baseline + '  vcpkg-baseline\n' in inputs
        assert hashlib.sha256(patch).hexdigest() + '  external.patch\n' in inputs
        before = {p.relative_to(output).as_posix(): sha(p)
                  for p in output.rglob('*') if p.is_file()}
        assert run(output).returncode != 0
        assert before == {p.relative_to(output).as_posix(): sha(p)
                          for p in output.rglob('*') if p.is_file()}
        for name, kwargs in [('missing-commit', {'ref': 'f' * 40}),
                             ('bad-hash', {'source_hash': '0' * 64})]:
            rejected = root / name
            assert run(rejected, **kwargs).returncode != 0, name
            assert not rejected.exists(), name
        print('PASS external build + vcpkg repositories, archive/manifest hashes, '
              'missing commit, bad upstream hash, overwrite rejection')
    print('PASS owned temporary repositories and outputs removed')


if __name__ == '__main__':
    main()
