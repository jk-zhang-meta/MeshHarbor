#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Offline assembly of an existing FFmpeg vendor build's corresponding source.

No downloads, signing or publication. The caller must identify the actual vendor
build revision and independently verify its upstream archive digest. This tool
records those inputs; it cannot prove which source produced a binary.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile


def git(repo, *args):
    # Never lazy-fetch absent blobs, or silently follow local replace objects.
    env = dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_NO_REPLACE_OBJECTS='1',
               GIT_OPTIONAL_LOCKS='0')
    for key in ('GIT_DIR', 'GIT_COMMON_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE',
                'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES'):
        env.pop(key, None)
    prefix = ['git', '--no-replace-objects', '-C', str(repo)]
    partial = subprocess.run(prefix + ['config', '--get-regexp',
                             r'^(extensions\.partialclone|remote\..*\.promisor)$'],
                             capture_output=True, env=env)
    if partial.returncode != 1:
        raise RuntimeError('require a complete local Git repository without promisor configuration')
    return subprocess.check_output(prefix + list(args), env=env)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-repo', type=Path, required=True,
                        help='complete local Git repository containing the actual vendor build')
    parser.add_argument('--build-ref', required=True,
                        help='full Git commit of the actual vendor build (not an assumed app revision)')
    parser.add_argument('--ffmpeg-source', type=Path, required=True)
    parser.add_argument('--ffmpeg-sha256', required=True,
                        help='independently verified upstream archive digest')
    parser.add_argument('--vcpkg-repo', type=Path, required=True,
                        help='local Git repository containing the pinned baseline')
    parser.add_argument('--output', type=Path, required=True,
                        help='new, exclusive output directory; no implicit output')
    args = parser.parse_args()
    if sys.version_info < (3, 11):
        parser.error('Python 3.11+ is required')
    repo = args.build_repo.resolve()
    if not re.fullmatch(r'[0-9a-f]{40}', args.build_ref):
        parser.error('--build-ref must be an exact full commit')
    if git(repo, 'rev-parse', args.build_ref + '^{commit}').decode().strip() != args.build_ref:
        parser.error('build commit does not resolve exactly')
    if not re.fullmatch(r'[0-9a-f]{64}', args.ffmpeg_sha256):
        parser.error('invalid upstream SHA-256')
    if not args.ffmpeg_source.is_file() or args.ffmpeg_source.is_symlink():
        parser.error('upstream archive must be a regular non-symlink file')
    if digest(args.ffmpeg_source) != args.ffmpeg_sha256:
        parser.error('upstream archive SHA-256 mismatch')
    recipes = {}
    for name in ('vendor-ffmpeg-windows.yml', 'vendor-ffmpeg-macos.yml'):
        # Missing historical recipes are an error, never silently replaced.
        recipes[name] = git(repo, 'show', args.build_ref + ':.github/workflows/' + name)
    windows = recipes['vendor-ffmpeg-windows.yml'].decode()
    macos = recipes['vendor-ffmpeg-macos.yml'].decode()
    baseline_match = re.findall(r"^\s*\$baseline = '([0-9a-f]{40})'", windows, re.M)
    # This assembler supports only the audited n9.0.1 recipe family.
    # Changes require review rather than a guessed version-to-asset mapping.
    if len(baseline_match) != 1 or "refs/tags/n9.0.1.tar.gz" not in windows or "default: 'n9.0.1'" not in macos:
        parser.error('unsupported or ambiguous recipe version/baseline')
    baseline = baseline_match[0]
    if git(args.vcpkg_repo, 'rev-parse', baseline + '^{commit}').decode().strip() != baseline:
        parser.error('vcpkg baseline missing or mismatched')
    entries = git(args.vcpkg_repo, 'ls-tree', '-z', baseline + ':ports/ffmpeg').split(b'\0')
    port = {}
    for entry in filter(None, entries):
        metadata, name_bytes = entry.split(b'\t', 1)
        mode, kind, _oid = metadata.split()
        name = name_bytes.decode()
        if mode not in (b'100644', b'100755') or kind != b'blob' or '/' in name or '\\' in name:
            parser.error('unsupported non-regular vcpkg port entry')
        port[name] = git(args.vcpkg_repo, 'show', baseline + ':ports/ffmpeg/' + name)
    if 'portfile.cmake' not in port:
        parser.error('incomplete vcpkg port')
    patches = {}
    for path_bytes in git(repo, 'ls-tree', '-rz', '--name-only', args.build_ref,
                          '--', '.github/ffmpeg-patches').split(b'\0'):
        if not path_bytes:
            continue
        path = path_bytes.decode()
        if path.endswith('.patch'):
            name = Path(path).name
            if name in patches or Path(path).parent.as_posix() != '.github/ffmpeg-patches':
                parser.error('unexpected patch layout')
            patches[name] = git(repo, 'show', args.build_ref + ':' + path)
    # Validate everything before creating any output. Never overwrite a prior offer.
    if args.output.exists() or args.output.is_symlink():
        parser.error('output already exists')
    args.output.mkdir(parents=False, exist_ok=False)
    bundle = args.output / 'bundle'
    for directory in ('patches', 'vcpkg-port-ffmpeg', 'recipe'):
        (bundle / directory).mkdir(parents=True)
    shutil.copyfile(args.ffmpeg_source, bundle / 'ffmpeg-n9.0.1.tar.gz')
    if digest(bundle / 'ffmpeg-n9.0.1.tar.gz') != args.ffmpeg_sha256:
        raise RuntimeError('source changed during copy; incomplete output retained, do not publish')
    for folder, files in [('patches', patches), ('vcpkg-port-ffmpeg', port), ('recipe', recipes)]:
        for name, content in files.items():
            (bundle / folder / name).write_bytes(content)
    patch_manifest = ''.join(f'{hashlib.sha256(data).hexdigest()}  {name}\n'
                             for name, data in sorted(patches.items()))
    (bundle / 'patches/MESHHARBOR-PATCHES.txt').write_text(patch_manifest)
    (bundle / 'vcpkg-port-ffmpeg/VCPKG-BASELINE.txt').write_text(baseline + '\n')
    inputs = patch_manifest.splitlines() + [baseline + '  vcpkg-baseline']
    inputs += [f'{hashlib.sha256(data).hexdigest()}  recipe/{name}' for name, data in recipes.items()]
    (args.output / 'ffmpeg-n9.0.1-corresponding-source.inputs.txt').write_text('\n'.join(sorted(inputs)) + '\n')
    (bundle / 'recipe/README.md').write_text(
        '# Historical FFmpeg n9.0.1 corresponding source inputs\n\n'
        'Upstream archive, our patches, pinned vcpkg ffmpeg port including its patches, '
        'and byte-exact original recipes are included. The recipes are historical inputs, '
        'not installed CI or a command to dispatch a workflow. Windows uses static-md '
        'and both patch sets; Linux uses shared libraries and our patches; macOS uses '
        'shared libraries and no source patches. Run native build commands on an isolated '
        'matching platform, replacing runner paths/expressions with explicit local inputs. '
        'See docs/local-build.md and docs/lgpl-relink.md in the application source.\n\n'
        'This local assembly has not been uploaded and does not establish binary provenance.\n')
    files = {p.relative_to(bundle).as_posix(): {'sha256': digest(p), 'bytes': p.stat().st_size}
             for p in sorted(bundle.rglob('*')) if p.is_file()}
    receipt = {'vendor_build_ref': args.build_ref, 'ffmpeg_tag': 'n9.0.1',
               'vendor_release_tag': 'vendored-ffmpeg-9.0.1', 'vcpkg_baseline': baseline,
               'upstream_sha256': args.ffmpeg_sha256, 'files': files,
               'published': False, 'binary_provenance_verified': False}
    (args.output / 'SOURCE-INPUTS.json').write_text(json.dumps(receipt, indent=2) + '\n')
    archive = args.output / 'ffmpeg-n9.0.1-corresponding-source.tar.xz'
    with tarfile.open(archive, 'w:xz') as tar:
        tar.add(bundle, arcname='.')
    with tarfile.open(archive, 'r:xz') as tar:
        members = {m.name.removeprefix('./'): m for m in tar.getmembers() if m.isfile()}
        if set(members) != set(files):
            raise RuntimeError('archive file map mismatch')
        for name, member in members.items():
            if hashlib.file_digest(tar.extractfile(member), 'sha256').hexdigest() != files[name]['sha256']:
                raise RuntimeError('archive member digest mismatch')
    archive.with_suffix(archive.suffix + '.sha256').write_text(digest(archive) + '  ' + archive.name + '\n')
    print('Offline source offer assembled and read back; NOT published; binary provenance NOT verified.')


if __name__ == '__main__':
    main()
