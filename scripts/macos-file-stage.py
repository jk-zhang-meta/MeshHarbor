#!/usr/bin/env python3
"""Mac-only four-object FILE stage. No installer, launchctl, TCC, GUI or feed.

The caller must independently quiesce the exact jobs/updater and restore their
original scope afterward. This helper does not claim runtime acceptance.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

TARGETS = {
    "daemon": ("bundle", "/Library/MeshHarbor/meshharbord.app"),
    "desktop": ("bundle", "/Applications/MeshHarbor.app"),
    "cli": ("file", "/usr/local/bin/mh"),
    "daemon_link": ("symlink", "/usr/local/bin/meshharbord"),
}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def native(argv):
    result = subprocess.run(argv, capture_output=True, timeout=120)
    require(result.returncode == 0, "native operation failed: " + argv[0] + ": " + result.stderr.decode(errors="replace")[:1200])
    return result.stdout


def sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def absolute(path):
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve() == path.parent, "absolute path without symlink ancestors required")
    return path


def tree_sha(path):
    """Byte tree + links + mode/UID/GID/mtime/flags/xattrs/resource forks/ACL.

    Excludes atime, ctime, inode and birthtime: copying/reading changes them.
    No signature bytes, executable metadata or resource-fork bytes are omitted.
    """
    path = absolute(path)
    entries = []
    def visit(current, relative):
        before = current.lstat()
        mode = before.st_mode
        row = dict(path=relative, mode=stat.S_IMODE(mode), uid=before.st_uid, gid=before.st_gid,
                   mtime_ns=before.st_mtime_ns, flags=getattr(before, "st_flags", 0))
        if stat.S_ISLNK(mode):
            row.update(kind="symlink", target=os.readlink(current))
        elif stat.S_ISREG(mode):
            row.update(kind="file", sha256=sha_file(current))
        elif stat.S_ISDIR(mode):
            row.update(kind="directory")
        else:
            raise RuntimeError("unsupported special file in object")
        keys = native(["/usr/bin/xattr", "-s", str(current)]).decode().splitlines()
        row["xattrs"] = {key: hashlib.sha256(bytes.fromhex(native(
            ["/usr/bin/xattr", "-p", "-s", "-x", key, str(current)]).decode())).hexdigest()
            for key in sorted(keys)}
        # Header includes the absolute filename, so hash only native ACL entries.
        row["acl"] = native(["/bin/ls", "-lde", str(current)]).decode().splitlines()[1:]
        after = current.lstat()
        require((before.st_mtime_ns, before.st_size, before.st_ino, before.st_ctime_ns) ==
                (after.st_mtime_ns, after.st_size, after.st_ino, after.st_ctime_ns), "object changed during hashing")
        entries.append(row)
        if row["kind"] == "directory":
            for child in sorted(current.iterdir(), key=lambda item: item.name):
                visit(child, child.name if relative == "." else relative + "/" + child.name)
    visit(path, ".")
    return hashlib.sha256(json.dumps(entries, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def verify(path, kind, expected):
    path = absolute(path)
    mode = path.lstat().st_mode
    require({"bundle": stat.S_ISDIR, "file": stat.S_ISREG, "symlink": stat.S_ISLNK}[kind](mode), "object kind changed")
    require(tree_sha(path) == expected, "object tree SHA mismatch: " + str(path))
    if kind == "bundle":
        native(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(path)])


def copy_object(source, destination, kind, expected):
    require(not destination.exists() and not destination.is_symlink(), "copy destination exists")
    if kind == "symlink":
        # ditto follows a top-level source symlink. Native cp -Pp preserves it.
        native(["/bin/cp", "-pP", str(source), str(destination)])
    else:
        native(["/usr/bin/ditto", "--rsrc", "--extattr", "--acl", str(source), str(destination)])
    verify(destination, kind, expected)


def sync_dir(path):
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def record(path, value):
    fd, temp = tempfile.mkstemp(prefix=".record-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        sync_dir(path.parent)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def swap(left, right):
    # Native macOS atomic exchange; no absent-target window for a .app directory.
    call = ctypes.CDLL(None, use_errno=True).renamex_np
    call.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    call.restype = ctypes.c_int
    if call(os.fsencode(left), os.fsencode(right), 0x00000002):  # SDK RENAME_SWAP
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def validate_plan(plan, fixture_root=None):
    require(sys.platform == "darwin", "native Mac tools required")
    objects = plan["objects"]
    require(set(objects) == set(TARGETS), "plan must name exactly both bundles, CLI and daemon symlink")
    root = absolute(fixture_root) if fixture_root else None
    if root:
        require(root.resolve() == root and root != Path.home() / ".agent-work/runtime"
                and str(root).startswith(str(Path.home() / ".agent-work/runtime") + "/"), "fixture root must be inside private task runtime")
    for role, item in objects.items():
        expected_kind, expected_target = TARGETS[role]
        require(item["kind"] == expected_kind, "role kind mismatch")
        for key in ("target", "candidate"):
            path = absolute(item[key])
            if root:
                require(str(path).startswith(str(root) + "/"), "fixture object escapes isolated root")
        require(item["target"] != item["candidate"], "candidate must be separate")
        if not root:
            require(item["target"] == expected_target, "target is outside the approved four-object scope")
    targets = [Path(item["target"]) for item in objects.values()]
    require(len(set(targets)) == 4, "duplicate targets")
    for target in targets:
        require(not any(str(target).startswith(str(other) + "/") for other in targets if other != target),
                "nested targets are not supported")
    for item in objects.values():
        for other in targets:
            require(not str(item["candidate"]).startswith(str(other) + "/") and Path(item["candidate"]) != other,
                    "candidate is inside a live target")
    return objects


def replace_one(source, item, desired_sha, allowed):
    target = Path(item["target"])
    current = tree_sha(target)
    require(current in allowed, "third-state target; manual recovery required: " + str(target))
    if current == desired_sha:
        verify(target, item["kind"], desired_sha)
        return
    stage = Path(tempfile.mkdtemp(prefix=".meshharbor-file-stage-", dir=str(target.parent)))
    payload = stage / "payload"
    try:
        copy_object(source, payload, item["kind"], desired_sha)
        # The lock serializes this helper, not other updaters. Caller quiescence
        # remains required; CAS is repeated after slow copy/signature work.
        require(tree_sha(target) == current, "target changed while staging; refusing overwrite")
        swap(payload, target)
        sync_dir(target.parent)
        verify(target, item["kind"], desired_sha)
        require(tree_sha(payload) == current, "retired object changed; retain staging for recovery")
        if payload.is_dir() and not payload.is_symlink():
            shutil.rmtree(payload)
        else:
            payload.unlink()
        stage.rmdir()
    except Exception:
        # No blind deletion: the stage may hold the only exact retired object.
        raise RuntimeError("file stage failed; retained private staging at " + str(stage))


def rollback_objects(directory, plan):
    objects = plan["objects"]
    # Validate ALL originals and current states before reversing any object.
    for role, item in objects.items():
        verify(directory / "baseline" / role, item["kind"], item["old_sha"])
        require(tree_sha(item["target"]) in (item["old_sha"], item["new_sha"]),
                "third-state target; manual recovery required: " + item["target"])
    for role in reversed(list(objects)):
        item = objects[role]
        replace_one(directory / "baseline" / role, item, item["old_sha"], (item["old_sha"], item["new_sha"]))


def apply(plan, directory, fixture_root=None):
    objects = validate_plan(plan, fixture_root)
    directory = absolute(directory)
    for item in objects.values():
        for name in ("target", "candidate"):
            path = Path(item[name])
            require(directory != path and not str(directory).startswith(str(path) + "/")
                    and not str(path).startswith(str(directory) + "/"),
                    "transaction must not overlap any source or target")
    directory.mkdir(mode=0o700)
    for name in ("baseline", "candidate"):
        (directory / name).mkdir(mode=0o700)
    for role, item in objects.items():
        verify(item["target"], item["kind"], item["old_sha"])
        verify(item["candidate"], item["kind"], item["new_sha"])
        copy_object(Path(item["target"]), directory / "baseline" / role, item["kind"], item["old_sha"])
        copy_object(Path(item["candidate"]), directory / "candidate" / role, item["kind"], item["new_sha"])
    plan = dict(plan, fixture_root=str(fixture_root) if fixture_root else None)
    record(directory / "plan.json", plan)
    shutil.copyfile(__file__, directory / "file-stage.py")
    import shlex
    (directory / "ROLLBACK.sh").write_text('#!/bin/sh\nset -eu\n'
        + '[ "$#" -eq 1 ] && [ "$1" = "--jobs-quiesced" ] || { echo "caller must quiesce jobs/updater, then pass --jobs-quiesced" >&2; exit 2; }\n'
        + 'here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec '
        + shlex.quote(sys.executable) + ' "$here/file-stage.py" rollback --transaction "$here" "$1"\n')
    (directory / "ROLLBACK.sh").chmod(0o700)
    # Persist every backup byte before first replacement; directory metadata
    # and code signatures have already been compared against the originals.
    for path in directory.rglob("*"):
        if path.is_file() and not path.is_symlink():
            with open(path, "rb") as stream:
                os.fsync(stream.fileno())
    for path in sorted(directory.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        if path.is_dir() and not path.is_symlink():
            sync_dir(path)
    sync_dir(directory)
    sync_dir(directory.parent)
    record(directory / "result.json", {"state": "prepared"})
    try:
        for role, item in objects.items():
            replace_one(directory / "candidate" / role, item, item["new_sha"], (item["old_sha"],))
        record(directory / "result.json", {"state": "files_replaced", "runtime_verified": False})
    except Exception as error:
        result = {"state": "failed", "error": str(error)}
        try:
            rollback_objects(directory, plan)
            result["state"] = "files_rolled_back"
        except Exception as recovery:
            result.update(state="manual_recovery_required", recovery_error=str(recovery))
        record(directory / "result.json", result)
        raise RuntimeError("file operation failed: " + result["state"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    snap = sub.add_parser("hash")
    snap.add_argument("path")
    for name in ("apply", "rollback"):
        command = sub.add_parser(name)
        command.add_argument("--transaction", required=True)
        command.add_argument("--jobs-quiesced", action="store_true", required=True,
                             help="caller has stopped exact jobs/updater; helper never controls them")
        if name == "apply":
            command.add_argument("--plan", required=True)
            command.add_argument("--fixture-root")
    args = parser.parse_args()
    require(sys.platform == "darwin", "Mac-only helper")
    if args.action == "hash":
        print(tree_sha(args.path))
        return
    # One per-operator lock across all four targets, never deleted/recreated.
    lockroot = Path.home() / ".agent-work/runtime"
    lockroot.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lockroot / ".macos-file-stage.lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600, "untrusted operation lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        directory = absolute(args.transaction)
        if args.action == "apply":
            apply(json.loads(Path(args.plan).read_text()), directory, args.fixture_root)
        else:
            info = directory.stat()
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, "untrusted transaction")
            plan = json.loads((directory / "plan.json").read_text())
            validate_plan(plan, plan.get("fixture_root"))
            rollback_objects(directory, plan)
            record(directory / "rollback-result.json", {"state": "files_rolled_back", "runtime_verified": False})
        print(json.dumps({"transaction": str(directory), "file_phase_complete": True, "runtime_verified": False}))
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
