#!/usr/bin/env python3
"""Explicit local Linux binary transaction; never install, enroll or query a feed.

Run as the EXISTING service owner (root for system, actual login user for user).
SHA arguments come from the reviewed artifact/audit, not this script's output.
Only process activation is verified here; remote functional acceptance is separate.
"""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
try:
    import tomllib
except ImportError:
    import tomli as tomllib  # Existing dependency only; never auto-install.

# Audited agent-core config::{mark_run_starting,mark_clean_shutdown,
# record_crash_at,record_clean_run_at,migrate}. No identity/permission/key exemptions.
TOMLI_WHEEL = "tomli-2.2.1-py3-none-any.whl"
TOMLI_SHA256 = "cb55c73c5f4408779d0cf3eef9f762b9c9f147a77de7b258bef0a5628adc85cc"
# Official pinned release: https://pypi.org/pypi/tomli/2.2.1/json (MIT).

RUNTIME_FIELDS = {"last_run_unhealthy", "crash_count", "last_crash_unix",
                  "rollback_attempted", "last_known_good_version", "config_schema_version"}


def config_state(path):
    with open(regular(path), "rb") as source:
        config = tomllib.load(source)
    require(not config.get("ephemeral", False), "ephemeral shutdown can unenroll; not supported")
    stable = {key: value for key, value in config.items() if key not in RUNTIME_FIELDS}
    semantic = hashlib.sha256(json.dumps(stable, sort_keys=True, default=str).encode()).hexdigest()
    return semantic, config.get("auto_update")


def bundle_parser(directory):
    if tomllib.__name__ == "tomllib":
        return None
    source = getattr(tomllib, "__file__", "")
    wheel, separator, _ = source.partition(".whl/")
    require(tomllib.__name__ == "tomli" and separator
            and getattr(tomllib, "__version__", None) == "2.2.1",
            "tomli must come from the reviewed pinned pure wheel for standalone rollback")
    wheel = regular(wheel + ".whl")
    same(wheel, TOMLI_SHA256, "official tomli wheel")
    target = directory / TOMLI_WHEEL
    shutil.copyfile(wheel, target)
    same(target, TOMLI_SHA256, "transaction tomli wheel")
    return dict(file=TOMLI_WHEEL, sha256=TOMLI_SHA256, license="MIT", version="2.2.1")


def sidecars(config):
    result = {}
    for name in ("temporary.json", "invites.json"):
        path = Path(config).parent / name
        result[name] = digest(regular(path)) if path.exists() or path.is_symlink() else None
    return result


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def regular(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, "absolute non-symlink path required")
    require(stat.S_ISREG(path.lstat().st_mode), "regular file required")
    return path


def same(path, expected, label):
    require(digest(regular(path)) == expected, label + " SHA mismatch")


@contextmanager
def target_lock(binary):
    # Persistent inode: unlinking it on exit would permit two overlapping locks.
    lock = Path(binary).parent / ".meshharbord-upgrade.lock"
    fd = os.open(str(lock), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600, "untrusted upgrade lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def file_metadata(path):
    info = Path(path).stat()
    return dict(uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode),
                xattrs={key: base64.b64encode(os.getxattr(path, key)).decode()
                        for key in os.listxattr(path)})


def atomic_copy(source, destination, metadata):
    destination = Path(destination)
    fd, temp = tempfile.mkstemp(prefix=".meshharbor-upgrade-", dir=str(destination.parent))
    try:
        with os.fdopen(fd, "wb") as target, open(source, "rb") as original:
            shutil.copyfileobj(original, target)
            target.flush()
            os.fchown(target.fileno(), metadata["uid"], metadata["gid"])
            os.fchmod(target.fileno(), metadata["mode"])
            for key in os.listxattr(target.fileno()):
                if key not in metadata["xattrs"]:
                    os.removexattr(target.fileno(), key)
            for key, value in metadata["xattrs"].items():
                os.setxattr(target.fileno(), key, base64.b64decode(value))
            os.fsync(target.fileno())
        os.replace(temp, destination)
        directory = os.open(str(destination.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def sync_directory(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json(path, value):
    path = Path(path)
    data = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
    fd, temp = tempfile.mkstemp(prefix=".record-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def checked_paths(scope, binary, config):
    binary, config = regular(binary), regular(config)
    if scope == "system":
        require(os.geteuid() == 0, "system scope requires existing root operator")
        require(str(binary) == "/usr/bin/meshharbord", "unexpected system binary")
        require(str(config) == "/etc/meshharbor/config.toml", "unexpected system config")
    else:
        require(os.geteuid() != 0, "user scope must run as actual non-root service owner")
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        require(binary == home / ".local/bin/meshharbord", "unexpected per-user binary")
        config_root = home / ".config/meshharbor"
        require(config.name == "config.toml" and (config.parent == config_root or config.parent.parent == config_root),
                "expected existing default or named per-user config")
    require(binary.stat().st_uid == os.geteuid() and config.stat().st_uid == os.geteuid(),
            "binary/config owner differs from service operator")
    return binary, config


def validate_status(status, pid, config_path, config, scope):
    require(status.get("pid") == pid, "LocalAPI answered from a different process")
    require(status.get("config_path") and Path(status["config_path"]).resolve() == config_path,
            "LocalAPI answered from a different config")
    require(status.get("node_id") == config.get("agent_id") and status.get("tenant_id") == config.get("tenant_id"),
            "LocalAPI enrollment identity differs")
    require(status.get("privileged") is (scope == "system"), "LocalAPI privilege scope differs")


class Systemd:
    def __init__(self, scope, binary, config):
        self.scope, self.binary, self.config = scope, Path(binary), Path(config)
        self.unit = "meshharbor.service" if scope == "user" else "meshharbord.service"
        self.command = ["/usr/bin/systemctl"] + (["--user"] if scope == "user" else [])

    def call(self, *args):
        result = subprocess.run(self.command + list(args), capture_output=True, timeout=60)
        require(result.returncode == 0, "systemctl " + args[0] + " failed: " + result.stderr.decode(errors="replace")[:1000])
        return result.stdout

    def ensure_outside(self):
        groups = Path("/proc/self/cgroup").read_text().splitlines()
        require(not any(self.unit in line.split("/") for line in groups),
                "run upgrade through an independent OS SSH/console, not inside the daemon service cgroup")

    def fingerprint(self):
        # Includes drop-ins, ExecStart, User, unit source and environment, but
        # only the hash is recorded; no environment/credential text is logged.
        return hashlib.sha256(self.call("cat", self.unit)).hexdigest()

    def process(self):
        values = self.call("show", self.unit, "--property=ActiveState,SubState,MainPID").decode()
        values = dict(line.split("=", 1) for line in values.splitlines() if "=" in line)
        return values

    def stopped(self):
        values = self.process()
        return int(values.get("MainPID", "0")) == 0 and values.get("ActiveState") in ("inactive", "failed")

    def stop(self):
        self.call("stop", self.unit)
        require(self.stopped(), "service did not stop; binary not replaced")

    def start(self):
        self.call("start", self.unit)

    def observe(self, expected):
        values = self.process()
        require(values.get("ActiveState") == "active" and values.get("SubState") == "running", "service is not running")
        pid = int(values.get("MainPID", "0"))
        require(pid > 0, "service has no MainPID")
        proc = Path("/proc") / str(pid)
        require(proc.stat().st_uid == os.geteuid(), "running service UID changed")
        require(Path(os.readlink(proc / "exe")) == self.binary, "MainPID executable is not the exact binary")
        require(digest(proc / "exe") == expected, "running image SHA mismatch")
        args = (proc / "cmdline").read_bytes().split(b"\0")[:-1]
        args = [os.fsdecode(arg) for arg in args]
        configs = [arg.split("=", 1)[1] for arg in args if arg.startswith("--config=")]
        configs += [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == "--config"]
        # A system installation may rely on its canonical /etc default. User
        # named installations must always expose their explicit active path.
        if not configs and self.scope == "system":
            configs = ["/etc/meshharbor/config.toml"]
        require(len(configs) == 1 and Path(configs[0]).resolve() == self.config, "running config path differs")
        status = subprocess.run([str(self.binary), "cli", "status", "--json"],
                                capture_output=True, timeout=3)
        require(status.returncode == 0, "LocalAPI status unavailable")
        status = json.loads(status.stdout)
        with open(self.config, "rb") as source:
            config = tomllib.load(source)
        validate_status(status, pid, self.config, config, self.scope)
        return pid

    def ready(self, expected):
        last = "no observation"
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                return self.observe(expected)
            except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
                last = str(error)
                time.sleep(0.25)
        raise RuntimeError("activation verification failed: " + last)


def guard(manifest, service):
    require(config_state(manifest["config"])[0] == manifest["config_semantic_sha"],
            "protected config semantics changed (not overwritten)")
    require(sidecars(manifest["config"]) == manifest["sidecars"], "invitation sidecars changed (not overwritten)")
    require(service.fingerprint() == manifest["unit_sha"], "service definition changed (not overwritten)")
    require(file_metadata(manifest["binary"]) == manifest["metadata"],
            "binary ownership/permissions/xattrs changed (not overwritten)")


def library_snapshot(source, binary, directory):
    if not source:
        return []
    source = Path(source)
    require(source.is_absolute() and source.resolve() == source and source.is_dir(), "invalid library source")
    dest = binary.parent.parent / "lib/meshharbor"
    # Only the same user's relocatable installation supports this extension.
    for parent in (binary.parent.parent, dest.parent, dest):
        if parent.exists() or parent.is_symlink():
            require(parent.resolve() == parent and parent.is_dir() and parent.stat().st_uid == os.geteuid(),
                    "library directory is not owned by the service user")
        else:
            parent.mkdir(mode=0o755)
    saved = directory / "libraries"
    saved.mkdir(mode=0o700)
    rows = []
    for src in sorted(source.iterdir()):
        regular(src)
        require(".so" in src.name and src.name not in (".", ".."), "unexpected library payload")
        dst = dest / src.name
        old = digest(regular(dst)) if dst.exists() or dst.is_symlink() else None
        metadata = file_metadata(dst) if old else dict(uid=os.geteuid(), gid=os.getegid(), mode=0o644, xattrs={})
        require(metadata["uid"] == os.geteuid(), "library belongs to another account")
        row = dict(name=src.name, path=str(dst), old_sha=old, new_sha=digest(src), metadata=metadata)
        shutil.copyfile(src, saved / (src.name + ".new"))
        if old:
            shutil.copyfile(dst, saved / (src.name + ".old"))
        rows.append(row)
    return rows


def library_guard(manifest, phase="either"):
    for row in manifest.get("libraries", []):
        path = Path(row["path"])
        actual = digest(regular(path)) if path.exists() or path.is_symlink() else None
        expected = [row[phase + "_sha"]] if phase in ("old", "new") else [row["old_sha"], row["new_sha"]]
        require(actual in expected, "library has unrecorded bytes; manual recovery required")
        if actual is not None:
            require(file_metadata(path) == row["metadata"], "library metadata changed; refusing overwrite")


def library_place(directory, manifest, phase):
    library_guard(manifest)
    for row in manifest.get("libraries", []):
        # Recheck immediately before each mutation; no other writer is locked out.
        library_guard(manifest)
        target = Path(row["path"])
        expected = row[phase + "_sha"]
        if expected is None:
            if target.exists():
                target.unlink()
                sync_directory(target.parent)
        else:
            source = directory / "libraries" / (row["name"] + (".old" if phase == "old" else ".new"))
            same(source, expected, "saved library")
            atomic_copy(source, target, row["metadata"])
    library_guard(manifest, phase)


def restore(directory, manifest, service):
    service.ensure_outside()
    same(directory / "baseline.bin", manifest["old_sha"], "baseline backup")
    guard(manifest, service)
    require(digest(regular(manifest["binary"])) in (manifest["old_sha"], manifest["new_sha"]),
            "current binary is neither recorded version; refusing overwrite")
    library_guard(manifest)
    service.stop()
    guard(manifest, service)
    library_guard(manifest)
    # stop may run arbitrary unit hooks; another updater does not hold our
    # cooperative lock. Recheck bytes immediately before replacing them.
    require(digest(regular(manifest["binary"])) in (manifest["old_sha"], manifest["new_sha"]),
            "binary changed during stop; manual recovery required, refusing overwrite")
    library_place(directory, manifest, "old")
    atomic_copy(directory / "baseline.bin", manifest["binary"], manifest["metadata"])
    same(manifest["binary"], manifest["old_sha"], "restored binary")
    service.start()
    pid = service.ready(manifest["old_sha"])
    guard(manifest, service)
    library_guard(manifest, "old")
    return pid


def apply(args, service=None, validate=checked_paths):
    binary, _ = validate(args.scope, args.binary, args.config)
    with target_lock(binary):
        return _apply(args, service, validate)


def _apply(args, service=None, validate=checked_paths):
    binary, config = validate(args.scope, args.binary, args.config)
    candidate = regular(args.candidate)
    require(candidate != binary, "candidate must be a separate file")
    for path, expected, label in ((binary, args.old_sha, "old binary"), (candidate, args.new_sha, "candidate"), (config, args.config_sha, "config")):
        same(path, expected, label)
    require(args.old_sha != args.new_sha, "candidate is unchanged")
    service = service or Systemd(args.scope, binary, config)
    service.ensure_outside()
    old_pid = service.observe(args.old_sha)
    unit_sha = service.fingerprint()
    semantic_sha, auto_update = config_state(config)
    invitation_files = sidecars(config)
    directory = Path(args.transaction)
    require(directory.is_absolute() and directory.parent.resolve() == directory.parent, "transaction needs absolute non-symlink parent")
    directory.mkdir(mode=0o700)  # exclusive: never reuse a transaction
    with open(directory / "lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        manifest = dict(scope=args.scope, binary=str(binary), config=str(config), old_sha=args.old_sha,
                        new_sha=args.new_sha, config_sha=args.config_sha, unit_sha=unit_sha,
                        config_semantic_sha=semantic_sha, auto_update_configured=auto_update,
                        sidecars=invitation_files,
                        metadata=file_metadata(binary))
        shutil.copy2(binary, directory / "baseline.bin")
        shutil.copyfile(config, directory / "baseline.config")
        shutil.copyfile(candidate, directory / "candidate.bin")
        for name, sha in invitation_files.items():
            if sha is not None:
                shutil.copyfile(config.parent / name, directory / ("baseline." + name))
                same(directory / ("baseline." + name), sha, "invitation backup")
        same(directory / "baseline.bin", args.old_sha, "copied baseline")
        same(directory / "baseline.config", args.config_sha, "copied config")
        same(directory / "candidate.bin", args.new_sha, "copied candidate")
        manifest["libraries"] = library_snapshot(getattr(args, "library_source", None), binary, directory)
        manifest["parser_dependency"] = bundle_parser(directory)
        write_json(directory / "manifest.json", manifest)
        shutil.copyfile(__file__, directory / "upgrade.py")
        rollback = directory / "ROLLBACK.sh"
        import shlex
        dependency = manifest["parser_dependency"]
        parser_setup = ""
        if dependency:
            # Validate bytes before Python can execute imports from the wheel.
            parser_setup = ("printf '%s  %s\\n' " + shlex.quote(dependency["sha256"]) + ' '
                            + shlex.quote(dependency["file"])
                            + ' | (cd "$here" && sha256sum --status -c -)\n'
                            + 'export PYTHONPATH="$here/' + dependency["file"] + '"\n'
                            + 'export PYTHONNOUSERSITE=1\n')
        rollback.write_text('#!/bin/sh\nset -eu\nhere=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
                            + parser_setup + 'exec ' + shlex.quote(sys.executable)
                            + ' "$here/upgrade.py" rollback --transaction "$here"\n')
        rollback.chmod(0o700)
        # Recovery material must reach disk BEFORE stopping the original.
        for saved in directory.rglob("*"):
            if not saved.is_file():
                continue
            with open(saved, "rb") as persisted:
                os.fsync(persisted.fileno())
        sync_directory(directory)
        sync_directory(directory.parent)
        result = dict(old_pid=old_pid, state="prepared", auto_update_configured=auto_update,
                      note="Existing automatic checks are unchanged; this script never queries or publishes a feed")
        write_json(directory / "result.json", result)
        try:
            guard(manifest, service)
            library_guard(manifest, "old")
            service.stop()
            guard(manifest, service)
            library_guard(manifest, "old")
            same(binary, args.old_sha, "old binary after stop")
            library_place(directory, manifest, "new")
            atomic_copy(directory / "candidate.bin", binary, manifest["metadata"])
            same(binary, args.new_sha, "installed binary")
            service.start()
            new_pid = service.ready(args.new_sha)
            require(new_pid != old_pid, "replacement did not produce a new PID")
            guard(manifest, service)
            library_guard(manifest, "new")
            result.update(state="activated", new_pid=new_pid, config_after_sha=digest(config),
                          config_semantics_unchanged=True)
        except Exception as error:
            result.update(state="failed", error=str(error))
            try:
                result.update(rollback_pid=restore(directory, manifest, service), state="rolled_back")
            except Exception as recovery:
                result.update(state="recovery_required", recovery_error=str(recovery))
            write_json(directory / "result.json", result)
            raise RuntimeError("upgrade failed; " + result["state"] + "; inspect private result.json") from error
        write_json(directory / "result.json", result)
    return result


def rollback(args, service=None, validate=checked_paths):
    directory = Path(args.transaction)
    require(directory.is_absolute() and directory.resolve() == directory, "invalid transaction path")
    info = directory.stat()
    require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            "transaction must be private and owned by operator")
    manifest = json.loads((directory / "manifest.json").read_text())
    binary, _ = validate(manifest["scope"], manifest["binary"], manifest["config"])
    with target_lock(binary):
        return _rollback(args, service, validate)


def _rollback(args, service=None, validate=checked_paths):
    directory = Path(args.transaction)
    require(directory.is_absolute() and directory.resolve() == directory, "invalid transaction path")
    st = directory.stat()
    require(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700, "transaction must be private and owned by operator")
    with open(directory / "lock", "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        manifest = json.loads((directory / "manifest.json").read_text())
        binary, config = validate(manifest["scope"], manifest["binary"], manifest["config"])
        service = service or Systemd(manifest["scope"], binary, config)
        pid = restore(directory, manifest, service)
        result = dict(state="rolled_back", rollback_pid=pid)
        write_json(directory / "rollback-result.json", result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    install = commands.add_parser("apply")
    install.add_argument("--scope", choices=("user", "system"), required=True)
    for name in ("binary", "config", "candidate", "old-sha", "new-sha", "config-sha", "transaction"):
        install.add_argument("--" + name, required=True)
    install.add_argument("--library-source")
    undo = commands.add_parser("rollback")
    undo.add_argument("--transaction", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(apply(args) if args.action == "apply" else rollback(args)))
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
