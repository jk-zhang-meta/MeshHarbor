#!/usr/bin/env python3
"""Isolated filesystem/service fixtures. Never contacts systemd or the network."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import shutil
import sys
import textwrap
import subprocess
import tempfile
import unittest
from unittest import mock
import types

spec = importlib.util.spec_from_file_location("upgrade", Path(__file__).with_name("linux-inplace-upgrade.py"))
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


class Service:
    def __init__(self, binary, config):
        self.binary, self.config = binary, config
        self.pid = 100
        self.active = True
        self.calls = []
        self.unit = "fixture-definition"
        self.fail_new = False
        self.mutate = None
        self.old = upgrade.digest(binary)

    def ensure_outside(self):
        pass

    def fingerprint(self):
        return self.unit

    def observe(self, expected):
        upgrade.require(self.active, "fixture stopped")
        upgrade.same(self.binary, expected, "fixture running image")
        return self.pid

    ready = observe

    def stop(self):
        self.calls.append("stop")
        self.active = False
        # The real daemon records a clean shutdown, even on unchanged versions.
        self.config.write_text(self.config.read_text().replace("last_run_unhealthy = true", "last_run_unhealthy = false"))

    def start(self):
        self.calls.append("start")
        if self.fail_new and upgrade.digest(self.binary) != self.old:
            raise RuntimeError("fixture candidate cannot start")
        self.active = True
        self.pid += 1
        self.config.write_text(self.config.read_text().replace("last_run_unhealthy = false", "last_run_unhealthy = true"))
        if self.mutate:
            self.mutate()


def fixture_paths(scope, binary, config):
    # Explicit in-process injection ONLY. Production CLI exposes no fixture
    # switch and uses exact Linux path/owner gates and real Systemd.
    return upgrade.regular(binary), upgrade.regular(config)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        # These existing file-transaction fixtures execute real shell scripts.
        # CPU admission is tested independently below, without this mock.
        patcher = mock.patch.object(upgrade, "require_candidate_architecture")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.binary = self.root / "meshharbord"
        self.binary.write_bytes(b'#!/bin/sh\nprintf "baseline:%s\\n" "$1"\n')
        self.binary.chmod(0o751)
        self.candidate = self.root / "candidate"
        self.candidate.write_bytes(b'#!/bin/sh\nprintf "modified:%s\\n" "$1"\n')
        self.config = self.root / "config.toml"
        self.config.write_text('agent_id = "fixture-id"\nagent_token = "fixture-only"\nssh_enabled = false\nauto_update = true\nlast_run_unhealthy = false\n[[orgs]]\nagent_id = "other-org"\n')
        self.args = argparse.Namespace(scope="user", binary=str(self.binary), config=str(self.config),
            candidate=str(self.candidate), old_sha=upgrade.digest(self.binary), new_sha=upgrade.digest(self.candidate),
            config_sha=upgrade.digest(self.config), transaction=str(self.root / "transaction"))
        self.service = Service(self.binary, self.config)

    def apply(self):
        return upgrade.apply(self.args, self.service, fixture_paths)

    def rollback(self):
        return upgrade.rollback(self.args, self.service, fixture_paths)

    def with_libraries(self):
        bindir = self.root / "bin"
        bindir.mkdir()
        original = self.binary
        self.binary = bindir / "meshharbord"
        original.rename(self.binary)
        self.args.binary = str(self.binary)
        self.service.binary = self.binary
        self.libsrc = self.root / "payload-libs"
        self.libsrc.mkdir()
        (self.libsrc / "libcodec.so.1").write_bytes(b"new-codec")
        (self.libsrc / "libnew.so.1").write_bytes(b"added-codec")
        self.libdest = self.root / "lib/meshharbor"
        self.libdest.mkdir(parents=True)
        (self.libdest / "libcodec.so.1").write_bytes(b"old-codec")
        (self.libdest / "unrelated.so.1").write_bytes(b"unrelated")
        self.args.library_source = str(self.libsrc)

    def test_library_set_activation_and_rollback_preserve_unrelated(self):
        self.with_libraries()
        self.apply()
        self.assertEqual((self.libdest / "libcodec.so.1").read_bytes(), b"new-codec")
        self.assertTrue((self.libdest / "libnew.so.1").exists())
        self.rollback()
        self.assertEqual((self.libdest / "libcodec.so.1").read_bytes(), b"old-codec")
        self.assertFalse((self.libdest / "libnew.so.1").exists())
        self.assertEqual((self.libdest / "unrelated.so.1").read_bytes(), b"unrelated")

    def test_library_failure_restores_complete_previous_set(self):
        self.with_libraries()
        self.service.fail_new = True
        with self.assertRaisesRegex(RuntimeError, "rolled_back"):
            self.apply()
        self.assertEqual((self.libdest / "libcodec.so.1").read_bytes(), b"old-codec")
        self.assertFalse((self.libdest / "libnew.so.1").exists())
        self.assertEqual(upgrade.digest(self.binary), self.args.old_sha)

    def test_library_partial_write_failure_restores_binaries_and_libraries(self):
        self.with_libraries()
        original = upgrade.atomic_copy
        failed = False
        def fail_once(source, dest, metadata):
            nonlocal failed
            if str(source).endswith("libnew.so.1.new") and not failed:
                failed = True
                raise OSError("injected disk failure")
            return original(source, dest, metadata)
        with mock.patch.object(upgrade, "atomic_copy", side_effect=fail_once):
            with self.assertRaisesRegex(RuntimeError, "rolled_back"):
                self.apply()
        self.assertEqual((self.libdest / "libcodec.so.1").read_bytes(), b"old-codec")
        self.assertFalse((self.libdest / "libnew.so.1").exists())
        self.assertEqual(upgrade.digest(self.binary), self.args.old_sha)

    def test_library_third_state_during_stop_refuses_overwrite(self):
        self.with_libraries()
        stop = self.service.stop
        def changed():
            stop()
            (self.libdest / "libcodec.so.1").write_bytes(b"third-party")
        self.service.stop = changed
        with self.assertRaisesRegex(RuntimeError, "recovery_required"):
            self.apply()
        self.assertEqual((self.libdest / "libcodec.so.1").read_bytes(), b"third-party")
        self.assertEqual(upgrade.digest(self.binary), self.args.old_sha)

    def test_apply_then_independent_frozen_rollback_preserves_scope_identity_and_mode(self):
        before = upgrade.config_state(self.config)[0]
        baseline = subprocess.check_output([str(self.binary), "same-input"], text=True).strip()
        result = self.apply()
        self.assertEqual(result["state"], "activated")
        self.assertEqual(upgrade.digest(self.binary), self.args.new_sha)
        modified = subprocess.check_output([str(self.binary), "same-input"], text=True).strip()
        self.assertEqual(upgrade.config_state(self.config)[0], before)
        tx = Path(self.args.transaction)
        self.assertEqual(stat.S_IMODE(tx.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.binary.stat().st_mode), 0o751)
        subprocess.run(["sh", "-n", str(tx / "ROLLBACK.sh")], check=True)
        # Load the transaction's frozen implementation, not the repository.
        frozen_spec = importlib.util.spec_from_file_location("frozen", tx / "upgrade.py")
        frozen = importlib.util.module_from_spec(frozen_spec)
        frozen_spec.loader.exec_module(frozen)
        self.assertEqual(frozen.rollback(self.args, self.service, fixture_paths)["state"], "rolled_back")
        self.assertEqual(upgrade.digest(self.binary), self.args.old_sha)
        self.assertEqual(upgrade.config_state(self.config)[0], before)
        restored = subprocess.check_output([str(self.binary), "same-input"], text=True).strip()
        self.assertEqual((baseline, modified, restored), ("baseline:same-input", "modified:same-input", "baseline:same-input"))
        print("same-input executable oracle:", baseline, "->", modified, "->", restored)
        self.assertEqual(self.service.calls, ["stop", "start", "stop", "start"])

    def test_candidate_failure_restores_pristine_binary_and_existing_service(self):
        self.service.fail_new = True
        with self.assertRaisesRegex(RuntimeError, "rolled_back"):
            self.apply()
        self.assertEqual(upgrade.digest(self.binary), self.args.old_sha)
        self.assertTrue(self.service.active)
        self.assertEqual(json.loads((Path(self.args.transaction) / "result.json").read_text())["state"], "rolled_back")

    def test_all_sha_mismatches_refuse_before_stop(self):
        for field in ("old_sha", "new_sha", "config_sha"):
            old = getattr(self.args, field)
            setattr(self.args, field, "0" * 64)
            with self.assertRaisesRegex(RuntimeError, "SHA mismatch"):
                self.apply()
            setattr(self.args, field, old)
        self.assertEqual(self.service.calls, [])
        self.assertFalse(Path(self.args.transaction).exists())

    def test_runtime_bookkeeping_allowed_but_protected_change_never_overwritten(self):
        self.service.mutate = lambda: self.config.write_text(self.config.read_text().replace('"fixture-id"', '"changed-by-other-writer"'))
        with self.assertRaisesRegex(RuntimeError, "recovery_required"):
            self.apply()
        self.assertIn("changed-by-other-writer", self.config.read_text())
        self.assertEqual(upgrade.digest(self.binary), self.args.new_sha)
        self.assertEqual(self.service.calls, ["stop", "start"])

    def test_rollback_refuses_unknown_binary_or_service_change(self):
        self.apply()
        self.binary.write_bytes(b"unrelated external update")
        with self.assertRaisesRegex(RuntimeError, "neither recorded"):
            self.rollback()
        self.assertEqual(self.binary.read_bytes(), b"unrelated external update")
        self.binary.write_bytes(self.candidate.read_bytes())
        self.service.unit = "changed definition"
        with self.assertRaisesRegex(RuntimeError, "service definition"):
            self.rollback()

    def test_invitation_sidecar_change_refuses_rollback_without_touching_it(self):
        marker = self.root / "temporary.json"
        marker.write_text('{"fixture":"invitation"}')
        self.apply()
        marker.write_text('{"fixture":"changed"}')
        with self.assertRaisesRegex(RuntimeError, "invitation sidecars"):
            self.rollback()
        self.assertEqual(marker.read_text(), '{"fixture":"changed"}')

    def test_symlink_and_existing_transaction_rejected(self):
        linked = self.root / "link"
        linked.symlink_to(self.candidate)
        self.args.candidate = str(linked)
        with self.assertRaisesRegex(RuntimeError, "non-symlink"):
            self.apply()
        self.args.candidate = str(self.candidate)
        Path(self.args.transaction).mkdir()
        with self.assertRaises(FileExistsError):
            self.apply()
        self.assertEqual(self.service.calls, [])

    def test_semantic_parse_preserves_all_nonruntime_fields(self):
        original = upgrade.config_state(self.config)[0]
        self.config.write_text(self.config.read_text() + '\n')
        self.assertEqual(upgrade.config_state(self.config)[0], original)
        self.config.write_text(self.config.read_text().replace("ssh_enabled = false", "ssh_enabled = true"))
        self.assertNotEqual(upgrade.config_state(self.config)[0], original)

    def test_ephemeral_is_refused_before_stop(self):
        self.config.write_text('ephemeral = true\n' + self.config.read_text())
        self.args.config_sha = upgrade.digest(self.config)
        with self.assertRaisesRegex(RuntimeError, "ephemeral"):
            self.apply()
        self.assertEqual(self.service.calls, [])

    def test_rollback_stop_hook_third_binary_is_not_overwritten(self):
        self.apply()
        stop = self.service.stop
        def third_writer_during_stop():
            stop()
            self.binary.write_bytes(b"third-party executable with preserved metadata")
        self.service.stop = third_writer_during_stop
        with self.assertRaisesRegex(RuntimeError, "manual recovery required"):
            self.rollback()
        self.assertEqual(self.binary.read_bytes(), b"third-party executable with preserved metadata")
        self.assertFalse(self.service.active)
        self.assertEqual(stat.S_IMODE(self.binary.stat().st_mode), 0o751)

    @unittest.skipUnless(os.environ.get("TOMLI_TEST_WHEEL"), "set TOMLI_TEST_WHEEL to the verified official wheel")
    def test_bundled_wheel_rollback_without_original_wheel_or_pythonpath(self):
        source = self.root / upgrade.TOMLI_WHEEL
        shutil.copyfile(os.environ["TOMLI_TEST_WHEEL"], source)
        upgrade.same(source, upgrade.TOMLI_SHA256, "test wheel")
        driver = self.root / "driver.py"
        wrapper = self.root / "fixture-python"
        driver.write_text(textwrap.dedent(r"""
            import argparse,importlib.util,json,os,pathlib,sys
            sys.modules['tomllib']=None  # Python 3.10 compatibility branch
            mode, script, tx = sys.argv[1:4]
            spec=importlib.util.spec_from_file_location('frozen_upgrade',script)
            m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
            m.require_candidate_architecture = lambda candidate: None  # shell-only parser/recovery fixture
            root=pathlib.Path(tx).parent
            binary=root/'meshharbord'; config=root/'config.toml'
            class FixtureService:
                def ensure_outside(self): pass
                def fingerprint(self): return 'fixture'
                def observe(self,sha): m.same(binary,sha,'fixture binary'); return 100
                def ready(self,sha): m.same(binary,sha,'fixture binary'); return 101
                def stop(self): pass
                def start(self): pass
            validate=lambda scope,b,c:(m.regular(b),m.regular(c))
            if mode=='apply':
                args=argparse.Namespace(scope='user',binary=str(binary),config=str(config),candidate=str(root/'candidate'),old_sha=m.digest(binary),new_sha=m.digest(root/'candidate'),config_sha=m.digest(config),transaction=tx)
                sys.executable=str(root/'fixture-python')
                m.apply(args,FixtureService(),validate)
            else:
                assert m.tomllib.__file__.startswith(tx+'/tomli-2.2.1-py3-none-any.whl/'),m.tomllib.__file__
                m.rollback(argparse.Namespace(transaction=tx),FixtureService(),validate)
                print('standalone rollback imported bundled wheel; original wheel absent; inherited PYTHONPATH absent')
        """))
        # The shell uses this test-only interpreter adapter rather than host
        # systemd. It still executes the generated ROLLBACK.sh verbatim.
        import shlex
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable)
                           + ' -B ' + shlex.quote(str(driver))
                           + ' rollback "$1" "$4"\n')
        wrapper.chmod(0o700)
        env = dict(os.environ, PYTHONPATH=str(source), PYTHONDONTWRITEBYTECODE="1")
        subprocess.run([sys.executable, "-B", str(driver), "apply", str(Path(upgrade.__file__)), self.args.transaction], env=env, check=True)
        source.unlink()  # only our fixture copy, never the official artifact
        env.pop("PYTHONPATH", None)
        tx=Path(self.args.transaction)
        result=subprocess.run([str(tx/'ROLLBACK.sh')],env=env,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('original wheel absent',result.stdout)
        self.assertEqual(upgrade.digest(self.binary),self.args.old_sha)
        print(result.stdout.strip())
        # A changed bundled wheel is rejected by the shell before Python import.
        (tx/upgrade.TOMLI_WHEEL).write_bytes(b'tampered dependency')
        result=subprocess.run([str(tx/'ROLLBACK.sh')],env=env,capture_output=True)
        self.assertNotEqual(result.returncode,0)

    def test_unbundled_tomli_source_is_refused_without_downloading(self):
        foreign = types.SimpleNamespace(__name__="tomli", __version__="2.2.1",
                                        __file__="/unreviewed/site-packages/tomli/__init__.py")
        with mock.patch.object(upgrade, "tomllib", foreign):
            with self.assertRaisesRegex(RuntimeError, "reviewed pinned pure wheel"):
                upgrade.bundle_parser(self.root)

    def test_per_target_lock_excludes_overlapping_transactions(self):
        with upgrade.target_lock(self.binary):
            with self.assertRaises(BlockingIOError):
                self.apply()
        self.assertEqual(self.service.calls, [])

    def test_binary_metadata_is_preserved_and_external_chmod_blocks_rollback(self):
        os.setxattr(self.binary, "user.meshharbor-fixture", b"metadata")
        self.apply()
        self.assertEqual(os.getxattr(self.binary, "user.meshharbor-fixture"), b"metadata")
        self.binary.chmod(0o700)
        with self.assertRaisesRegex(RuntimeError, "ownership/permissions/xattrs"):
            self.rollback()
        self.assertEqual(stat.S_IMODE(self.binary.stat().st_mode), 0o700)

    def test_local_status_must_bind_pid_named_config_identity_and_scope(self):
        config = {"agent_id": "a", "tenant_id": "t"}
        good = dict(pid=123, config_path=str(self.config), node_id="a", tenant_id="t", privileged=False)
        upgrade.validate_status(good, 123, self.config, config, "user")
        for field, value in [("pid", 456), ("config_path", str(self.root / "stale.toml")),
                             ("node_id", "other"), ("tenant_id", "other"), ("privileged", True),
                             ("privileged", None)]:
            with self.assertRaises(RuntimeError):
                upgrade.validate_status(dict(good, **{field: value}), 123, self.config, config, "user")

    def test_exact_scope_commands_do_not_install_second_instance(self):
        user = upgrade.Systemd("user", self.binary, self.config)
        system = upgrade.Systemd("system", self.binary, self.config)
        self.assertEqual(user.command, ["/usr/bin/systemctl", "--user"])
        self.assertEqual(user.unit, "meshharbor.service")
        self.assertEqual(system.command, ["/usr/bin/systemctl"])
        self.assertEqual(system.unit, "meshharbord.service")
        with self.assertRaises(RuntimeError):
            upgrade.checked_paths("system", self.binary, self.config)



class ArchitectureGateTests(unittest.TestCase):
    def test_cross_arch_rejected_before_any_write_or_service_action(self):
        for host, candidate_machine in [("x86_64", 183), ("aarch64", 62)]:
            with self.subTest(host=host), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                binary, config, candidate = root / "daemon", root / "config.toml", root / "candidate"
                binary.write_bytes(b"pristine old binary")
                config.write_text('agent_id="preserved"\nssh_enabled=false\n')
                candidate.write_bytes(self.elf(candidate_machine))
                args = argparse.Namespace(scope="user", binary=str(binary), config=str(config),
                    candidate=str(candidate), transaction=str(root / "transaction"))
                service = Service(binary, config)
                before = {p.name: p.read_bytes() for p in root.iterdir()}
                with mock.patch.object(upgrade.os, "uname", return_value=types.SimpleNamespace(machine=host)):
                    with self.assertRaisesRegex(RuntimeError, "architecture does not match"):
                        upgrade.apply(args, service, fixture_paths)
                self.assertEqual(service.calls, [])
                self.assertTrue(service.active)
                self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)

    @staticmethod
    def elf(machine):
        header = bytearray(64)
        header[:7] = b"\x7fELF\x02\x01\x01"
        header[16:18] = (3).to_bytes(2, "little")
        header[18:20] = machine.to_bytes(2, "little")
        header[20:24] = (1).to_bytes(4, "little")
        return bytes(header)

    def test_matching_elf_reaches_transaction_without_arch_mock(self):
        for host, machine in [("x86_64", 62), ("aarch64", 183)]:
            with self.subTest(host=host), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                binary, config, candidate = root / "daemon", root / "config.toml", root / "candidate"
                binary.write_bytes(self.elf(machine) + b"old")
                candidate.write_bytes(self.elf(machine) + b"new")
                config.write_text('agent_id="preserved"\nssh_enabled=false\n')
                args = argparse.Namespace(scope="user", binary=str(binary), config=str(config),
                    candidate=str(candidate), transaction=str(root / "transaction"),
                    old_sha=upgrade.digest(binary), new_sha=upgrade.digest(candidate), config_sha=upgrade.digest(config))
                service = Service(binary, config)
                with mock.patch.object(upgrade.os, "uname", return_value=types.SimpleNamespace(machine=host)):
                    result = upgrade.apply(args, service, fixture_paths)
                self.assertEqual(result["state"], "activated")
                self.assertEqual(service.calls, ["stop", "start"])

    def test_matching_architecture_passes_and_malformed_headers_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "candidate"
            for host, machine in [("x86_64", 62), ("aarch64", 183)]:
                with self.subTest(host=host), mock.patch.object(upgrade.os, "uname", return_value=types.SimpleNamespace(machine=host)):
                    candidate.write_bytes(self.elf(machine))
                    upgrade.require_candidate_architecture(candidate)
                    for bad in [b"#!/bin/sh\n", self.elf(machine)[:20], self.elf(machine).replace(b"ELF", b"BAD"), self.elf(machine)[:4] + b"\x01" + self.elf(machine)[5:]]:
                        candidate.write_bytes(bad)
                        with self.assertRaises(RuntimeError):
                            upgrade.require_candidate_architecture(candidate)
            with mock.patch.object(upgrade.os, "uname", return_value=types.SimpleNamespace(machine="unknown")):
                with self.assertRaisesRegex(RuntimeError, "unsupported Linux host"):
                    upgrade.require_candidate_architecture(candidate)

if __name__ == "__main__":
    unittest.main(verbosity=2)
