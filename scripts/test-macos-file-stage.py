#!/usr/bin/env python3
"""Native user-owned synthetic bundle fixtures; never launch GUI or launchctl."""
import copy
import getpass
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("stage", Path(__file__).with_name("macos-file-stage.py"))
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


@unittest.skipUnless(sys.platform == "darwin", "requires Apple's native ditto/codesign/renamex_np")
class FileStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = Path.home() / ".agent-work/runtime/meshharbor-personal-device-20261114/mac-file-fixtures"
        cls.runtime.mkdir(parents=True, exist_ok=True, mode=0o700)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="case-", dir=str(self.runtime))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plan = {"objects": {}}
        for version in ("old", "new"):
            parent = self.root / version
            parent.mkdir()
            program = parent / "fixture.c"
            program.write_text('#include <stdio.h>\nint main(void){puts("' + version + '");return 0;}\n')
            for role, executable in (("daemon", "meshharbord"), ("desktop", "MeshHarbor")):
                app = parent / (executable + ".app")
                (app / "Contents/MacOS").mkdir(parents=True)
                (app / "Contents/Resources").mkdir()
                with open(app / "Contents/Info.plist", "wb") as stream:
                    plistlib.dump(dict(CFBundleIdentifier="test.meshharbor.fixture." + role,
                        CFBundleName=executable, CFBundleExecutable=executable,
                        CFBundlePackageType="APPL", CFBundleVersion="1"), stream)
                subprocess.run(["/usr/bin/clang", str(program), "-o", str(app / "Contents/MacOS" / executable)], check=True, capture_output=True)
                resource = app / "Contents/Resources/example.txt"
                resource.write_text(version)
                stage.native(["/usr/bin/xattr", "-w", "com.meshharbor.fixture", "retain-xattr", str(resource)])
                subprocess.run(["/bin/chmod", "+a", "user:" + getpass.getuser() + " allow read,readattr,readextattr,readsecurity", str(resource)], check=True)
                subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(app)], check=True, capture_output=True)
            cli = parent / "mh"
            shutil.copy2(parent / "meshharbord.app/Contents/MacOS/meshharbord", cli)
            stage.native(["/usr/bin/xattr", "-w", "com.apple.ResourceFork", "fixture resource fork", str(cli)])
            os.symlink(str(self.root / "old/meshharbord.app/Contents/MacOS/meshharbord"), parent / "meshharbord")
        for role, (kind, _) in stage.TARGETS.items():
            name = {"daemon": "meshharbord.app", "desktop": "MeshHarbor.app", "cli": "mh", "daemon_link": "meshharbord"}[role]
            old, new = self.root / "old" / name, self.root / "new" / name
            self.plan["objects"][role] = dict(kind=kind, target=str(old), candidate=str(new),
                                            old_sha=stage.tree_sha(old), new_sha=stage.tree_sha(new))
        self.tx = self.root / "transaction"

    def apply(self):
        stage.apply(self.plan, self.tx, self.root)

    def verify_all(self, state):
        for item in self.plan["objects"].values():
            stage.verify(item["target"], item["kind"], item[state + "_sha"])

    def test_signed_bundles_metadata_cli_symlink_and_independent_rollback(self):
        binary = self.root / "old/meshharbord.app/Contents/MacOS/meshharbord"
        before = subprocess.check_output([str(binary)], text=True).strip()
        self.apply()
        self.verify_all("new")
        modified = subprocess.check_output([str(binary)], text=True).strip()
        # Execute the generated rollback with its frozen script, no source-tree dependency.
        refused = subprocess.run([str(self.tx / "ROLLBACK.sh")], capture_output=True)
        self.assertEqual(refused.returncode, 2, "rollback must require renewed caller quiescence assertion")
        subprocess.run([str(self.tx / "ROLLBACK.sh"), "--jobs-quiesced"], check=True, capture_output=True)
        self.verify_all("old")
        restored = subprocess.check_output([str(binary)], text=True).strip()
        self.assertEqual((before, modified, restored), ("old", "new", "old"))
        self.assertEqual(stage.native(["/usr/bin/xattr", "-p", "com.apple.ResourceFork", str(self.root / "old/mh")]).rstrip(b"\n"), b"fixture resource fork")
        print("signed fixture same-input:", before, "->", modified, "->", restored)

    def test_partial_second_swap_failure_restores_all_originals(self):
        original = stage.swap
        calls = []
        def injected(left, right):
            calls.append(str(right))
            if len(calls) == 2:
                raise OSError("fixture second exchange failed")
            return original(left, right)
        with mock.patch.object(stage, "swap", injected):
            with self.assertRaisesRegex(RuntimeError, "files_rolled_back"):
                self.apply()
        self.verify_all("old")

    def test_third_state_after_copy_is_refused_without_overwrite(self):
        self.apply()
        cli = self.root / "old/mh"
        original = stage.copy_object
        def third_writer(source, destination, kind, expected):
            original(source, destination, kind, expected)
            if source.name == "cli":
                metadata = cli.stat()
                cli.write_bytes(b"third-party bytes")
                os.utime(cli, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        with mock.patch.object(stage, "copy_object", third_writer):
            with self.assertRaises(RuntimeError):
                stage.rollback_objects(self.tx, dict(self.plan, fixture_root=str(self.root)))
        self.assertEqual(cli.read_bytes(), b"third-party bytes")

    def test_bad_candidate_signature_refuses_before_live_change(self):
        candidate = self.root / "new/meshharbord.app/Contents/Resources/example.txt"
        candidate.write_text("tampered signed resource")
        self.plan["objects"]["daemon"]["new_sha"] = stage.tree_sha(self.root / "new/meshharbord.app")
        with self.assertRaises(RuntimeError):
            self.apply()
        self.verify_all("old")

    def test_hash_drift_refused_and_transaction_cannot_be_inside_bundle(self):
        plan = copy.deepcopy(self.plan)
        plan["objects"]["daemon"]["old_sha"] = "0" * 64
        with self.assertRaises(RuntimeError):
            stage.apply(plan, self.tx, self.root)
        self.verify_all("old")
        with self.assertRaisesRegex(RuntimeError, "overlap"):
            stage.apply(self.plan, self.root / "old/meshharbord.app/backup", self.root)
        self.verify_all("old")


if __name__ == "__main__":
    unittest.main(verbosity=2)
