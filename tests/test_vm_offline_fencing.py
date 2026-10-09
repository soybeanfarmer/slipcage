"""SC-13b10: durable but strictly OFFLINE fencing identity, no VM launcher.

All records and subprocesses are restricted to test-created private roots.
"""
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from slipcage_engine.cli import main
from slipcage_engine.vm_plan import load_vm_plan, validate_vm_plan_bytes
from slipcage_engine.vm_offline_fencing import (
    API_VERSION, FencingJournalBusy, FencingJournalError, OfflineResolution,
    LOCK_NAME, inspect_offline_fencing, issue_offline_generation,
    resolve_offline_generation, _event_filename,
)

EXAMPLE = ROOT / "examples" / "vm-plans" / "k3s-synthetic-design.json"
CHILD_HOLD = """
import sys
from slipcage_engine.vm_offline_fencing import _locked
with _locked(sys.argv[1], create_lock=False):
    print("HELD",flush=True)
    sys.stdin.readline()
"""
CHILD_CRASH = """
import os
import sys
from slipcage_engine.vm_offline_fencing import issue_offline_generation
from slipcage_engine.vm_plan import load_vm_plan
x=issue_offline_generation(sys.argv[1],load_vm_plan(sys.argv[2]),"baseline",0)
print(x.generation, flush=True)
os._exit(29)
"""


class DurableFencingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.root = self.home / "journal"
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o700)
        plan = load_vm_plan(EXAMPLE).design
        plan["provenance"]["pin_status"] = "operator_supplied_unverified"
        plan["provenance"]["note"] = "CI-only intent; no actual publisher or VM"
        plan["software"]["guest_kernel_release"] = "6.8.0-test"
        self.plan = validate_vm_plan_bytes(json.dumps(plan).encode("utf-8"))
        self.planfile = self.home / "test-plan.json"
        self.planfile.write_bytes(self.plan.canonical_json)
        self.neighbor = self.home / "keep-existing-backup.db"
        self.neighbor.write_bytes(b"KEEP_ME")

    def issue(self, attempt="baseline", expected=0):
        return issue_offline_generation(self.root, self.plan, attempt, expected)

    def resolve(self, snap, choice=OfflineResolution.ABANDONED):
        return resolve_offline_generation(
            self.root, snap.active_attempt, snap.generation,
            snap.active_record_sha256, choice,
        )

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = main(list(argv))
        return status, out.getvalue(), err.getvalue()

    def test_first_generation_persists_private_canonical_record(self):
        snap = self.issue()
        self.assertEqual(snap.generation, 1)
        self.assertEqual(snap.state, "outstanding_offline_intent")
        self.assertEqual(snap.active_attempt, "baseline")
        self.assertEqual(snap.plan_digest_sha256, self.plan.digest_sha256)
        self.assertEqual(snap.record_count, 1)
        self.assertEqual(snap, inspect_offline_fencing(self.root))
        self.assertEqual(
            set(os.listdir(self.root)), {LOCK_NAME, "generation-00000001.json"},
        )
        for path in self.root.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual((self.root / LOCK_NAME).read_bytes(), b"")
        issued = (self.root / "generation-00000001.json").read_bytes()
        self.assertEqual(snap.active_record_sha256, hashlib.sha256(issued).hexdigest())
        self.assertEqual(json.loads(issued)["execution_enabled"], False)

    def test_chain_monotonic_generation_and_duplicate_owner_refused(self):
        original = self.issue()
        retired = self.resolve(original)
        self.assertEqual(retired.generation, 1)
        self.assertIsNone(retired.active_attempt)
        self.assertEqual(retired.state, "offline_abandoned_no_guest_claim_only")
        second = self.issue("candidate", expected=1)
        self.assertEqual(second.generation, 2)
        self.assertEqual(second.active_attempt, "candidate")
        raw_1 = (self.root / "resolution-00000001.json").read_bytes()
        raw_2 = (self.root / "generation-00000002.json").read_bytes()
        self.assertEqual(json.loads(raw_2)["previous_resolution_sha256"],
                         hashlib.sha256(raw_1).hexdigest())
        self.assertEqual(inspect_offline_fencing(self.root), second)
        with self.assertRaisesRegex(FencingJournalError, "reused"):
            self.issue("baseline", expected=2)
        with self.assertRaisesRegex(FencingJournalError, "Stale expected"):
            self.issue("third", expected=1)

    def test_outstanding_blocks_new_generations_after_crash_like_abandonment(self):
        first = self.issue()
        with self.assertRaisesRegex(FencingJournalError, "unresolved"):
            self.issue("candidate", expected=1)
        self.assertEqual(inspect_offline_fencing(self.root), first)
        self.assertFalse((self.root / "generation-00000002.json").exists())

    def test_resolution_requires_exact_generation_owner_and_digest(self):
        first = self.issue()
        for name, gen, digest in (
            ("candidate", 1, first.active_record_sha256),
            ("baseline", 0, first.active_record_sha256),
            ("baseline", 1, "f"*64),
        ):
            with self.subTest(name=name, gen=gen), self.assertRaises(FencingJournalError):
                resolve_offline_generation(
                    self.root, name, gen, digest, OfflineResolution.ABANDONED,
                )
        with self.assertRaises(FencingJournalError):
            resolve_offline_generation(self.root, "baseline", 1,
                                       first.active_record_sha256, "offline_done")
        self.assertEqual(self.root.joinpath("generation-00000001.json").is_file(), True)
        self.assertFalse((self.root / "resolution-00000001.json").exists())

    def test_quarantine_is_permanent_and_no_later_generation_possible(self):
        first = self.issue()
        quarantine = self.resolve(first, OfflineResolution.QUARANTINED)
        self.assertEqual(quarantine.state, "unresolved_quarantine")
        self.assertEqual(quarantine.last_resolution, "unresolved_quarantine")
        with self.assertRaisesRegex(FencingJournalError, "quarantined"):
            self.issue("candidate", expected=1)
        with self.assertRaises(FencingJournalError):
            self.resolve(first)
        self.assertEqual(inspect_offline_fencing(self.root), quarantine)

    def test_tampered_hash_chain_or_event_does_not_become_clean(self):
        first = self.issue()
        self.resolve(first)
        second = self.issue("candidate", 1)
        record = self.root / "resolution-00000001.json"
        original = record.read_bytes()
        document = json.loads(original)
        document["resolution"] = OfflineResolution.QUARANTINED.value
        record.write_bytes(json.dumps(document, sort_keys=True, separators=(",", ":")).encode())
        with self.assertRaises(FencingJournalError):
            inspect_offline_fencing(self.root)
        self.assertTrue((self.root / "generation-00000002.json").exists())
        self.assertEqual(self.neighbor.read_bytes(), b"KEEP_ME")

    def test_unknown_and_orphan_events_fail_closed(self):
        self.issue()
        (self.root / "unowned-guest.qcow2").write_bytes(b"UNKNOWN")
        with self.assertRaisesRegex(FencingJournalError, "Unexpected"):
            inspect_offline_fencing(self.root)
        (self.root / "unowned-guest.qcow2").unlink()
        orphan = self.root / "resolution-00000002.json"
        orphan.write_bytes(b"{}")
        orphan.chmod(0o600)
        with self.assertRaises(FencingJournalError):
            inspect_offline_fencing(self.root)

    def test_interrupt_during_event_write_is_permanent_blocker(self):
        from slipcage_engine import vm_offline_fencing as module
        real = module._write_event
        def interrupted(fd, filename, record):
            if filename.startswith("generation-"):
                path_fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                  0o600, dir_fd=fd)
                with os.fdopen(path_fd, "wb") as out:
                    out.write(b"PARTIAL")
                    out.flush()
                    os.fsync(out.fileno())
                os.fsync(fd)
                raise FencingJournalError("test simulated interrupted journal publication")
            return real(fd, filename, record)
        with patch.object(module, "_write_event", side_effect=interrupted):
            with self.assertRaises(FencingJournalError):
                self.issue()
        self.assertTrue((self.root / "generation-00000001.json").exists())
        with self.assertRaises(FencingJournalError):
            inspect_offline_fencing(self.root)
        with self.assertRaises(FencingJournalError):
            self.issue("candidate")
        self.assertEqual((self.root / "generation-00000001.json").read_bytes(), b"PARTIAL")

    def test_symlink_root_and_nonprivate_root_fail_without_creation(self):
        alias = self.home / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(FencingJournalError):
            issue_offline_generation(alias, self.plan, "baseline", 0)
        self.root.chmod(0o755)
        with self.assertRaises(FencingJournalError):
            self.issue()
        self.root.chmod(0o700)
        self.assertEqual(set(os.listdir(self.root)), set())

    def test_symlink_record_modes_hardlinks_and_extra_entries_rejected(self):
        self.issue()
        event = self.root / "generation-00000001.json"
        event.chmod(0o644)
        with self.assertRaises(FencingJournalError):
            inspect_offline_fencing(self.root)
        event.chmod(0o600)
        extra = self.home / "hardlink"
        os.link(event, extra)
        with self.assertRaises(FencingJournalError):
            inspect_offline_fencing(self.root)
        extra.unlink()
        saved = self.home / "event-copy"
        saved.write_bytes(event.read_bytes())
        event.unlink()
        event.symlink_to(saved)
        with self.assertRaises(FencingJournalError):
            inspect_offline_fencing(self.root)

    def test_invalid_lock_inode_symlink_and_content_refused(self):
        self.issue()
        lock = self.root / LOCK_NAME
        lock.write_bytes(b"changed")
        with self.assertRaises(FencingJournalError):
            inspect_offline_fencing(self.root)
        lock.unlink()
        lock.symlink_to(self.neighbor)
        with self.assertRaises(FencingJournalError):
            inspect_offline_fencing(self.root)
        self.assertEqual(self.neighbor.read_bytes(), b"KEEP_ME")

    def test_cross_process_flock_contention_returns_busy(self):
        self.issue()
        process = subprocess.Popen(
            [sys.executable, "-c", CHILD_HOLD, str(self.root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        try:
            self.assertEqual(process.stdout.readline().strip(), "HELD")
            with self.assertRaises(FencingJournalBusy):
                inspect_offline_fencing(self.root)
            code, out, err = self.cli("inspect-offline-vm-generations", str(self.root), "--json")
            self.assertEqual(code, 5)
            self.assertEqual(out, "")
            self.assertIn("holds", err)
            rest, serr = process.communicate(input="\n", timeout=8)
            self.assertEqual((process.returncode, rest, serr), (0, "", ""))
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=8)
        self.assertEqual(inspect_offline_fencing(self.root).generation, 1)

    def test_abrupt_process_exit_does_not_resolve_outstanding_attempt(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", CHILD_CRASH, str(self.root), str(self.planfile)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            out, err = proc.communicate(timeout=8)
            self.assertEqual((proc.returncode, out.strip(), err), (29, "1", ""))
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=8)
        snap = inspect_offline_fencing(self.root)
        self.assertEqual(snap.state, "outstanding_offline_intent")
        with self.assertRaises(FencingJournalError):
            self.issue("candidate", 1)

    def test_different_roots_do_not_claim_host_global_exclusion(self):
        other = self.home / "another-journal"
        other.mkdir(mode=0o700)
        other.chmod(0o700)
        from slipcage_engine import vm_offline_fencing as module
        with module._locked(self.root, create_lock=True):
            with module._locked(other, create_lock=True):
                self.assertTrue((other / LOCK_NAME).is_file())
        self.assertNotEqual((self.root / LOCK_NAME).stat().st_ino,
                            (other / LOCK_NAME).stat().st_ino)

    def test_no_real_guest_and_no_production_data_mutation(self):
        with (
            patch.object(subprocess, "Popen", side_effect=AssertionError("QEMU")),
            patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
            patch.object(socket, "socket", side_effect=AssertionError("network")),
        ):
            report = self.issue()
            assert report.generation == 1
        for k in (
            "host_global_execution_lease", "guest_process_fenced",
            "quarantine_clearance_available", "actual_guest_cleanup_verified",
            "operator_identity_authenticated", "software_provenance_authenticated",
            "qemu_or_overlay_created", "execution_authorized",
            "host_modified_except_private_journal_files", "vm_launched",
            "lock_held_after_command",
        ):
            with self.subTest(k=k):
                self.assertFalse(report.to_dict()[k])
        self.assertEqual(self.neighbor.read_bytes(), b"KEEP_ME")
        self.assertEqual(set(os.listdir(self.root)),
                         {LOCK_NAME, "generation-00000001.json"})

    def test_cli_issue_inspect_resolve_issue_is_durable_and_nonexecuting(self):
        code, out, err = self.cli(
            "stage-offline-vm-generation", str(self.planfile), "--root", str(self.root),
            "--attempt", "baseline", "--expected-generation", "0", "--json",
        )
        self.assertEqual((code, err), (0, ""))
        first = json.loads(out)
        self.assertEqual(first["last_generation"], 1)
        self.assertEqual(first["api_version"], API_VERSION)
        self.assertEqual(first["state"], "outstanding_offline_intent")
        self.assertFalse(first["execution_authorized"])
        self.assertNotIn(str(self.home), out)
        code, out, err = self.cli(
            "resolve-offline-vm-generation", str(self.root),
            "--attempt", "baseline", "--generation", "1",
            "--issue-sha256", first["active_record_sha256"],
            "--resolution", "offline_intent_abandoned_not_vm_cleanup", "--json",
        )
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["state"], "offline_abandoned_no_guest_claim_only")
        code, out, err = self.cli(
            "stage-offline-vm-generation", str(self.planfile), "--root", str(self.root),
            "--attempt", "candidate", "--expected-generation", "1", "--json",
        )
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["last_generation"], 2)
        code, out, err = self.cli("inspect-offline-vm-generations",
                                  str(self.root), "--json")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["state"], "outstanding_offline_intent")

    def test_cli_quarantine_returns_unresolved_exit_5(self):
        first = self.issue()
        code, out, err = self.cli(
            "resolve-offline-vm-generation", str(self.root),
            "--attempt", "baseline", "--generation", "1",
            "--issue-sha256", first.active_record_sha256,
            "--resolution", "unresolved_quarantine", "--json",
        )
        self.assertEqual((code, err), (5, ""))
        self.assertEqual(json.loads(out)["state"], "unresolved_quarantine")
        self.assertEqual(self.cli("inspect-offline-vm-generations",str(self.root),"--json")[0],5)

    def test_real_commands_remain_disabled(self):
        for cmd in ("run", "compare", "report"):
            rc, out, err = self.cli(cmd)
            self.assertEqual(rc, 3)
            self.assertEqual(out, "")


if __name__ == "__main__":
    unittest.main()
