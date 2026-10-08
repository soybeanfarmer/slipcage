"""Offline tests: KVM capability checks, disposable boot design and offsite opt-in."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "slipcage-kvm-probe.py"
spec = importlib.util.spec_from_file_location("slipcage_kvm_probe", MODULE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def available():
    return {"process_can_open_kvm": True, "qemu_binary_available": True}


class ReadinessTests(unittest.TestCase):
    def test_qmp_requires_explicit_true_status_not_merely_greeting(self):
        ok = '{"QMP":{"version":{}}}\n' + (
            '{"return":{},"id":"enable"}\n'
            '{"return":{"enabled":true,"present":true},"id":"inspect-kvm"}\n'
            '{"return":{},"id":"exit"}\n'
        )
        self.assertTrue(probe.parse_kvm_status(ok))
        for text in [
            '{"QMP":{"version":{}}}', "",
            '{"return":{"present":true,"enabled":false},"id":"inspect-kvm"}',
            '{"return":{"present":true,"enabled":"true"},"id":"inspect-kvm"}',
            '{"error":{"class":"GenericError"},"id":"inspect-kvm"}',
        ]:
            self.assertFalse(probe.parse_kvm_status(text))

    def test_qmp_probe_has_no_disk_network_or_guest_execution(self):
        with patch.object(probe, "inspect", return_value=available()):
            def runner(cmd, **kwargs):
                self.assertIn("q35,accel=kvm", cmd)
                self.assertIn("-nic", cmd)
                self.assertEqual(cmd[cmd.index("-nic") + 1], "none")
                self.assertIn("-S", cmd)
                self.assertNotIn("-drive", cmd)
                self.assertNotIn("-kernel", cmd)
                self.assertEqual(kwargs["timeout"], 15)
                self.assertIn('"execute":"query-kvm"', kwargs["input"])
                return Mock(returncode=0, stdout=(
                    '{"return":{},"id":"enable"}\n'
                    '{"return":{"present":true,"enabled":true},"id":"inspect-kvm"}\n'
                    '{"return":{},"id":"exit"}\n'), stderr="")
            self.assertTrue(probe.smoke(runner=runner)["kvm_initialized"])

    def test_qmp_fails_closed_without_open_kvm(self):
        with patch.object(probe, "inspect", return_value={
            "process_can_open_kvm": False, "qemu_binary_available": True
        }):
            self.assertFalse(probe.smoke(runner=lambda *_a, **_k: self.fail())["kvm_initialized"])

    def test_guest_boot_is_diskless_networkless_and_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            kernel = Path(d) / "vmlinuz"
            initrd = Path(d) / "microguest.cpio.gz"
            kernel.write_bytes(b"dummy test kernel")
            initrd.write_bytes(b"dummy test initramfs")
            def runner(cmd, **kwargs):
                self.assertIn("q35,accel=kvm", cmd)
                self.assertIn("-nic", cmd)
                self.assertEqual(cmd[cmd.index("-nic") + 1], "none")
                for forbidden in ["-drive", "-hda", "-hdb", "-cdrom", "-virtfs", "-netdev"]:
                    self.assertNotIn(forbidden, cmd)
                self.assertIn("-kernel", cmd)
                self.assertIn("-initrd", cmd)
                self.assertEqual(kwargs["timeout"], 75)
                return Mock(returncode=0,
                            stdout="boot\nSLIPCAGE_MICROGUEST_OK\npoweroff\n", stderr="")
            with patch.object(probe, "inspect", return_value=available()):
                result = probe.boot_guest(runner=runner, kernel_path=kernel,
                                          initrd_path=initrd)
            self.assertTrue(result["guest_booted"])
            self.assertFalse(result["persistent_guest_disk"])
            self.assertEqual(result["network"], "disabled")

    def test_guest_requires_marker_and_clean_shutdown(self):
        with tempfile.TemporaryDirectory() as d:
            kernel, initrd = Path(d) / "kernel", Path(d) / "initramfs"
            kernel.touch()
            initrd.touch()
            with patch.object(probe, "inspect", return_value=available()):
                for code, output in [(0, "ordinary boot"), (1, probe.BOOT_MARKER)]:
                    result = probe.boot_guest(runner=lambda *_args, **_kwargs:
                        Mock(returncode=code, stdout=output, stderr=""),
                        kernel_path=kernel, initrd_path=initrd)
                    self.assertFalse(result["guest_booted"])

    def test_systemd_probe_units_are_manual_and_resource_bounded(self):
        for name in ("slipcage-kvm-probe.service", "slipcage-kvm-boot.service"):
            text = (ROOT / "systemd" / name).read_text()
            self.assertIn("User=slipcage-vmprobe", text)
            self.assertIn("SupplementaryGroups=kvm", text)
            self.assertIn("PrivateNetwork=yes", text)
            self.assertIn("DeviceAllow=/dev/kvm rw", text)
            self.assertIn("MemoryMax=", text)
            self.assertIn("CPUQuota=100%", text)
            self.assertIn("TimeoutStartSec=", text)
            self.assertNotIn("WantedBy=", text)
        self.assertEqual(
            (ROOT / "systemd" / "slipcage-kvm-boot.service").read_text().count(
                "ExecStart="), 1)

    def test_offsite_uses_remote_repo_and_timer_is_not_enabled_by_playbook(self):
        service = (ROOT / "systemd" / "slipcage-offsite-backup.service").read_text()
        playbook = (ROOT / "playbooks" / "site.yml").read_text()
        script = ROOT / "scripts" / "slipcage-offsite-backup.sh"
        self.assertIn("ConditionPathExists=/etc/slipcage/offsite.env", service)
        self.assertIn("EnvironmentFile=/etc/slipcage/offsite.env", service)
        self.assertNotIn("enabled: true", playbook.split(
            "- name: Install disabled-by-default encrypted backup timer")[1].split(
            "- name: Release deployment maintenance")[0])
        process = subprocess.run(["bash", str(script)], capture_output=True,
                                  text=True, env={"RESTIC_REPOSITORY": "/tmp/not-remote",
                                                  "RESTIC_PASSWORD_FILE": "/tmp/fake"},
                                  timeout=5)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("Refusing local", process.stderr)

    def test_microguest_init_has_no_external_payload(self):
        source = (ROOT / "scripts" / "build-microguest.sh").read_text()
        self.assertIn("SLIPCAGE_MICROGUEST_OK", source)
        self.assertIn("poweroff -f", source)
        self.assertNotIn("curl ", source)
        self.assertNotIn("wget ", source)


if __name__ == "__main__":
    unittest.main()
