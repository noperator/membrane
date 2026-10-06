#!/usr/bin/env python3
"""Setup regression tests using temporary host files and fake system services."""

import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bpf_setup", SCRIPTS / "setup-bpf-lsm.py")
bpf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bpf)


class BootSetupTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.write("sys/kernel/security/lsm", "capability,yama,apparmor")
        self.write("proc/cmdline", "quiet root=/dev/vda1")
        self.write("boot/config-" + platform.release(), 'CONFIG_BPF_LSM=y\nCONFIG_LSM="landlock,lockdown,yama,apparmor"\n')
        self.grub = self.write("etc/default/grub", 'GRUB_TIMEOUT=7\nGRUB_CMDLINE_LINUX="audit=1"\nGRUB_CMDLINE_LINUX_DEFAULT="quiet splash"\n')
        self.dropin = self.root / "etc/default/grub.d/99-membrane-bpf-lsm.cfg"
        self.log = self.root / "grub-updates"
        command = self.write("bin/update-grub", '#!/bin/sh\nprintf "update\\n" >> "$GRUB_TEST_LOG"\n')
        command.chmod(0o700)
        env = patch.dict(os.environ, PATH=str(command.parent) + os.pathsep + os.environ["PATH"], GRUB_TEST_LOG=str(self.log))
        env.start()
        self.addCleanup(env.stop)

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
        return path

    def test_configure_preserves_order_and_other_grub_options(self):
        self.write("etc/default/grub.d/60-custom.cfg", 'GRUB_CMDLINE_LINUX_DEFAULT="quiet lsm=yama,landlock,apparmor console=ttyS0"\n')
        original = self.grub.read_bytes()
        self.assertEqual(bpf.configure(self.root, automatic=True), 75)
        self.assertEqual(self.grub.read_bytes(), original)
        self.assertIn("lsm=yama,landlock,apparmor,bpf", self.dropin.read_text())
        files = [self.grub, *sorted(self.dropin.parent.glob("*.cfg"))]
        effective = subprocess.check_output(["sh", "-ec", 'for file do . "$file"; done; printf "%s\\n" "$GRUB_TIMEOUT" "$GRUB_CMDLINE_LINUX $GRUB_CMDLINE_LINUX_DEFAULT"', "sh", *map(str, files)], text=True)
        self.assertIn("7\n", effective)
        self.assertIn("audit=1", effective)
        self.assertIn("console=ttyS0", effective)
        self.assertEqual(effective.count("lsm="), 1)
        before = self.dropin.stat().st_mtime_ns
        self.assertEqual(bpf.configure(self.root, automatic=True), 75)
        self.assertEqual(self.dropin.stat().st_mtime_ns, before)
        self.assertEqual(self.log.read_text(), "update\n")
        self.write("sys/kernel/security/lsm", "capability,yama,landlock,apparmor,bpf")
        self.assertEqual(bpf.configure(self.root), 0)
        self.assertEqual(bpf.configure(self.root), 0)
        self.assertEqual(self.dropin.stat().st_mtime_ns, before)
        self.assertEqual(self.log.read_text(), "update\n")

    def test_proc_config_and_cmdline_order(self):
        with gzip.open(self.root / "proc/config.gz", "wt") as stream:
            stream.write('CONFIG_BPF_LSM=y\nCONFIG_LSM="yama"\n')
        self.write("boot/config-" + platform.release(), "# CONFIG_BPF_LSM is not set\n")
        self.write("proc/cmdline", "lsm=apparmor,landlock,yama,bpf quiet")
        self.assertEqual(bpf.configure(self.root, automatic=True), 75)
        self.assertIn("lsm=apparmor,landlock,yama,bpf", self.dropin.read_text())
        self.assertNotIn("bpf,bpf", self.dropin.read_text())

    def test_corrupt_proc_config_falls_back_to_boot(self):
        self.write("proc/config.gz", "not a gzip file")
        self.assertEqual(bpf.configure(self.root, automatic=True), 75)

    def test_unsupported_does_not_change_boot_config(self):
        self.write("boot/config-" + platform.release(), "# CONFIG_BPF_LSM is not set\n")
        with self.assertRaisesRegex(RuntimeError, "does not support BPF LSM"):
            bpf.configure(self.root, automatic=True)
        self.assertFalse(self.dropin.exists())
        self.assertFalse(self.log.exists())

    def test_unknown_support_and_already_active_without_config(self):
        (self.root / "boot" / ("config-" + platform.release())).unlink()
        with self.assertRaisesRegex(RuntimeError, "Cannot determine BPF LSM support"):
            bpf.configure(self.root, automatic=True)
        self.write("sys/kernel/security/lsm", "capability,bpf")
        self.assertEqual(bpf.configure(self.root), 0)
        self.assertFalse(self.dropin.exists())
        self.assertFalse(self.log.exists())

    def test_native_consent_required(self):
        real_open = open

        def no_tty(path, *args, **kwargs):
            if str(path) == "/dev/tty":
                raise OSError("no controlling terminal")
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=no_tty):
            with self.assertRaisesRegex(RuntimeError, "Boot configuration unchanged"):
                bpf.configure(self.root)
        self.assertFalse(self.dropin.exists())
        self.assertFalse(self.log.exists())

    def test_native_consent_accepts_only_yes(self):
        real_open = open
        for answer in ("n\n", "y\n"):
            with self.subTest(answer=answer):
                def terminal(path, *args, **kwargs):
                    if str(path) == "/dev/tty":
                        return io.StringIO(answer)
                    return real_open(path, *args, **kwargs)

                with patch("builtins.open", side_effect=terminal):
                    if answer == "n\n":
                        with self.assertRaisesRegex(RuntimeError, "Boot configuration unchanged"):
                            bpf.configure(self.root)
                        self.assertFalse(self.dropin.exists())
                    else:
                        self.assertEqual(bpf.configure(self.root), 75)

    def test_unreadable_lsm_list_does_not_modify_boot(self):
        (self.root / "sys/kernel/security/lsm").unlink()
        with self.assertRaisesRegex(RuntimeError, "securityfs mount"):
            bpf.configure(self.root, automatic=True)
        self.assertFalse(self.dropin.exists())

    def test_failed_update_grub_does_not_leave_stale_reboot_marker(self):
        self.assertEqual(bpf.configure(self.root, automatic=True), 75)
        self.write("etc/default/grub.d/60-custom.cfg", 'GRUB_CMDLINE_LINUX_DEFAULT="lsm=apparmor,yama"\n')
        command = self.root / "bin/update-grub"
        command.write_text("#!/bin/sh\nexit 1\n")
        with self.assertRaises(subprocess.CalledProcessError):
            bpf.configure(self.root, automatic=True)
        self.assertFalse((self.root / "var/lib/membrane/bpf-lsm-reboot-required").exists())
        command.write_text('#!/bin/sh\nprintf "update\\n" >> "$GRUB_TEST_LOG"\n')
        self.assertEqual(bpf.configure(self.root, automatic=True), 75)
        self.assertEqual(self.log.read_text(), "update\nupdate\n")

    def test_later_grub_override_does_not_report_ready_to_reboot(self):
        custom = self.write("etc/default/grub.d/zz-custom.cfg", 'GRUB_CMDLINE_LINUX_DEFAULT="quiet lsm=yama,apparmor"\n')
        original = custom.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "Another GRUB drop-in overrides"):
            bpf.configure(self.root, automatic=True)
        self.assertEqual(custom.read_bytes(), original)
        self.assertFalse(self.log.exists())
        self.assertFalse((self.root / "var/lib/membrane/bpf-lsm-reboot-required").exists())

    def test_pending_config_is_rechecked_after_admin_edit(self):
        self.assertEqual(bpf.configure(self.root, automatic=True), 75)
        self.write("etc/default/grub.d/zz-custom.cfg", 'GRUB_CMDLINE_LINUX_DEFAULT="lsm=landlock,lockdown,yama,apparmor"\n')
        with self.assertRaisesRegex(RuntimeError, "Another GRUB drop-in overrides"):
            bpf.configure(self.root, automatic=True)
        self.assertEqual(self.log.read_text(), "update\n")


# Only setup helpers run against these commands: no package install, mount,
# service operation, boot change, or VM restart reaches the real host.
HOST_COMMAND = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['SETUP_FIXTURE'])
state_file = root / 'state.json'
state = json.loads(state_file.read_text())
command, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
with (root / 'calls.jsonl').open('a') as log:
    log.write(json.dumps([command, *args]) + '\n')
def finish(code=0):
    state_file.write_text(json.dumps(state))
    sys.exit(code)
if command == 'sudo':
    if args[0] == 'test':
        finish(0 if not (root / args[-1].lstrip('/')).exists() else 1)
    if args[0] == 'cmp':
        args[2] = str(root / args[2].lstrip('/'))
    if args[0] == 'mkdir':
        args[-1] = str(root / args[-1].lstrip('/'))
    os.execvp(args[0], args)
if command == 'tee':
    dest = root / args[0].lstrip('/')
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(sys.stdin.read())
    finish()
if command == 'systemctl':
    action, unit = args[0], args[-1]
    units = state['units']
    if action == 'cat':
        finish(0 if unit in units else 1)
    elif action == 'is-enabled':
        print(units.get(unit, 'not-found'))
        finish(0 if units.get(unit) in ('enabled', 'static', 'generated') else 1)
    elif action == 'is-active':
        finish(0 if unit in state.get('active', []) else 3)
    elif action in ('enable', 'start'):
        if action == 'enable':
            units[unit] = 'enabled'
        if action == 'start' or '--now' in args:
            state.setdefault('active', []).append(unit)
    elif action != 'daemon-reload':
        finish(99)
    finish()
finish(99)
'''


class ServiceSetupTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        binary = self.root / "bin"
        binary.mkdir()
        for command in ("sudo", "tee", "systemctl"):
            file = binary / command
            file.write_text(HOST_COMMAND)
            file.chmod(0o700)
        self.env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"], SETUP_FIXTURE=str(self.root))

    def run_helper(self, helper, state):
        (self.root / "state.json").write_text(json.dumps(state))
        result = subprocess.run(["bash", "-c", 'source "$1"; "$2"', "bash", str(SCRIPTS / "install-linux.sh"), helper], env=self.env, capture_output=True, text=True)
        return result, json.loads((self.root / "state.json").read_text())

    def calls(self):
        return [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]

    def test_sysbox_enablement_and_repeated_setup(self):
        units = ("sysbox.service", "sysbox-mgr.service", "sysbox-fs.service")
        state = {"units": dict.fromkeys(units, "disabled")}
        result, state = self.run_helper("enable_sysbox", state)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(state["units"][unit] == "enabled" for unit in units))
        self.assertEqual({tuple(call) for call in self.calls() if call[:2] == ["systemctl", "enable"]},
                         {("systemctl", "enable", "--now", unit) for unit in units})
        (self.root / "calls.jsonl").unlink()
        state["active"] = []
        result, state = self.run_helper("enable_sysbox", state)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(state["active"]), set(units))
        self.assertFalse(any(call[:2] == ["systemctl", "enable"] for call in self.calls()))

    def test_missing_sysbox_unit_is_not_guessed(self):
        result, _ = self.run_helper("enable_sysbox", {"units": {"sysbox.service": "enabled"}})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sysbox-mgr.service is missing", result.stderr)
        self.assertFalse(any(call[:2] == ["systemctl", "start"] for call in self.calls()))

    def test_native_docker_dependencies_unchanged(self):
        self.env.pop("MEMBRANE_COLIMA", None)
        result, _ = self.run_helper("configure_colima_sysbox", {"units": {}})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "calls.jsonl").exists())

    def test_colima_docker_dependency_is_persistent_and_idempotent(self):
        self.env["MEMBRANE_COLIMA"] = "1"
        state = {"units": {"docker.service": "enabled"}}
        result, state = self.run_helper("configure_colima_sysbox", state)
        self.assertEqual(result.returncode, 0, result.stderr)
        dropin = self.root / "etc/systemd/system/docker.service.d/membrane-sysbox.conf"
        before = dropin.stat().st_mtime_ns
        result, _ = self.run_helper("configure_colima_sysbox", state)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(dropin.stat().st_mtime_ns, before)
        self.assertEqual(sum(call[:2] == ["systemctl", "daemon-reload"] for call in self.calls()), 1)
        self.assertFalse(any(call[:2] == ["systemctl", "restart"] for call in self.calls()))

    def test_colima_docker_dependency_preserves_admin_config(self):
        self.env["MEMBRANE_COLIMA"] = "1"
        dropin = self.root / "etc/systemd/system/docker.service.d/membrane-sysbox.conf"
        dropin.parent.mkdir(parents=True)
        dropin.write_text("# administrator configuration\n")
        result, _ = self.run_helper("configure_colima_sysbox", {"units": {"docker.service": "enabled"}})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has different contents", result.stderr)
        self.assertEqual(dropin.read_text(), "# administrator configuration\n")

    def test_colima_docker_pulls_sysbox_into_real_systemd_transaction(self):
        systemd = os.environ.get("TEST_SYSTEMD", "/lib/systemd/systemd")
        package_units = Path(os.environ.get("TEST_SYSBOX_UNITS", "/usr/lib/systemd/system"))
        names = ("sysbox.service", "sysbox-mgr.service", "sysbox-fs.service")
        if os.geteuid() == 0 or not Path(systemd).exists() or not all((package_units / name).exists() for name in names):
            self.skipTest("non-root systemd --test and installed Sysbox package units required")
        units = self.root / "etc/systemd/system"
        units.mkdir(parents=True)
        for name in names:
            shutil.copy2(package_units / name, units / name)
        # Start Docker alone, with no multi-user.target boot links. Its runtime
        # must still be pulled in using the actual package's BindsTo/After graph.
        (units / "docker.service").write_text("[Unit]\nRequires=containerd.service\nAfter=containerd.service\n[Service]\nExecStart=/bin/true\n")
        (units / "containerd.service").write_text("[Service]\nExecStart=/bin/true\n")
        env = dict(os.environ, SYSTEMD_UNIT_PATH=str(units) + ":" + os.environ.get("SYSTEMD_UNIT_PATH", ""))

        def start_jobs():
            result = subprocess.run([systemd, "--test", "--system", "--unit=docker.service"], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("ordering cycle", result.stderr)
            return set(re.findall(r"Action: (\S+) -> start", result.stdout))

        before = start_jobs()
        self.assertIn("docker.service", before)
        self.assertTrue(set(names).isdisjoint(before))
        self.env["MEMBRANE_COLIMA"] = "1"
        result, _ = self.run_helper("configure_colima_sysbox", {"units": {"docker.service": "enabled"}})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(set(names).issubset(start_jobs()))



COLIMA_COMMAND = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['SETUP_FIXTURE'])
state_file = root / 'state.json'
state = json.loads(state_file.read_text())
command, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
with (root / 'calls.jsonl').open('a') as log:
    log.write(json.dumps([command, *args]) + '\n')
def finish(code=0):
    state_file.write_text(json.dumps(state))
    sys.exit(code)
units = ['sysbox.service', 'sysbox-mgr.service', 'sysbox-fs.service']
if command == 'uname':
    print('Darwin')
    finish()
if command == 'brew':
    if args[0] == '--prefix':
        print(root)
    finish()
if command == 'docker':
    assert os.environ['DOCKER_CONTEXT'] == 'colima-membrane'
    if args[0] == 'info':
        print('{"sysbox-runc":{"path":"/usr/bin/sysbox-runc"}}')
    elif args[0] == 'run':
        finish(0 if state.get('active') == units else 1)
    finish()
assert command == 'colima' and args[1:3] == ['--profile', 'membrane'], args
if args[0] == 'status':
    finish()
if args[0] == 'stop':
    state['active'] = []
    finish()
if args[0] == 'start':
    # Reproduce a VM boot that leaves enabled Sysbox units inactive. Docker
    # must independently pull them in through its persisted dependency.
    state['active'] = units[:] if state.get('docker_pulls_sysbox') else []
    state['active_after_restart'] = state['active'][:]
    state['bpf'] = not state.get('bad_boot', False)
    finish()
assert args[0] == 'ssh' and args[3] == '--', args
args = args[4:]
if args[0] == 'mktemp':
    print('/tmp/membrane-setup.fixture')
elif args[0] == 'tee':
    sys.stdin.read()
elif args[0] == 'rm':
    pass
elif args[0] in ('sh', 'env'):
    if args[0] == 'sh':
        wrapper = sys.stdin.read()
        assert 'status=$?' in wrapper and '"$1/status"' in wrapper
        assert 'MEMBRANE_COLIMA=1 ' in wrapper
    else:
        assert args[1:3] == ['MEMBRANE_COLIMA=1', 'bash'], args
    state['setup_calls'] = state.get('setup_calls', 0) + 1
    code = state.get('setup_status', 0) if state['setup_calls'] == 1 else 0
    state['remote_setup_status'] = code
    if code == 0:
        state['docker_pulls_sysbox'] = True
        state['enabled'] = units[:]
        state['active'] = units[:]
        state['bpf'] = True
    # Real colima versions can normalize all failing remote exits to 1.
    finish(0 if args[0] == 'sh' or code == 0 else 1)
elif args[0] == 'cat':
    assert args[-1].endswith('/status')
    print(state['remote_setup_status'])
elif args[0] == 'sudo':
    assert args[1:] == ['cat', '/sys/kernel/security/lsm'], args
    print('capability,yama,bpf' if state.get('bpf') else 'capability,yama')
elif args[0] == 'systemctl':
    if args[1] == 'is-enabled':
        print('enabled' if args[-1] in state.get('enabled', []) else 'disabled')
    else:
        finish(0 if args[-1] in state.get('active', []) else 3)
else:
    finish(99)
finish()
'''


@unittest.skipUnless(os.environ.get("TEST_YQ") or shutil.which("yq"), "install Homebrew yq or set TEST_YQ to run Colima config tests")
class ColimaSetupTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        binary = self.root / "bin"
        binary.mkdir()
        (binary / "yq").symlink_to(os.environ.get("TEST_YQ") or shutil.which("yq"))
        for command in ("uname", "brew", "colima", "docker"):
            file = binary / command
            file.write_text(COLIMA_COMMAND)
            file.chmod(0o700)
        self.config = self.root / ".colima/membrane/colima.yaml"
        self.config.parent.mkdir(parents=True)
        self.config.write_text('# Keep profile settings\ncpu: 6\ndocker:\n  features:\n    buildkit: false\n  runtimes:\n    other:\n      path: /usr/bin/other\n    sysbox-runc:\n      path: /usr/bin/sysbox-runc\n      runtimeArgs: ["--debug"]\n')
        self.env = dict(os.environ, HOME=str(self.root), COLIMA_HOME="", XDG_CONFIG_HOME="", PATH=str(binary) + os.pathsep + os.environ["PATH"], SETUP_FIXTURE=str(self.root))

    def run_setup(self, state):
        (self.root / "state.json").write_text(json.dumps(state))
        result = subprocess.run(["bash", str(SCRIPTS / "install-macos.sh")], env=self.env, capture_output=True, text=True)
        return result, json.loads((self.root / "state.json").read_text())

    def calls(self):
        return [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]

    def test_healthy_profile_needs_no_restart_or_config_rewrite(self):
        before = self.config.stat().st_mtime_ns
        result, state = self.run_setup({})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result, _ = self.run_setup(state)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.config.stat().st_mtime_ns, before)
        self.assertFalse(any(call[:2] == ["colima", "stop"] for call in self.calls()))

    def test_boot_and_runtime_changes_share_one_restart(self):
        self.config.write_text(self.config.read_text().replace("/usr/bin/sysbox-runc", "/old/sysbox-runc"))
        result, state = self.run_setup({"setup_status": 75})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state["setup_calls"], 2)
        self.assertEqual(sum(call[:2] == ["colima", "stop"] for call in self.calls()), 1)
        content = self.config.read_text()
        for preserved in ("cpu: 6", "buildkit: false", "path: /usr/bin/other", "--debug", "# Keep profile settings"):
            self.assertIn(preserved, content)
        self.assertIn("path: /usr/bin/sysbox-runc", content)

    def test_runtime_restart_retains_enabled_sysbox_services(self):
        self.config.write_text("docker: {}\n")
        result, state = self.run_setup({})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Error: no matches found", result.stderr)
        self.assertEqual(set(state["active_after_restart"]), {"sysbox.service", "sysbox-mgr.service", "sysbox-fs.service"})

    def test_vm_restart_starts_sysbox_without_rerunning_setup(self):
        result, state = self.run_setup({})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        setup_calls = state["setup_calls"]
        for command in ("stop", "start"):
            subprocess.run(["colima", command, "--profile", "membrane"], env=self.env, check=True, capture_output=True)
        state = json.loads((self.root / "state.json").read_text())
        self.assertEqual(state["setup_calls"], setup_calls)
        self.assertEqual(set(state["active_after_restart"]), {"sysbox.service", "sysbox-mgr.service", "sysbox-fs.service"})

    def test_failure_does_not_trigger_reboot(self):
        result, _ = self.run_setup({"setup_status": 1})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("VM was not restarted", result.stderr)
        self.assertFalse(any(call[:2] == ["colima", "stop"] for call in self.calls()))

    def test_failed_activation_is_checked_before_continuing(self):
        result, state = self.run_setup({"setup_status": 75, "bad_boot": True})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("still inactive after restart", result.stderr)
        self.assertEqual(state["setup_calls"], 1)


if __name__ == "__main__":
    unittest.main()
