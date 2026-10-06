#!/usr/bin/env python3
"""Exercise the real Bash supervisor with real children and fixture cgroup files."""

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

BASH = os.environ.get("TEST_BASH", "bash")
SUPERVISOR = Path(__file__).resolve().parents[1] / "docker/handler/supervisor.sh"

CHILD = r'''
import os, signal, sys, time
from pathlib import Path
root, name = Path(sys.argv[1]), sys.argv[2]
def stop(*_):
    (root / (name + '.stopped')).write_text((root / 'cgroup.events').read_text())
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
(root / (name + '.pid')).write_text(str(os.getpid()))
while True:
    if (root / (name + '.exit')).exists():
        sys.exit(int((root / (name + '.exit')).read_text()))
    time.sleep(0.01)
'''

HARNESS = r'''
set -euo pipefail
source "$1"
for name in dns-proxy mitmproxy tracer; do
    "$2" "$3/child.py" "$3" "$name" &
    supervise "$name" "$!"
done
while [ ! -f "$3/start" ]; do sleep 0.01; done
check_children
touch "$3/ready"
wait_for_critical_exit
'''


@unittest.skipUnless(
    subprocess.run([BASH, "-c", "(( BASH_VERSINFO[0] > 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] >= 1) ))"]).returncode == 0,
    "Bash 5.1+ required; set TEST_BASH when the host uses an older Bash")
class SupervisorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.write("cgroup.events", "populated 1\n")
        self.write("cgroup.kill", "")
        self.write("child.py", CHILD)
        self.log = (self.root / "output").open("w")
        self.addCleanup(self.log.close)
        self.process = subprocess.Popen(
            [BASH, "-c", HARNESS, "bash", str(SUPERVISOR), sys.executable, str(self.root)],
            env=dict(os.environ, MEMBRANE_TARGET_CGROUP=str(self.root)),
            stdout=self.log, stderr=self.log, start_new_session=True)
        self.addCleanup(self.cleanup)
        for name in ("dns-proxy", "mitmproxy", "tracer"):
            self.wait_for(lambda: (self.root / (name + ".pid")).exists())

    def write(self, name, data):
        (self.root / name).write_text(data)

    def wait_for(self, predicate):
        deadline = time.monotonic() + 5
        while not predicate():
            if time.monotonic() >= deadline:
                self.fail("timed out: " + (self.root / "output").read_text())
            time.sleep(0.01)

    def cleanup(self):
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.process.wait(timeout=5)

    def ready(self):
        self.write("start", "")
        self.wait_for(lambda: (self.root / "ready").exists())

    def drain(self, failed=None):
        self.wait_for(lambda: (self.root / "cgroup.kill").read_text().strip() == "1")
        # No remaining child may receive TERM until populated becomes zero.
        self.assertFalse(list(self.root.glob("*.stopped")))
        self.assertIsNone(self.process.poll())
        self.write("cgroup.events", "populated 0\n")
        status = self.process.wait(timeout=5)
        for name in ("dns-proxy", "mitmproxy", "tracer"):
            if name != failed:
                self.assertEqual((self.root / (name + ".stopped")).read_text(), "populated 0\n")
        return status

    def test_dns_death(self):
        self.ready()
        os.kill(int((self.root / "dns-proxy.pid").read_text()), signal.SIGKILL)
        self.assertNotEqual(self.drain("dns-proxy"), 0)

    def test_mitmproxy_clean_exit_is_still_fatal(self):
        self.ready()
        self.write("mitmproxy.exit", "0")
        self.assertNotEqual(self.drain("mitmproxy"), 0)

    def test_loader_crash(self):
        self.ready()
        self.write("tracer.exit", "17")
        self.assertNotEqual(self.drain("tracer"), 0)

    def test_startup_failure_never_signals_ready(self):
        self.write("tracer.exit", "1")
        tracer = int((self.root / "tracer.pid").read_text())
        def dead():
            try:
                os.kill(tracer, 0)
            except ProcessLookupError:
                return True
            return False
        self.wait_for(dead)
        self.write("start", "")
        self.assertNotEqual(self.drain("tracer"), 0)
        self.assertFalse((self.root / "ready").exists())

    def test_expected_termination_is_successful_and_drains_first(self):
        self.ready()
        self.process.send_signal(signal.SIGTERM)
        self.assertEqual(self.drain(), 0)


if __name__ == "__main__":
    unittest.main()
