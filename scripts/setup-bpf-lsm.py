#!/usr/bin/env python3
"""Configure BPF LSM boot activation on the Docker host (exit 75: reboot needed)."""

import gzip
import hashlib
import os
from pathlib import Path
import platform
import re
from shutil import which
import subprocess
import sys


def kernel_config(root):
    for path, opener in ((root / "proc/config.gz", gzip.open),
                         (root / "boot" / ("config-" + platform.release()), open)):
        try:
            with opener(path, "rt") as stream:
                config = stream.read()
            if config.strip():
                return config
        except (OSError, EOFError, UnicodeError):
            pass
    return None


def read_optional(path):
    try:
        return path.read_text().strip()
    except OSError:
        return ""


def grub_command_line(root, exclude=None):
    files = [root / "etc/default/grub", *sorted((root / "etc/default/grub.d").glob("*.cfg"))]
    files = [str(p) for p in files if p.exists() and p != exclude]
    return subprocess.check_output([
        "sh", "-ec", 'for file do . "$file"; done; printf "%s\\n" "${GRUB_CMDLINE_LINUX-} ${GRUB_CMDLINE_LINUX_DEFAULT-}"',
        "sh", *files,
    ], text=True)


def lsm_order(root, config, dropin):
    # Prefer the next boot's explicit setting, including administrator drop-ins.
    # Exclude our own override when deciding which ordering to preserve.
    grub = grub_command_line(root, exclude=dropin)
    for command_line in (grub, read_optional(root / "proc/cmdline")):
        explicit = [arg[4:] for arg in command_line.split() if arg.startswith("lsm=")]
        if explicit:
            return explicit[-1]
    match = re.search(r'^CONFIG_LSM="([^"]*)"$', config, re.M)
    return match.group(1) if match else read_optional(root / "sys/kernel/security/lsm")


def verify_grub_lsms(root, lsms):
    effective = [arg[4:] for arg in grub_command_line(root).split() if arg.startswith("lsm=")]
    if effective != [lsms]:
        raise RuntimeError("Another GRUB drop-in overrides the Membrane lsm= setting. Check /etc/default/grub.d and preserve the LSM order including bpf; update-grub was not run and no reboot is requested.")


def configure(root=Path("/"), automatic=False):
    marker = root / "var/lib/membrane/bpf-lsm-reboot-required"
    try:
        active = (root / "sys/kernel/security/lsm").read_text().strip()
    except OSError:
        active = None
    if active is not None and "bpf" in active.split(","):
        marker.unlink(missing_ok=True)
        print("BPF LSM is already active; boot configuration unchanged.")
        return 0

    config = kernel_config(root)
    if config is None:
        raise RuntimeError("Cannot determine BPF LSM support: neither /proc/config.gz nor the running kernel's /boot/config is readable. Check the kernel config and active LSMs; boot configuration was not changed.")
    if not re.search(r"^CONFIG_BPF_LSM=y$", config, re.M):
        raise RuntimeError("Current kernel does not support BPF LSM (CONFIG_BPF_LSM=y required). Install a supported Ubuntu kernel, reboot, and rerun setup; boot configuration was not changed.")
    if active is None:
        raise RuntimeError("Kernel supports BPF LSM, but /sys/kernel/security/lsm cannot be read. Check the Docker host's securityfs mount before changing boot configuration.")

    dropin = root / "etc/default/grub.d/99-membrane-bpf-lsm.cfg"
    lsms = lsm_order(root, config, dropin)
    if not re.fullmatch(r"[a-zA-Z0-9_-]+(?:,[a-zA-Z0-9_-]+)*", lsms):
        raise RuntimeError("Cannot safely determine existing LSM ordering; add bpf to your bootloader's lsm= list manually, reboot, and rerun setup.")
    if "bpf" not in lsms.split(","):
        lsms += ",bpf"
    # Remove only lsm= tokens from both variables, then append exactly one.
    # No administrator file or unrelated kernel option is overwritten.
    strip_lsm = "sed -E 's/(^|[[:space:]])lsm=[^[:space:]]+//g'"
    content = "# Membrane BPF LSM activation; preserve other GRUB options.\n"
    for key in ("GRUB_CMDLINE_LINUX", "GRUB_CMDLINE_LINUX_DEFAULT"):
        suffix = " lsm=" + lsms if key.endswith("_DEFAULT") else ""
        content += f'{key}="$(printf \'%s\\n\' "${{{key}-}}" | {strip_lsm}){suffix}"\n'
    fingerprint = hashlib.sha256(content.encode()).hexdigest()
    if read_optional(dropin) == content.strip() and read_optional(marker) == fingerprint:
        verify_grub_lsms(root, lsms)
        print("BPF LSM boot configuration is already pending. Reboot, then rerun setup (exit 75).")
        return 75
    if which("update-grub") is None:
        raise RuntimeError("update-grub not found. Add bpf to your bootloader's lsm= list manually, reboot, then rerun setup.")

    print("BPF LSM is supported but not active.")
    print(f"Setup will write {dropin}, preserve the existing LSM order as lsm={lsms}, and run update-grub.")
    print("A reboot is required; native Linux will NOT be rebooted automatically.")
    if not automatic:
        try:
            with open("/dev/tty") as tty:
                print("Apply this boot configuration? [y/N] ", file=sys.stderr, end="", flush=True)
                accepted = tty.readline().strip().lower() == "y"
        except OSError:
            accepted = False
        if not accepted:
            raise RuntimeError("Boot configuration unchanged. Enable bpf in the boot lsm= list, reboot, then rerun setup.")
    dropin.parent.mkdir(parents=True, exist_ok=True)
    marker.unlink(missing_ok=True)
    if read_optional(dropin) != content.strip():
        dropin.write_text(content)
    verify_grub_lsms(root, lsms)
    subprocess.run(["update-grub"], check=True)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(fingerprint + "\n")
    print("Boot configuration updated. Reboot, then rerun setup (exit 75). No reboot was performed.")
    return 75


if __name__ == "__main__":
    try:
        sys.exit(configure(automatic=os.environ.get("MEMBRANE_CONFIGURE_BPF_LSM") == "1"))
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
