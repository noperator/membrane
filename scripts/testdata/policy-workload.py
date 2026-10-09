"""Real filesystem operations run as sandbox root by scripts/test.py."""
import ctypes
import errno
import mmap
import os
from pathlib import Path
import struct
import subprocess
import sys
import time


def check(ok, label):
    if not ok:
        raise RuntimeError(label)
    print("PASS " + label, flush=True)


def denied(label, operation):
    try:
        operation()
    except OSError as error:
        check(error.errno == errno.EACCES, f"{label}: EACCES (got {error})")
    else:
        raise RuntimeError(label + ": unexpectedly allowed")


def mapped(path, writable=False):
    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_COPY if writable else mmap.ACCESS_READ) as view:
            return view[:1]


def access(path, sealed):
    path = Path(path)
    check(path.stat().st_size > 0, str(path) + ": stat")
    if sealed:
        denied(str(path) + ": read", path.read_bytes)
        denied(str(path) + ": mmap", lambda: mapped(path))
    else:
        check(bool(path.read_bytes()), str(path) + ": read")
        check(bool(mapped(path)), str(path) + ": read-only mmap")
    denied(str(path) + ": write", lambda: path.write_bytes(b"bad"))
    denied(str(path) + ": append", lambda: open(path, "ab"))
    denied(str(path) + ": truncate", lambda: os.truncate(path, 0))
    denied(str(path) + ": writable mmap", lambda: mapped(path, True))


def gate(name="continue"):
    Path("ready").touch()
    deadline = time.monotonic() + 90
    while not Path(name).exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("host gate timed out: " + name)
        time.sleep(0.02)


def prepare():
    """Seed optional Linux metadata before policy enrollment, including on Colima."""
    try:
        os.setxattr("protected", "user.membrane", b"initial")
        Path("xattr-supported").touch()
        check(True, "Linux xattr fixture prepared")
    except OSError as error:
        if error.errno not in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL):
            raise
        print("SKIP xattrs unsupported on workspace filesystem: " + str(error), flush=True)
    # Include a named user so Linux stores an ACL instead of reducing it to mode bits.
    acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", tag, perm, uid)
                                          for tag, perm, uid in ((1, 6, 0xffffffff), (2, 4, 12345),
                                                                 (4, 4, 0xffffffff), (16, 4, 0xffffffff), (32, 4, 0xffffffff)))
    try:
        os.setxattr("ordinary", "system.posix_acl_access", acl)
        os.setxattr("protected", "system.posix_acl_access", acl)
        Path("acl-supported").touch()
        check(True, "Linux ACL fixtures prepared")
    except OSError as error:
        if error.errno not in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL):
            raise
        print("SKIP ACLs unsupported on workspace filesystem: " + str(error), flush=True)


def semantics(sealed):
    protected = Path("protected")
    tree = Path("secrets")
    check("protected" in os.listdir("."), "protected filename remains visible")
    for name in ("protected", "symlink", "hardlink", "secrets/api-key.txt"):
        access(name, sealed)
    denied("chmod", lambda: os.chmod(protected, 0o600))
    st = protected.stat()
    denied("chown", lambda: os.chown(protected, st.st_uid, st.st_gid))
    if Path("xattr-supported").exists():
        denied("setxattr", lambda: os.setxattr(protected, "user.membrane", b"bad"))
        denied("removexattr", lambda: os.removexattr(protected, "user.membrane"))
    if Path("acl-supported").exists():
        acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", tag, perm, 0xffffffff)
                                               for tag, perm in ((1, 7), (4, 5), (32, 5)))
        denied("set ACL", lambda: os.setxattr(protected, "system.posix_acl_access", acl))
        denied("remove ACL", lambda: os.removexattr(protected, "system.posix_acl_access"))
    denied("unlink", protected.unlink)
    denied("rename away", lambda: protected.rename("moved"))
    denied("replace by rename", lambda: os.replace("replacement", protected))
    denied("hardlink source", lambda: os.link(protected, "new-hardlink"))
    check("api-key.txt" in os.listdir(tree), "protected directory remains listable")
    denied("create child", lambda: (tree / "new").touch())
    denied("mkdir child", lambda: (tree / "new-dir").mkdir())
    denied("symlink child", lambda: os.symlink("/etc/hostname", tree / "new-link"))
    denied("mknod child", lambda: os.mkfifo(tree / "new-fifo"))
    denied("hardlink into directory", lambda: os.link("ordinary", tree / "new-hardlink"))
    denied("unlink child", lambda: (tree / "api-key.txt").unlink())
    denied("rmdir child", lambda: (tree / "sub").rmdir())
    denied("rename child", lambda: (tree / "api-key.txt").rename(tree / "renamed"))
    denied("move child out", lambda: (tree / "api-key.txt").rename("outside"))
    denied("move object in", lambda: os.rename("ordinary", tree / "ordinary"))
    if sealed:
        denied("sealed executable", lambda: subprocess.run(["./protected-exec", "policy-exec", "45900"], check=True))
    else:
        subprocess.run(["./protected-exec", "policy-exec", "45900"], check=True)
        check(True, "readonly ELF executable")
        # A new mprotect must not upgrade an existing read-only mapping.
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mmap.restype = ctypes.c_void_p
        libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
        libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        with open(protected, "rb") as f:
            address = libc.mmap(None, 4096, mmap.PROT_READ, mmap.MAP_PRIVATE, f.fileno(), 0)
            check(address != ctypes.c_void_p(-1).value, "readonly mmap for mprotect")
            try:
                check(libc.mprotect(address, 4096, mmap.PROT_READ | mmap.PROT_WRITE) == -1
                      and ctypes.get_errno() == errno.EACCES, "mprotect write upgrade denied")
            finally:
                libc.munmap(address, 4096)
    Path("/tmp/workspace-copy").mkdir(exist_ok=True)
    subprocess.run(["mount", "--bind", ".", "/tmp/workspace-copy"], check=True)
    try:
        access("/tmp/workspace-copy/protected", sealed)
    finally:
        subprocess.run(["umount", "/tmp/workspace-copy"], check=True)
    check(Path("ordinary").read_text() == "ordinary\n", "ordinary read")
    Path("ordinary").write_text("agent write\n")
    gate()
    check(Path("host-new").read_text() == "host\n", "host can create ordinary objects")
    access("protected", sealed)


def snapshot():
    def identity(path):
        st = Path(path).stat()
        return st.st_dev, st.st_ino

    denied("startup .env is sealed", lambda: Path(".env").read_bytes())
    old = open("readonly-old", "rb")
    ordinary = open("ordinary", "r+b")
    try:
        initial = {name: identity(name) for name in (".env", "readonly-old", "ordinary")}
        print("SNAPSHOT startup inode identities: " + repr(initial), flush=True)
        gate()
        check(ordinary.read() == b"ordinary\n", "ordinary FD remains readable after host mutations")
        ordinary.seek(0)
        # Mutations and release run on the Linux Docker host through the same
        # VFS. Check identities once so a failure distinguishes an unexpected
        # namespace view from incorrect enforcement on a replacement inode.
        names = (".env", "renamed-env", "old-alias", "readonly-old", "moved/.env", "late/.env", "tree/new")
        observed = {name: identity(name) for name in names}
        print("SNAPSHOT guest inode identities after host mutations: " + repr(observed), flush=True)
        check(observed[".env"] != initial[".env"]
              and observed["readonly-old"] != initial["readonly-old"]
              and observed["renamed-env"] == observed["old-alias"] == initial[".env"]
              and observed["moved/.env"] == initial["ordinary"],
              "host replacements have distinct inodes; renamed objects retain startup identities")
        denied("renamed enrolled inode", lambda: Path("renamed-env").read_bytes())
        denied("replaced enrolled inode via hardlink", lambda: Path("old-alias").read_bytes())
        check(Path(".env").read_text() == "replacement\n", "replacement .env is normal")
        Path(".env").write_text("agent replacement write\n")
        check(Path("late/.env").read_text() == "late\n", "late matching file remains normal")
        Path("late/.env").write_text("agent late write\n")
        check(Path("moved/.env").read_text() == "ordinary\n", "ordinary inode renamed onto matching path stays normal")
        ordinary.write(b"agent"); ordinary.flush()
        check(old.read() == b"readonly original\n", "FD still references enrolled old inode")
        denied("old readonly FD cannot acquire writable mapping", lambda: mmap.mmap(old.fileno(), 0, access=mmap.ACCESS_COPY))
        check(Path("readonly-old").read_text() == "replacement\n", "readonly pathname replacement is normal")
        Path("readonly-old").write_text("writable replacement\n")
        check(Path("tree/new").read_text() == "new\n", "host-created child is not enrolled")
        Path("tree/new").write_text("allowed content update\n")
        denied("parent still blocks new child unlink", lambda: Path("tree/new").unlink())
    finally:
        old.close(); ordinary.close()


mode = sys.argv[1]
if mode == "prepare":
    prepare()
elif mode in ("sealed", "readonly"):
    semantics(mode == "sealed")
elif mode == "snapshot":
    snapshot()
elif mode == "precedence":
    access("config/settings.yaml", False)
    access("config/secrets.txt", True)
    access("sealed/readonly/child", True)
elif mode == "hold":
    denied("policy active at first workload operation", lambda: Path("protected").read_bytes())
    gate()
    denied("held policy remains active", lambda: Path("protected").read_bytes())
elif mode == "ordinary":
    check(bool(Path("protected").read_bytes()), "second session can read same inode")
    Path("protected").write_text("other session write\n")
    gate()
elif mode == "late-only":
    gate()
    check(Path(".env").read_text() == "late\n", "empty snapshot: late matching inode is normal")
    Path(".env").write_text("agent write\n")
    Path("agent").mkdir()
    Path("agent/.env").write_text("agent-created matching inode\n")
    check(bool(Path("agent/.env").read_bytes()), "agent-created matching inode remains normal")
    # The host runner cannot unlink children of this root-owned directory.
    Path("agent/.env").unlink()
    Path("agent").rmdir()
else:
    raise RuntimeError("unknown workload mode: " + mode)
