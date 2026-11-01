#!/bin/bash
set -e

# Template-supplied tools in the workload's PATH must not intercept setup.
WORKLOAD_PATH=$PATH
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

# Set default route through handler gateway
ip route replace default via "$MEMBRANE_GATEWAY" 2>/dev/null || true

# Point DNS at handler gateway (dns-proxy runs there)
echo "nameserver $MEMBRANE_GATEWAY" >/etc/resolv.conf

# Fix MTU
ip link set dev eth0 mtu 1200 2>/dev/null || true

# Disable IPv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true

# Install handler CA cert (must be present — handler signals ready only after writing it)
[ -f /membrane-ca/ca.crt ] || {
    echo "ERROR: CA cert not found"
    exit 1
}
cp /membrane-ca/ca.crt /usr/local/share/ca-certificates/membrane-ca.crt
update-ca-certificates >/dev/null 2>&1

# usermod -u recursively chowns the old home, including host bind mounts.
# Adjust the account directly and chown only private objects, using the kernel's
# actual mount table. This runs before dockerd or any user workload starts.
/usr/bin/python3 -I -S - <<'PY'
import grp, os, pwd, re

mounts = []
with open('/proc/self/mountinfo') as stream:
    for line in stream:
        name = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), line.split()[4])
        if name != '/':
            mounts.append(name)

def mounted(name):
    return any(name == root or name.startswith(root + '/') for root in mounts)

account = pwd.getpwnam('agent')
workspace = os.stat('.')
# A root-owned workspace must not turn the ordinary agent into root.
uid = workspace.st_uid or account.pw_uid
gid = workspace.st_gid or account.pw_gid
# Like usermod/groupmod without --non-unique, retain the image identity when
# the requested ID is occupied. In particular, an unmapped bind can report
# nobody/nogroup (65534); duplicate UIDs make sudo identify agent as nobody.
if any(user.pw_uid == uid and user.pw_name != 'agent' for user in pwd.getpwall()):
    uid = account.pw_uid
if any(group.gr_gid == gid and group.gr_name != 'agent' for group in grp.getgrall()):
    gid = account.pw_gid
for filename, fields in (('/etc/passwd', {2: uid, 3: gid}), ('/etc/group', {2: gid})):
    if mounted(filename):
        raise RuntimeError('Membrane startup requires a private ' + filename)
    with open(filename) as stream:
        lines = stream.readlines()
    for i, line in enumerate(lines):
        parts = line.rstrip('\n').split(':')
        if parts[0] == 'agent':
            for index, value in fields.items():
                parts[index] = str(value)
            lines[i] = ':'.join(parts) + '\n'
    with open(filename, 'w') as stream:
        stream.writelines(lines)

home = '/home/agent'
if not mounted(home):
    os.chown(home, uid, gid, follow_symlinks=False)
    for root, dirs, files in os.walk(home, followlinks=False):
        for name in list(dirs) + files:
            name = os.path.join(root, name)
            if mounted(name):
                if os.path.basename(name) in dirs:
                    dirs.remove(os.path.basename(name))
                continue
            os.chown(name, uid, gid, follow_symlinks=False)
PY

# Start Docker daemon if running in Sysbox
if [ "$MEMBRANE_DIND" = "1" ] && command -v dockerd >/dev/null 2>&1; then
    dockerd --add-runtime=crun=/usr/bin/crun --default-runtime=crun \
        >/var/log/dockerd.log 2>&1 &
    for _ in $(seq 1 30); do
        [ -S /var/run/docker.sock ] && break
        sleep 1
    done
    [ -S /var/run/docker.sock ] || echo "Warning: Docker daemon failed to start" >&2
fi

if [ -n "$MEMBRANE_TITLE" ]; then
    { echo -ne "\e]2;${MEMBRANE_TITLE}\007" >/dev/tty; } 2>/dev/null || true
fi

export PATH=$WORKLOAD_PATH
# shellcheck disable=SC2016
exec /usr/sbin/capsh --drop=cap_net_admin,cap_net_raw,cap_setpcap,cap_setfcap \
    -- -c 'exec /usr/sbin/gosu agent "${@:-bash}"' -- "$@"
