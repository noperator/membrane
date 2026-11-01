#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

# Protect preparation/startup, not the running agent against its own root user.
# No agent/template program is executed when this list is consumed on the host.
{
    printf '%s\n' /usr/local/bin/entrypoint.sh /usr/local/share/membrane/startup-paths \
        /etc/passwd /etc/group /etc/nsswitch.conf \
        /etc/ld.so.preload /etc/ld.so.cache
    # ld.so.conf and ld.so.conf.d are inputs to ldconfig, which startup does not
    # run. Only the loader's active cache/preload files need protection here.
    # dockerd reads configuration/TLS material and restores runtime/plugin state
    # before the workload starts; these are not ordinary agent configuration.
    printf '%s\n' /etc/docker /run/docker /var/lib/docker
    # CA setup executes every hook and opens OpenSSL's config. Its output tree
    # must remain private/writable for the handler CA and generated trust bundle.
    # Extra input certificates may still be supplied under local/share below.
    printf '%s\n' /etc/ssl/openssl.cnf /etc/ca-certificates/update.d /etc/ssl/certs \
        /sbin/restorecon /usr/sbin/restorecon \
        /usr/sbin/test /usr/bin/test /sbin/test /bin/test \
        /usr/local/share/ca-certificates/membrane-ca.crt
    # Absolute invocations need only their actual path and resolved image target.
    # mkdir/dirname are build-time helpers, unused by the bundled startup path.
    for command in bash sh ip sysctl cp update-ca-certificates /usr/bin/python3 \
        /usr/sbin/capsh /usr/sbin/gosu dockerd containerd /usr/bin/crun runc docker-init docker-proxy containerd-shim-runc-v2 \
        iptables ip6tables seq sleep \
        mktemp rm ln basename readlink sed find sort openssl chmod cat run-parts wc mv; do
        program=$(command -v "$command")
        readlink -f "$program"
        case "$command" in
            /*) printf '%s\n' "$command" ;;
            *)
                # A template must not introduce an earlier PATH match.
                for directory in /usr/sbin /usr/bin /sbin /bin; do
                    printf '%s/%s\n' "$directory" "$command"
                done ;;
        esac
        # Keep directories: the loader also selects hardware variants and dlopen
        # modules. Enumerating only ldd's files would miss those startup inputs.
        ldd "$program" 2>/dev/null | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' |
            while IFS= read -r library; do dirname "$(readlink -f "$library")"; done
    done
    # Isolated Python still imports the stdlib and its extension modules. Keep
    # the tree rather than maintaining a version-dependent transitive import list.
    python3 -I -S -c 'import sysconfig; print(sysconfig.get_path("stdlib"))'
} > /usr/local/share/membrane/startup-paths
sort -u /usr/local/share/membrane/startup-paths -o /usr/local/share/membrane/startup-paths
