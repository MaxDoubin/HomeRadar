#!/bin/sh
# Drop from root to the unprivileged "homeradar" user before starting the app,
# carrying over only the capabilities Home Radar uses: binding DNS on port 53
# and raw-socket ARP scanning. `--cap-add` alone doesn't work for a non-root
# USER (its effective set stays empty), so with host networking the DNS proxy
# couldn't bind port 53. Ambient capabilities are the supported way to hand
# those two capabilities to an unprivileged process.
set -eu

if [ "$(id -u)" != "0" ]; then
    exec "$@"
fi

cap_bit() {
    # $1 = CapEff/CapBnd line name, $2 = capability bit number
    mask=$(awk -v key="$1:" '$1 == key { print $2 }' /proc/self/status)
    echo $(( (0x$mask >> $2) & 1 ))
}

# CAP_SETGID=6 and CAP_SETUID=7 are required to switch users. Refuse to run the
# app as root if they're missing rather than silently keeping root.
for bit in 6 7; do
    if [ "$(cap_bit CapEff "$bit")" != "1" ]; then
        echo "homeradar: the container needs --cap-add SETUID --cap-add SETGID" >&2
        echo "homeradar: (alongside NET_BIND_SERVICE and NET_RAW) to drop to its unprivileged user." >&2
        exit 1
    fi
done

caps=""
[ "$(cap_bit CapBnd 10)" = "1" ] && caps="${caps},+net_bind_service"
[ "$(cap_bit CapBnd 13)" = "1" ] && caps="${caps},+net_raw"

# Shrinking the bounding set (so SETUID/SETGID can never come back) needs
# CAP_SETPCAP=8; skip it if the runtime didn't grant that.
set -- --inh-caps="-all${caps}" --ambient-caps="-all${caps}" "$@"
if [ "$(cap_bit CapEff 8)" = "1" ]; then
    set -- --bounding-set="-all${caps}" "$@"
fi

exec setpriv --reuid=homeradar --regid=homeradar --clear-groups "$@"
