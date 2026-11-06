#!/system/bin/sh
# Run on a rooted device after the universal KO is loaded.
# This script only switches the active profile and checks su; it does not
# install modules or reboot the device.

set -eu

NODE=/proc/kernelsu_manager

if [ ! -r "$NODE" ]; then
    echo "missing $NODE"
    exit 1
fi

switch_to() {
    pkg="$1"
    apk=$(pm path "$pkg" 2>/dev/null | head -n1 | sed 's/^package://')
    if [ -z "$apk" ]; then
        echo "SKIP $pkg (not installed)"
        return 0
    fi
    uid=$(stat -c %u "/data/data/$pkg")
    printf '%s %u %s' "$pkg" "$uid" "$apk" > "$NODE"
    rc=$?
    state=$(cat "$NODE")
    echo "SWITCH $pkg rc=$rc state=$state"
    su -c id
}

for pkg in \
    me.weishu.kernelsu \
    com.rifsxd.ksunext \
    com.resukisu.resukisu \
    com.sukisu.ultra \
    me.yuki.fina
do
    switch_to "$pkg"
done

echo "DONE"
