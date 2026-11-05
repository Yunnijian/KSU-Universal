#!/usr/bin/env bash
# Build the universal KernelSU LKM for one KMI.
# Usage: scripts/build.sh [android16-6.12|android17-6.18]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KSU_BUILD="${KSU_BUILD:-$HOME/ksu-build}"
KMI="${1:-${KMI:-android17-6.18}}"

case "$KMI" in
    android16-6.12)
        IMAGE="${IMAGE:-ghcr.io/ylarod/ddk-min:android16-6.12-20260828}"
        KDIR="${KDIR:-/opt/ddk/kdir/android16-6.12}"
        ;;
    android17-6.18)
        IMAGE="${IMAGE:-ghcr.io/ylarod/ddk-min:android17-6.18-20260828}"
        KDIR="${KDIR:-/work/kdir/android17-6.18}"
        ;;
    *)
        echo "unsupported KMI: $KMI" >&2
        exit 2
        ;;
esac

docker run --rm \
    -v "$KSU_BUILD:/work" \
    -v "$ROOT:/src" \
    -e KMI="$KMI" \
    -e KDIR="$KDIR" \
    "$IMAGE" \
    bash -lc '
        set -e
        cd /src/kernel
        make -C "$KDIR" M="$PWD" MO="$PWD" clean >/dev/null 2>&1 || true
        make -C "$KDIR" M="$PWD" MO="$PWD" \
            CONFIG_KSU=m CC=clang modules -j"$(nproc)"
        mkdir -p /src/dist
        cp kernelsu.ko "/src/dist/ksu_universal-${KMI}.ko"
        ls -l "/src/dist/ksu_universal-${KMI}.ko"
        strings -a "/src/dist/ksu_universal-${KMI}.ko" | grep -m1 "vermagic="
    '
