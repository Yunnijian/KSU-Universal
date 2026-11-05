#!/usr/bin/env bash
# Build the dual-manager kernelsu.ko for PYB110 6.18.21.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KSU_BUILD="${KSU_BUILD:-/Users/tubi/ksu-build}"
IMAGE="${IMAGE:-ghcr.io/ylarod/ddk-min:android17-6.18-20260828}"

docker run --rm \
    -v "$KSU_BUILD:/work" \
    -v "$ROOT:/src" \
    "$IMAGE" \
    bash -lc '
        set -e
        cd /src/kernel
        make -C /work/kdir/android17-6.18 M="$PWD" MO="$PWD" \
            CONFIG_KSU=m CC=clang modules -j"$(nproc)"
        ls -l kernelsu.ko
        strings -a kernelsu.ko | grep -m1 "vermagic="
    '
