#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORM_LIB_DEFAULT="$ROOT/libWormAPI/libWormAPI.so"

detect_tse_mount() {
    local p
    for p in "${CLOUDTSE_WORM_PATH:-}" /mnt/tse /mnt/SWISSBIT; do
        [[ -n "$p" && -f "$p/TSE_INFO.DAT" ]] || continue
        echo "$p"
        return 0
    done
    for p in /media/*/SWISSBIT /media/*/*/SWISSBIT; do
        [[ -f "$p/TSE_INFO.DAT" ]] || continue
        echo "$p"
        return 0
    done
    return 1
}

ensure_tse_mount() {
    local mount_path=""

    if mount_path="$(detect_tse_mount)"; then
        if findmnt -no OPTIONS "$mount_path" 2>/dev/null | grep -q '\bro\b'; then
            mount -o remount,rw "$mount_path" 2>/dev/null || true
        fi
        export CLOUDTSE_WORM_PATH="$mount_path"
        echo "cloudtse: TSE mount: $mount_path" >&2
        return 0
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return 1
    fi

    local part="${CLOUDTSE_TSE_DEVICE:-/dev/sda1}"
    if [[ "$part" == /dev/sda && -b /dev/sda1 ]]; then
        part=/dev/sda1
    fi
    [[ -b "$part" ]] || return 1

    mkdir -p /mnt/tse
    if mount "$part" /mnt/tse 2>/dev/null || mount -o ro "$part" /mnt/tse 2>/dev/null; then
        export CLOUDTSE_WORM_PATH=/mnt/tse
        mount -o remount,rw /mnt/tse 2>/dev/null || true
        echo "cloudtse: mounted $part at /mnt/tse" >&2
        return 0
    fi
    return 1
}

if [[ "${1:-}" == "sim" || "${1:-}" == "simulator" ]]; then
    shift
    export CLOUDTSE_TSE_MODE=sim
elif [[ -z "${CLOUDTSE_TSE_MODE:-}" ]]; then
    export CLOUDTSE_TSE_MODE=hardware
fi

BIN="$ROOT/c/cloudtse"

if [[ "$CLOUDTSE_TSE_MODE" != "sim" ]]; then
    export CLOUDTSE_WORM_LIB="${CLOUDTSE_WORM_LIB:-$WORM_LIB_DEFAULT}"
    if [[ ! -f "$CLOUDTSE_WORM_LIB" ]]; then
        echo "cloudtse: missing $CLOUDTSE_WORM_LIB" >&2
        echo "cloudtse: place libWormAPI.so from the Swissbit SDK at libWormAPI/libWormAPI.so" >&2
        exit 1
    fi
    export LD_LIBRARY_PATH="$(dirname "$CLOUDTSE_WORM_LIB")${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    : "${CLOUDTSE_TSE_DEVICE:=/dev/sda}"
    export CLOUDTSE_TSE_DEVICE
    ensure_tse_mount || true
fi

if [[ ! -x "$BIN" ]]; then
    echo "cloudtse: building $BIN" >&2
    make -C "$ROOT/c"
fi

exec "$BIN" "$@"
