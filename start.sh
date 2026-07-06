#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORM_LIB_DEFAULT="$ROOT/libWormAPI/libWormAPI.so"

# Load TSE credentials (and any other local overrides) from .env, without
# clobbering values already explicitly set in the environment.
if [[ -f "$ROOT/.env" ]]; then
    while IFS='=' read -r key value; do
        [[ -z "$key" || "$key" == \#* ]] && continue
        if [[ -z "${!key:-}" ]]; then
            export "$key=$value"
        fi
    done < "$ROOT/.env"
fi

# USB vendor:model of the TSE stick (see /etc/udev/rules.d/99-cloudtse.rules).
# Used to find the device regardless of which /dev/sdX letter it enumerates
# as this boot, instead of assuming a fixed letter.
TSE_USB_VENDOR_ID="12d1"
TSE_USB_MODEL_ID="1436"

detect_tse_device() {
    local dev vid mid
    for dev in /dev/sd?; do
        [[ -b "$dev" ]] || continue
        vid="$(udevadm info --query=property --name="$dev" 2>/dev/null | sed -n 's/^ID_VENDOR_ID=//p')"
        mid="$(udevadm info --query=property --name="$dev" 2>/dev/null | sed -n 's/^ID_MODEL_ID=//p')"
        if [[ "$vid" == "$TSE_USB_VENDOR_ID" && "$mid" == "$TSE_USB_MODEL_ID" ]]; then
            echo "$dev"
            return 0
        fi
    done
    return 1
}

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
    # Prefer the invoking (non-root) user when run via sudo, so the vfat
    # mount and files underneath are actually usable without root.
    local owner_uid="${SUDO_UID:-$(id -u)}"
    local owner_gid="${SUDO_GID:-$(id -g)}"

    if mount_path="$(detect_tse_mount)"; then
        if findmnt -no OPTIONS "$mount_path" 2>/dev/null | grep -q '\bro\b'; then
            mount -o remount,rw "$mount_path" 2>/dev/null || true
        fi
        if [[ "$(id -u)" -eq 0 ]] && [[ "$(stat -c %u "$mount_path" 2>/dev/null)" != "$owner_uid" ]]; then
            mount -o "remount,uid=$owner_uid,gid=$owner_gid" "$mount_path" 2>/dev/null || true
        fi
        export CLOUDTSE_WORM_PATH="$mount_path"
        echo "cloudtse: TSE mount: $mount_path" >&2
        return 0
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return 1
    fi

    local part="${CLOUDTSE_TSE_DEVICE:-}"
    if [[ -z "$part" ]]; then
        part="$(detect_tse_device || true)"
    fi
    if [[ -n "$part" && -b "${part}1" ]]; then
        part="${part}1"
    fi
    [[ -n "$part" && -b "$part" ]] || return 1

    mkdir -p /mnt/tse
    local mount_opts="uid=$owner_uid,gid=$owner_gid"
    if mount -o "$mount_opts" "$part" /mnt/tse 2>/dev/null ||
        mount -o "ro,$mount_opts" "$part" /mnt/tse 2>/dev/null; then
        export CLOUDTSE_WORM_PATH=/mnt/tse
        mount -o "remount,rw,$mount_opts" /mnt/tse 2>/dev/null || true
        echo "cloudtse: mounted $part at /mnt/tse (uid=$owner_uid gid=$owner_gid)" >&2
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
    if [[ -z "${CLOUDTSE_TSE_DEVICE:-}" ]]; then
        CLOUDTSE_TSE_DEVICE="$(detect_tse_device || echo /dev/sda)"
    fi
    export CLOUDTSE_TSE_DEVICE

    # TSE credentials (CLOUDTSE_WORM_ADMIN_PIN / _PUK / _TIME_ADMIN_PIN) are
    # loaded from .env above; they're permanent on the physical hardware
    # from the one-time worm_tse_setup provisioning, so keep them there
    # instead of hardcoding/regenerating them here.
    if [[ -z "${CLOUDTSE_WORM_ADMIN_PIN:-}" ]]; then
        echo "cloudtse: warning: CLOUDTSE_WORM_ADMIN_PIN not set (expected in $ROOT/.env)" >&2
    fi

    ensure_tse_mount || true
fi

if [[ ! -x "$BIN" ]]; then
    echo "cloudtse: building $BIN" >&2
    make -C "$ROOT/c"
fi

exec "$BIN" "$@"
