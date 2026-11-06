#!/bin/sh
set -eu
export XDG_RUNTIME_DIR
XDG_RUNTIME_DIR=$(mktemp -d /tmp/sanitize-wayland.XXXXXX)
chmod 700 "$XDG_RUNTIME_DIR"
export WAYLAND_DISPLAY=sanitize-test
weston --backend=headless-backend.so --socket="$WAYLAND_DISPLAY" --idle-time=0 > "$XDG_RUNTIME_DIR/weston.log" 2>&1 &
compositor=$!
trap 'kill "$compositor" 2>/dev/null || true' EXIT
n=0
while [ ! -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ]; do
    n=$((n + 1))
    if [ "$n" -gt 50 ]; then cat "$XDG_RUNTIME_DIR/weston.log"; exit 1; fi
    sleep 0.1
done
QT_QPA_PLATFORM=wayland sh /scripts/smoke-appimage.sh "$1"
