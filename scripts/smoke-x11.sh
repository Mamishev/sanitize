#!/bin/sh
set -eu
export DISPLAY=:97
Xvfb "$DISPLAY" -screen 0 1280x1024x24 -nolisten tcp > /tmp/sanitize-xvfb.log 2>&1 &
xserver=$!
trap 'kill "$xserver" 2>/dev/null || true' EXIT
sleep 1
QT_QPA_PLATFORM=xcb sh /scripts/smoke-appimage.sh "$1"
