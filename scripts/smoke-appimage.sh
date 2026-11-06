#!/bin/sh
# Run as an unprivileged user. Only temporary fixtures are scanned or modified.
set -eu
image=$1
export APPIMAGE_EXTRACT_AND_RUN=1
fixture=$(mktemp -d /tmp/sanitize-smoke.XXXXXX)
mkdir -p "$fixture/site/upload" "$fixture/site/bitrix/modules"
printf 'private document' > "$fixture/site/upload/document.pdf"
printf 'protected module' > "$fixture/site/bitrix/modules/keep.pdf"
printf 'external target' > "$fixture/outside.pdf"
ln -s "$fixture/outside.pdf" "$fixture/site/upload/link.pdf"
printf '%%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%%%EOF\n' > "$fixture/site/upload/no-extension"
"$image" --version
before=$(sha256sum "$fixture/site/upload/document.pdf")
"$image" --path "$fixture/site" --dry-run --magic --json > "$fixture/dry.json"
test "$before" = "$(sha256sum "$fixture/site/upload/document.pdf")"
grep -q no-extension "$fixture/dry.json"
"$image" --path "$fixture/site" --zero --yes --json > "$fixture/zero.json"
test ! -s "$fixture/site/upload/document.pdf"
test -s "$fixture/site/bitrix/modules/keep.pdf"
test -s "$fixture/outside.pdf"
test -L "$fixture/site/upload/link.pdf"
"$image" --path "$fixture/site" --zero --yes --json > "$fixture/repeat.json"
grep -q skipped_empty "$fixture/repeat.json"
# With a real X11/Wayland server supplied, the GUI must remain alive until timeout.
set +e
timeout 5 "$image" --gui > "$fixture/gui.log" 2>&1
status=$?
set -e
cat "$fixture/gui.log"
test "$status" = 124
printf 'PASS: version, magic, dry-run, zero, idempotency, exclusions, symlinks, GUI (%s)\n' "${QT_QPA_PLATFORM:-auto}"
