#!/bin/sh
set -eu
: "${APPIMAGETOOL:?Set APPIMAGETOOL to a verified appimagetool executable}"
version=$(python -c 'from sanitize import __version__; print(__version__)')
if [ -d build/AppDir ]; then
    echo 'Use a clean build directory (build/AppDir already exists).' >&2
    exit 1
fi
python -m PyInstaller --noconfirm --clean --onedir --name sanitize \
  --collect-data sanitize --collect-all textual --collect-all magic \
  --hidden-import sanitize.gui.app --hidden-import sanitize.gui.main_window \
  --hidden-import sanitize.tui \
  --add-binary '/usr/lib/x86_64-linux-gnu/libmagic.so.1:.' \
  --add-data '/usr/share/misc/magic.mgc:.' \
  --add-data 'LICENSE:.' --add-data 'docs/user-guide.md:.' \
  scripts/appimage_entry.py
python scripts/prune_qt_bundle.py
mkdir -p build/AppDir/usr/bin build/AppDir/usr/share/doc/sanitize
cp -a dist/sanitize/. build/AppDir/usr/bin/
mkdir -p build/AppDir/usr/share/sanitize
cp packaging/fontconfig/fonts.conf build/AppDir/usr/share/sanitize/fonts.conf
cp sanitize/gui/icons/icon-256.png build/AppDir/sanitize.png
cp LICENSE docs/user-guide.md docs/third-party.md build/AppDir/usr/share/doc/sanitize/
cp packaging/licenses/AppImage-runtime-LICENSE.txt build/AppDir/usr/share/doc/sanitize/
cp sanitize/gui/icons/README.md build/AppDir/usr/share/doc/sanitize/icon-origin.md
python scripts/collect_licenses.py build/AppDir/usr/share/doc/sanitize/licenses
cat > build/AppDir/sanitize.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=sanitize
Comment=Sanitize sensitive files in development projects
Exec=sanitize
Icon=sanitize
Categories=Utility;
Terminal=false
EOF
cat > build/AppDir/AppRun <<'EOF'
#!/bin/sh
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${FONTCONFIG_FILE:=$HERE/usr/share/sanitize/fonts.conf}"
: "${FONTCONFIG_PATH:=$HERE/usr/share/sanitize}"
export FONTCONFIG_FILE FONTCONFIG_PATH
export MAGIC="$HERE/usr/bin/_internal/magic.mgc"
exec "$HERE/usr/bin/sanitize" "$@"
EOF
chmod +x build/AppDir/AppRun
desktop-file-validate build/AppDir/sanitize.desktop
: "${APPIMAGE_RUNTIME:?Set APPIMAGE_RUNTIME to a verified runtime-x86_64}"
ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$APPIMAGETOOL" --runtime-file "$APPIMAGE_RUNTIME" build/AppDir "dist/sanitize-$version-x86_64.AppImage"
