#!/bin/sh
set -eu
mkdir -p /work
cd /work
cp -a /src/packaging /src/sanitize /src/scripts /src/docs /src/pyproject.toml /src/uv.lock /src/README.md /src/LICENSE .
uv export --frozen --extra gui --extra magic --extra tui --no-dev --no-emit-project --format requirements-txt > requirements.txt
uv pip install --python /opt/build/bin/python -r requirements.txt
uv pip install --python /opt/build/bin/python --no-deps .
APPIMAGE_RUNTIME=/tools/runtime-x86_64 APPIMAGETOOL=/tools/appimagetool-x86_64.AppImage sh scripts/build-appimage.sh
for image in dist/*.AppImage; do
    cp "$image" "/out/$(basename "$image").new"
    mv "/out/$(basename "$image").new" "/out/$(basename "$image")"
done
cp -a build/AppDir/usr/share/doc/sanitize/licenses /out/
cp requirements.txt /out/build-requirements.txt

if [ "${COLLECT_SOURCES:-0}" = 1 ]; then
    sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
    apt-get update > /tmp/apt-sources.log
    python scripts/collect_system_sources.py dist/sanitize/_internal /out/source-kit/system
    python scripts/fetch-qt-sources.py /out/source-kit/upstream
    python scripts/collect_upstream_notices.py /out/source-kit/upstream /out/licenses/upstream
    tar -czf /out/sanitize-1.0.2-dependency-sources.tar.gz -C /out source-kit
fi
