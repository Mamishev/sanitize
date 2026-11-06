#!/bin/sh
set -eu
mkdir -p "$1"
cd "$1"
curl -fL --retry 3 -o appimagetool-x86_64.AppImage https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
curl -fL --retry 3 -o runtime-x86_64 https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64
printf '%s\n' \
'e8c1169c4af66c3184d7ee110713d4be04befe671fa358e2c1591ee840553b03  appimagetool-x86_64.AppImage' \
'617aa77314d57c8b8e4fae9c3f0b35af7b30d5529cb69e98f64f92510ed98a46  runtime-x86_64' | sha256sum -c -
chmod +x appimagetool-x86_64.AppImage
# continuous URLs can change: fail on checksum mismatch; update only after review.
