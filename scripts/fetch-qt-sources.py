"""Download matching upstream source archives for the portable Qt distribution."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

output = Path(sys.argv[1])
output.mkdir(parents=True, exist_ok=True)
base = "https://download.qt.io/official_releases"
urls = [
    f"{base}/qt/6.12/6.12.0/submodules/{module}-everywhere-src-6.12.0.tar.xz"
    for module in ("qtbase", "qtwayland", "qtsvg", "qtimageformats")
]
urls.append(
    f"{base}/QtForPython/pyside6/PySide6-6.12.0-src/pyside-setup-everywhere-src-6.12.0.tar.xz"
)
urls.append("https://github.com/unicode-org/icu/releases/download/release-73-2/icu4c-73_2-src.tgz")
urls += [
    "https://github.com/AppImage/type2-runtime/archive/fedfad51acc2860b2916a1eef32ba4a500ff31ef.tar.gz",
    "https://github.com/libfuse/libfuse/releases/download/fuse-3.15.0/fuse-3.15.0.tar.xz",
    "https://github.com/vasi/squashfuse/archive/0.5.2.tar.gz",
    "https://musl.libc.org/releases/musl-1.2.5.tar.gz",
    "https://zlib.net/fossils/zlib-1.3.1.tar.gz",
    "https://github.com/facebook/zstd/releases/download/v1.5.6/zstd-1.5.6.tar.gz",
    "https://github.com/microsoft/mimalloc/archive/refs/tags/v2.1.7.tar.gz",
]
manifest = []
for url in urls:
    path = output / url.rsplit("/", 1)[-1]
    if not path.exists():
        temporary = path.with_suffix(path.suffix + ".part")
        candidates = [url]
        if url.startswith(base):
            candidates += [
                url.replace("https://download.qt.io", mirror)
                for mirror in (
                    "https://mirrors.dotsrc.org/qtproject",
                    "https://ftp.fau.de/qtproject",
                )
            ]
        for candidate in candidates:
            result = subprocess.run(
                [
                    "curl",
                    "-fL",
                    "--retry",
                    "2",
                    "--connect-timeout",
                    "10",
                    "--max-time",
                    "120",
                    "-o",
                    str(temporary),
                    candidate,
                ]
            )
            if result.returncode == 0:
                break
        else:
            raise RuntimeError(f"Cannot download source archive: {url}")
        temporary.replace(path)
    manifest.append(
        {"url": url, "file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    )
    print(path.name, flush=True)
(output / "upstream-sources.json").write_text(json.dumps(manifest, indent=2))
