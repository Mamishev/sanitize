"""Identify and download Ubuntu source packages corresponding to bundled libraries."""

import json
import subprocess
import sys
from pathlib import Path

bundle = Path(sys.argv[1])
output = Path(sys.argv[2])
output.mkdir(parents=True, exist_ok=True)
cache = subprocess.check_output(["ldconfig", "-p"], text=True)
lookup = {}
for line in cache.splitlines():
    if " => " in line:
        name, path = line.strip().split(" => ")
        lookup[name.split()[0]] = path
manifest = {}
for binary in bundle.glob("*.so*"):
    original = lookup.get(binary.name)
    if not original:
        continue  # Qt/PySide and ICU wheel libraries are covered by the upstream source kit.
    original = str(Path(original).resolve())
    owners = subprocess.run(["dpkg-query", "-S", original], text=True, capture_output=True)
    if owners.returncode:
        owners = subprocess.run(
            ["dpkg-query", "-S", original.removeprefix("/usr")], text=True, capture_output=True
        )
    if owners.returncode:
        raise RuntimeError(f"Cannot identify system library: {binary.name}")
    owner = owners.stdout.split(": /")[0].strip()
    source = subprocess.check_output(
        ["dpkg-query", "-W", "-f=${source:Package}=${source:Version}", owner], text=True
    )
    manifest[binary.name] = {"binary_package": owner, "source": source, "path": original}
(output / "system-sources.json").write_text(json.dumps(manifest, indent=2))
for source in sorted({item["source"] for item in manifest.values()}):
    subprocess.run(["apt-get", "source", "--download-only", source], cwd=output, check=True)
