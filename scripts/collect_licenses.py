"""Collect installed Python and system license notices for the portable build."""

import importlib.metadata
import json
import shutil
import sys
from pathlib import Path

output = Path(sys.argv[1])
output.mkdir(parents=True, exist_ok=True)
packages = []
for dist in importlib.metadata.distributions():
    name = dist.metadata["Name"]
    if name.lower() in {
        "pip",
        "setuptools",
        "uv",
        "pyinstaller-hooks-contrib",
        "altgraph",
        "packaging",
    }:
        continue
    target = output / name
    target.mkdir(exist_ok=True)
    (target / "METADATA").write_text(dist.read_text("METADATA") or "")
    for item in dist.files or ():
        if any(word in str(item).lower() for word in ("license", "copying", "notice")):
            source = Path(dist.locate_file(item))
            if source.is_file():
                destination = target / str(item).replace("..", "_")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
    packages.append({"name": name, "version": dist.version})
(output / "python-packages.json").write_text(json.dumps(packages, indent=2))
# Debian copyright files include component authors, licensing and upstream source URLs.
for source in Path("/usr/share/doc").glob("*/copyright"):
    target = output / "system" / source.parent.name
    target.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target / "copyright")
common = Path("/usr/share/common-licenses")
if common.is_dir():
    shutil.copytree(common, output / "common-licenses", dirs_exist_ok=True)
