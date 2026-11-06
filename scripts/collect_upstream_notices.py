"""Copy license notices from upstream source archives without extracting code."""

import sys
import tarfile
from pathlib import Path, PurePosixPath

source = Path(sys.argv[1])
output = Path(sys.argv[2])
for archive in sorted(source.iterdir()):
    if not tarfile.is_tarfile(archive):
        continue
    with tarfile.open(archive) as stream:
        for member in stream:
            path = PurePosixPath(member.name)
            if not member.isfile() or path.is_absolute() or ".." in path.parts:
                continue
            name = path.name.lower()
            if not any(
                word in name for word in ("license", "licence", "copying", "copyright", "notice")
            ):
                continue
            if member.size > 2_000_000:
                raise ValueError(f"Unexpected notice size: {member.name}")
            content = stream.extractfile(member)
            if content is not None:
                target = output / archive.name / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content.read())
