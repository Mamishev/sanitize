"""Checks for the portable distribution staging scripts."""

import subprocess
import sys
from pathlib import Path


def test_qt_staging_excludes_unused_modules(tmp_path: Path) -> None:
    internal = tmp_path / "dist/sanitize/_internal"
    lib = internal / "PySide6/Qt/lib"
    plugins = internal / "PySide6/Qt/plugins"
    lib.mkdir(parents=True)
    (tmp_path / "build").mkdir()
    for name in ("libQt6Core.so.6", "libQt6Pdf.so.6", "libQt6VirtualKeyboard.so.6"):
        (lib / name).touch()
    for name in (
        "platforms/libqxcb.so",
        "platforms/libqwayland.so",
        "platforms/libqvnc.so",
        "imageformats/libqpdf.so",
        "platforminputcontexts/libqtvirtualkeyboardplugin.so",
    ):
        path = plugins / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    script = Path(__file__).resolve().parents[1] / "scripts/prune_qt_bundle.py"
    subprocess.run([sys.executable, str(script)], cwd=tmp_path, check=True)
    assert (lib / "libQt6Core.so.6").exists()
    assert not (lib / "libQt6Pdf.so.6").exists()
    assert not (lib / "libQt6VirtualKeyboard.so.6").exists()
    assert (plugins / "platforms/libqxcb.so").exists()
    assert (plugins / "platforms/libqwayland.so").exists()
    assert not (plugins / "imageformats/libqpdf.so").exists()
    assert not (plugins / "platforms/libqvnc.so").exists()
