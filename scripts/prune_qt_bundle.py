"""Keep only desktop Qt modules used by sanitize in the staging directory."""

from pathlib import Path

internal = Path("dist/sanitize/_internal")
allowed = {
    "Core",
    "Gui",
    "Widgets",
    "DBus",
    "Network",
    "OpenGL",
    "Svg",
    "WaylandClient",
    "WlShellIntegration",
    "XcbQpa",
}
removed = []
for path in internal.rglob("libQt6*.so*"):
    module = path.name.removeprefix("libQt6").split(".so")[0]
    if module not in allowed:
        path.unlink()
        removed.append(str(path))
plugins = internal / "PySide6/Qt/plugins"
for path in plugins.rglob("*.so"):
    category = path.parent.name
    if (
        category in {"egldeviceintegrations", "generic"}
        or "virtualkeyboard" in path.name
        or path.name == "libqpdf.so"
        or (
            category == "platforms"
            and path.name
            not in {"libqxcb.so", "libqwayland.so", "libqoffscreen.so", "libqminimal.so"}
        )
    ):
        path.unlink()
        removed.append(str(path))
Path("build/qt-pruned.txt").write_text("\n".join(removed) + "\n")
