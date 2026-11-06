"""Настройки GUI через QSettings("sanitize", "sanitize") (~/.config/sanitize/)."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QByteArray, QSettings

_ORG = "sanitize"
_APP = "sanitize"


class Settings:
    """Типизированная обёртка над QSettings."""

    def __init__(self) -> None:
        self._settings = QSettings(_ORG, _APP)

    # --- общие helpers ---

    def get(self, key: str, default: Any) -> Any:
        value = self._settings.value(key)
        return default if value is None else value

    def set(self, key: str, value: Any) -> None:
        self._settings.setValue(key, value)

    def get_bool(self, key: str, default: bool = False) -> bool:
        value = self.get(key, default)
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "1", "yes")

    # --- конкретные ключи ---

    @property
    def last_path(self) -> str:
        return str(self.get("scan/last_path", ""))

    @last_path.setter
    def last_path(self, value: str) -> None:
        self.set("scan/last_path", value)

    @property
    def preset(self) -> str:
        return str(self.get("scan/preset", "bitrix"))

    @preset.setter
    def preset(self, value: str) -> None:
        self.set("scan/preset", value)

    def category_checked(self, category_id: str, default: bool) -> bool:
        return self.get_bool(f"checks/{category_id}", default)

    def set_category_checked(self, category_id: str, checked: bool) -> None:
        self.set(f"checks/{category_id}", checked)

    def save_geometry(self, geometry: QByteArray) -> None:
        self._settings.setValue("window/geometry", geometry)

    def restore_geometry(self) -> QByteArray | None:
        value = self._settings.value("window/geometry")
        return value if isinstance(value, QByteArray) else None

    def sync(self) -> None:
        self._settings.sync()
