"""Тесты GUI. Основная реализация — фаза 4 (pytest-qt, QT_QPA_PLATFORM=offscreen)."""

from __future__ import annotations

import importlib


def test_gui_package_importable_without_pyside6() -> None:
    """Пакет sanitize.gui импортируется без установленного PySide6 (CLI-режим)."""
    for name in ("sanitize.gui", "sanitize.gui.app"):
        importlib.import_module(name)
