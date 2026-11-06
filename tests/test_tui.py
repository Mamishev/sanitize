"""Smoke-тесты TUI (Textual): конструирование без запуска событийного цикла."""

from __future__ import annotations

import pytest

pytest.importorskip("textual", reason="TUI требует extras 'tui' (textual)")


def test_app_constructs() -> None:
    from sanitize.tui import SanitizeTUI

    app = SanitizeTUI()
    assert app._cancel_event is not None


def test_confirm_screen_constructs() -> None:
    from sanitize.tui import ConfirmScreen

    plain = ConfirmScreen("Обнулить", 3, 100, require_delete=False)
    with_delete = ConfirmScreen("Удалить", 3, 100, require_delete=True)
    assert plain and with_delete


def test_run_is_callable() -> None:
    from sanitize import tui

    assert callable(tui.run)
