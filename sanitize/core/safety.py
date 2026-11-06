"""Защита от опасных путей (AGENTS.md, разделы 7, 9).

- чёрный список корней: /, /home, /root, /usr, /etc, /var, /opt, /srv, /tmp
  (подкаталоги разрешены, например /var/www/site);
- проверка маркеров проекта (bitrix/, upload/) — только предупреждение;
- каталог карантина должен быть вне корня проекта.
"""

from __future__ import annotations

from pathlib import Path

from sanitize.core.presets import Preset

#: Корни, с которыми работа запрещена целиком.
BLOCKED_ROOTS: frozenset[str] = frozenset(
    {"/", "/home", "/root", "/usr", "/etc", "/var", "/opt", "/srv", "/tmp"}
)


class SafetyError(ValueError):
    """Опасный или недопустимый путь."""


def resolve_safe(root: Path) -> Path:
    """Нормализует путь (expanduser + resolve) и возвращает его."""
    return root.expanduser().resolve()


def check_root(root: Path) -> Path:
    """Проверяет корень: существует, это каталог, не в чёрном списке.

    Возвращает нормализованный путь; SafetyError при отказе.
    """
    resolved = resolve_safe(root)
    if str(resolved) in BLOCKED_ROOTS:
        raise SafetyError(
            f"Отказ: {resolved} — системный каталог из чёрного списка. "
            f"Укажите подкаталог проекта (например, /var/www/site)."
        )
    if not resolved.exists():
        raise SafetyError(f"Отказ: путь не существует: {resolved}")
    if not resolved.is_dir():
        raise SafetyError(f"Отказ: путь не является каталогом: {resolved}")
    return resolved


def has_project_markers(root: Path, preset: Preset) -> bool:
    """True, если в корне есть хотя бы один маркер проекта (bitrix/, upload/)."""
    resolved = resolve_safe(root)
    return any((resolved / marker).exists() for marker in preset.markers)


def check_quarantine_dir(root: Path, quarantine_dir: Path) -> Path:
    """Каталог карантина должен быть вне корня проекта.

    Возвращает нормализованный путь; SafetyError при нарушении.
    """
    root_resolved = resolve_safe(root)
    quarantine_resolved = resolve_safe(quarantine_dir)
    if quarantine_resolved == root_resolved or root_resolved in quarantine_resolved.parents:
        raise SafetyError(
            f"Отказ: каталог карантина {quarantine_resolved} находится внутри "
            f"корня проекта {root_resolved}"
        )
    return quarantine_resolved
