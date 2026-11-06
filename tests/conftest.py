"""Общие фикстуры для тестов sanitize.

Главные фикстуры:
- fake_bitrix_tree: мини-копия структуры Битрикс-проекта (AGENTS.md, фаза 0);
- outside_dir: каталог вне корня проекта для проверки симлинков.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest


def _touch(path: Path, size: int = 16) -> Path:
    """Создаёт файл заданного размера с бинарным мусором."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    return path


@pytest.fixture()
def outside_dir(tmp_path: Path) -> Path:
    """Каталог вне корня проекта — цель для симлинков."""
    outside = tmp_path / "outside"
    outside.mkdir()
    _touch(outside / "secret.txt")
    return outside


@pytest.fixture()
def fake_bitrix_tree(tmp_path: Path, outside_dir: Path) -> Iterator[Path]:
    """Мини-копия Битрикс-проекта: файлы всех категорий, исключения, симлинки, нет доступа."""
    root = tmp_path / "site"

    # --- bitrix/ ---
    _touch(root / "bitrix" / "modules" / "main" / "include.php")  # исключённый каталог
    _touch(root / "bitrix" / "backup" / "20260105_full.tar.gz", size=2048)  # backups + risky
    _touch(root / "bitrix" / "backup" / "db_dump.sql")  # backups + risky
    _touch(root / "bitrix" / "cache" / "html.cache")  # junk-каталог из logs
    _touch(root / "bitrix" / "managed_cache" / "mc.cache")
    _touch(root / "bitrix" / "stack_cache" / "sc.cache")
    _touch(root / "bitrix" / "html_pages" / "index.html")
    _touch(root / "bitrix" / "tmp" / "session.tmp")
    _touch(root / "bitrix" / ".settings.php")  # secrets_report
    _touch(root / "bitrix" / ".settings_extra.php")  # secrets_report
    _touch(root / "bitrix" / "php_interface" / "dbconn.php")  # secrets_report

    # --- upload/ ---
    _touch(root / "upload" / "iblock" / "4f3" / "doc.pdf")  # docs
    _touch(root / "upload" / "iblock" / "4f3" / "photo.jpg")  # изображение — не категория
    _touch(root / "upload" / "iblock" / "table.xls")  # sheets
    _touch(root / "upload" / "webform" / "results.csv")  # sheets (only_under) + risky
    _touch(root / "upload" / "webform" / "notes.txt")  # docs (.txt только под upload) + risky
    _touch(root / "upload" / "form" / "scan.pdf")  # docs + risky
    _touch(root / "upload" / "resize_cache" / "resize.pdf")  # НЕ должен найтись (исключён)
    _touch(root / "upload" / "tmp" / "debug.log")  # logs

    # --- local/ ---
    _touch(root / "local" / "readme.txt")  # .txt вне upload/ — игнорируется

    # --- корень: файлы всех категорий ---
    _touch(root / "report.pdf")  # docs
    _touch(root / "report_upper.PDF")  # регистр расширения
    _touch(root / "data.xlsx")  # sheets
    _touch(root / "deck.pptx")  # slides
    _touch(root / "archive.tar.gz")  # archives (двойное расширение)
    _touch(root / "archive.zip")  # archives
    _touch(root / "key.pem")  # keys
    _touch(root / "id_rsa")  # keys (точное имя)
    _touch(root / "backup.sql")  # backups
    _touch(root / "letter.eml")  # mail
    _touch(root / "contacts.vcf")  # mail
    _touch(root / "song.mp3")  # media (default off)
    _touch(root / "notes.txt")  # .txt вне upload/ — игнорируется
    _touch(root / "config.log")  # logs
    _touch(root / ".env")  # secrets_report
    _touch(root / ".env.local")  # secrets_report (.env.*)
    _touch(root / ".htpasswd")  # secrets_report
    empty = root / "empty.pdf"
    _touch(empty, size=0)  # пустой файл: ZERO должен пропустить как skipped_empty

    # --- симлинки ---
    os.symlink(outside_dir / "secret.txt", root / "link_outside_file")
    os.symlink(outside_dir, root / "link_outside_dir")

    # --- каталог без прав доступа ---
    noaccess = root / "noaccess"
    _touch(noaccess / "hidden.pdf")
    noaccess.chmod(0)

    try:
        yield root
    finally:
        # Возвращаем права, чтобы pytest мог удалить tmp_path.
        noaccess.chmod(stat.S_IRWXU)


# Владелец/права для тестов атрибутов (actions, фаза 2) выставляет этот набор:
DEFAULT_TEST_MODE = 0o640


def make_file(
    root: Path,
    relative: str,
    content: bytes = b"sensitive",
    mode: int = DEFAULT_TEST_MODE,
) -> Path:
    """Создаёт файл с заданным содержимым и правами (для тестов действий)."""
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    os.chmod(path, mode)
    return path
