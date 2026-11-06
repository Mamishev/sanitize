"""Опциональное определение типа файла по сигнатуре (python-magic).

AGENTS.md, раздел 9: используется только для файлов, не распознанных по
имени/расширению (включая файлы без расширения). При отсутствии python-magic
или системной libmagic — предупреждение один раз, не падение.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

try:  # pragma: no cover — зависит от окружения
    import magic as _magic

    _AVAILABLE = True
except ImportError:  # pragma: no cover
    _magic = None  # type: ignore[assignment]
    _AVAILABLE = False

_WARNED = False

#: Префикс MIME -> id категории (проверка по startswith, порядок важен).
MIME_PREFIX_TO_CATEGORY: tuple[tuple[str, str], ...] = (
    # Документы
    ("application/pdf", "docs"),
    ("application/msword", "docs"),
    ("application/vnd.oasis.opendocument.text", "docs"),
    ("application/vnd.openxmlformats-officedocument.wordprocessingml", "docs"),
    ("application/vnd.ms-word", "docs"),
    ("application/epub+zip", "docs"),
    ("application/x-dvi", "docs"),
    # Таблицы
    ("application/vnd.ms-excel", "sheets"),
    ("application/x-msaccess", "sheets"),
    ("application/vnd.oasis.opendocument.spreadsheet", "sheets"),
    ("application/vnd.openxmlformats-officedocument.spreadsheetml", "sheets"),
    ("text/csv", "sheets"),
    # Презентации
    ("application/vnd.ms-powerpoint", "slides"),
    ("application/vnd.oasis.opendocument.presentation", "slides"),
    ("application/vnd.openxmlformats-officedocument.presentationml", "slides"),
    # Архивы
    ("application/zip", "archives"),
    ("application/x-zip-compressed", "archives"),
    ("application/x-tar", "archives"),
    ("application/gzip", "archives"),
    ("application/x-gzip", "archives"),
    ("application/x-bzip2", "archives"),
    ("application/x-xz", "archives"),
    ("application/zstd", "archives"),
    ("application/x-7z-compressed", "archives"),
    ("application/x-rar", "archives"),
    ("application/vnd.rar", "archives"),
    ("application/x-cab", "archives"),
    ("application/x-iso9660-image", "archives"),
    ("application/x-arj", "archives"),
    ("application/x-lha", "archives"),
    # Ключи/подписи
    ("application/pkix-cert", "keys"),
    ("application/pkcs", "keys"),
    ("application/x-pkcs", "keys"),
    ("application/pgp", "keys"),
    ("application/x-keepass", "keys"),
    ("text/x-pem", "keys"),
    # Почта
    ("message/rfc822", "mail"),
    ("application/vnd.ms-outlook", "mail"),
    ("text/x-vcard", "mail"),
    ("text/calendar", "mail"),
    # Бэкапы/дампы
    ("application/sql", "backups"),
    ("application/x-sqlite", "backups"),
    ("application/vnd.ms-access", "backups"),
    ("application/x-dbf", "backups"),
)


def is_available() -> bool:
    """True, если python-magic (и libmagic) доступны."""
    return _AVAILABLE


def mime_for(path: Path, chunk_size: int = 65536) -> str | None:
    """MIME по содержимому; None, если библиотека недоступна или ошибка.

    При первом вызове без python-magic пишет предупреждение в журнал.
    """
    global _WARNED
    if not _AVAILABLE or _magic is None:
        if not _WARNED:
            _WARNED = True
            logger.warning(
                "python-magic недоступен (--magic игнорируется): "
                "pip install 'sanitize[magic]' и системную libmagic"
            )
        return None
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(chunk_size)
        mime: str | None = _magic.from_buffer(chunk, mime=True)
        return mime
    except (OSError, AttributeError, ValueError) as exc:
        logger.debug("magic не смог определить тип %s: %s", path, exc)
        return None


def category_for_mime(mime: str | None) -> str | None:
    """id категории по MIME; None — сигнатура не относится к категориям поиска."""
    if not mime:
        return None
    lowered = mime.lower()
    for prefix, category_id in MIME_PREFIX_TO_CATEGORY:
        if lowered.startswith(prefix):
            return category_id
    return None
