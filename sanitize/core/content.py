"""Опциональный поиск ПДн по содержимому: --deep-scan (AGENTS.md, фаза 5).

Текстовые форматы (csv, txt, tsv, md, xml, json, yaml, yml, log, sql, eml, vcf)
читаются как текст с лимитом; .docx/.xlsx — как zip (word/document.xml,
xl/sharedStrings.xml). Находки: e-mail, телефон РФ, паспорт РФ, СНИЛС
(контрольная сумма), ИНН (контрольная сумма), номер карты (Луна).

Результат — словарь счётчиков content_hits (AGENTS.md, раздел 5).
"""

from __future__ import annotations

import logging
import re
import zipfile
from pathlib import Path
from typing import BinaryIO

logger = logging.getLogger(__name__)

#: Лимит чтения на файл по умолчанию (AGENTS.md, раздел 10).
DEFAULT_READ_LIMIT = 20 * 1024 * 1024

#: Расширения, для которых выполняется текстовый deep-scan.
TEXTUAL_EXTS: frozenset[str] = frozenset(
    {
        ".csv",
        ".tsv",
        ".txt",
        ".md",
        ".xml",
        ".json",
        ".yaml",
        ".yml",
        ".log",
        ".sql",
        ".eml",
        ".vcf",
    }
)

#: Office-файлы, читаемые как zip с XML-внутренностями.
_OFFICE_ZIP_PARTS: dict[str, tuple[str, ...]] = {
    ".docx": ("word/document.xml", "word/sharedStrings.xml"),
    ".xlsx": ("xl/sharedStrings.xml",),
    ".pptx": ("ppt/slides/",),
}

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

_PHONE_RE = re.compile(r"(?<![\d(])(?:\+7|8)[\s\-()]*(?:\d[\s\-()]*){10}(?!\d)")

_PASSPORT_RE = re.compile(r"(?<!\d)\d{2}[\s.-]\d{2}[\s.-]\d{6}(?!\d)")

_SNILS_RE = re.compile(r"(?<!\d)(\d{3})-(\d{3})-(\d{3})\s(\d{2})(?!\d)")

_INN_RE = re.compile(r"(?<!\d)(\d{10}|\d{12})(?!\d)")

_CARD_RE = re.compile(r"(?<!\d)((?:\d{4}[ -]?){3,5}\d{1,4})(?!\d)")


def _snils_valid(groups: re.Match[str]) -> bool:
    """Контрольная сумма СНИЛС: вес 9..1, сумма <100 — сама, 100/101 — 0."""
    digits = [int(c) for c in (groups.group(1) + groups.group(2) + groups.group(3))]
    total = sum(d * weight for d, weight in zip(digits, range(9, 0, -1), strict=True))
    if total >= 100:
        total %= 101
        if total == 100:
            total = 0
    return total == int(groups.group(4))


def _inn_check_digit(digits: tuple[int, ...], weights: tuple[int, ...]) -> int:
    total = sum(d * w for d, w in zip(digits, weights, strict=True)) % 11
    return 0 if total == 10 else total


def _inn_valid(match: re.Match[str]) -> bool:
    digits_str = match.group(1)
    digits = tuple(int(c) for c in digits_str)
    if len(digits) == 10:
        return _inn_check_digit(digits[:9], (2, 4, 10, 3, 5, 9, 4, 6, 8)) == digits[9]
    first = _inn_check_digit(digits[:10], (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)) == digits[10]
    second = _inn_check_digit(digits[:11], (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)) == digits[11]
    return first and second


def _luhn_valid(number: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for position, digit in enumerate(reversed(digits)):
        if position % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def analyze_text(text: str) -> dict[str, int]:
    """Считает ПДн-паттерны в тексте; возвращает только ненулевые счётчики."""
    hits: dict[str, int] = {}

    email_count = len(_EMAIL_RE.findall(text))
    if email_count:
        hits["email"] = email_count

    phone_count = len(_PHONE_RE.findall(text))
    if phone_count:
        hits["phone"] = phone_count

    passport_count = len(_PASSPORT_RE.findall(text))
    if passport_count:
        hits["passport"] = passport_count

    snils_count = sum(1 for m in _SNILS_RE.finditer(text) if _snils_valid(m))
    if snils_count:
        hits["snils"] = snils_count

    inn_count = sum(1 for m in _INN_RE.finditer(text) if _inn_valid(m))
    if inn_count:
        hits["inn"] = inn_count

    card_count = sum(1 for m in _CARD_RE.finditer(text) if _luhn_valid(m.group(1)))
    if card_count:
        hits["card"] = card_count

    return hits


def _read_limited(fh: BinaryIO, read_limit: int) -> bytes:
    """Читает поток с ограничением объёма."""
    return fh.read(read_limit)


def _analyze_office(path: Path, read_limit: int) -> dict[str, int]:
    """Deep-scan docx/xlsx/pptx как zip: извлекаем XML-части и ищем в них."""
    lowered = path.name.lower()
    parts = next(
        (patterns for ext, patterns in _OFFICE_ZIP_PARTS.items() if lowered.endswith(ext)),
        (),
    )
    try:
        with zipfile.ZipFile(path) as archive:
            texts: list[str] = []
            budget = read_limit
            for name in archive.namelist():
                if budget <= 0:
                    break
                matched = any(name == part or name.startswith(part) for part in parts)
                if not matched:
                    continue
                with archive.open(name) as member:
                    raw = member.read(budget)
                budget -= len(raw)
                texts.append(raw.decode("utf-8", errors="ignore"))
            combined = "\n".join(texts)
    except (OSError, zipfile.BadZipFile, EOFError) as exc:
        logger.debug("Не удалось прочитать office-файл %s: %s", path, exc)
        return {}
    return analyze_text(combined)


def analyze_file(path: Path, read_limit: int = DEFAULT_READ_LIMIT) -> dict[str, int]:
    """Ищет ПДн в текстовых файлах и office-контейнерах.

    Возвращает content_hits (пустой словарь, если формат не текстовый или
    файл не читается).
    """
    lowered = path.name.lower()
    if any(lowered.endswith(ext) for ext in _OFFICE_ZIP_PARTS):
        return _analyze_office(path, read_limit)
    dot = lowered.rfind(".")
    ext = lowered[dot:] if dot >= 0 else ""
    if ext not in TEXTUAL_EXTS:
        return {}
    try:
        raw = _read_from_file(path, read_limit)
    except OSError as exc:
        logger.debug("deep-scan не смог прочитать %s: %s", path, exc)
        return {}
    return analyze_text(raw.decode("utf-8", errors="ignore"))


def _read_from_file(path: Path, read_limit: int) -> bytes:
    with open(path, "rb") as fh:
        return _read_limited(fh, read_limit)
