"""Тесты deep-scan ПДн по содержимому (AGENTS.md, фаза 5)."""

from __future__ import annotations

import zipfile
from pathlib import Path

from sanitize.core.content import (
    DEFAULT_READ_LIMIT,
    TEXTUAL_EXTS,
    analyze_file,
    analyze_text,
)


class TestRegexChecksums:
    def test_email(self) -> None:
        hits = analyze_text("Пишите на ivanov@example.com или petrov@mail.ru")
        assert hits == {"email": 2}

    def test_phone_ru(self) -> None:
        text = "+7 912 345-67-89, 8-800-555-35-35, +79123456789"
        assert analyze_text(text) == {"phone": 3}

    def test_phone_not_in_long_digits(self) -> None:
        # 12 цифр подряд — не телефон
        assert "phone" not in analyze_text("id=79123456789012")

    def test_passport(self) -> None:
        assert analyze_text("паспорт 12 34 567890 выдан") == {"passport": 1}
        assert "passport" not in analyze_text("номер 1234567890")

    def test_snils_known_valid(self) -> None:
        # 123-456-788: 1*9+2*8+3*7+4*6+5*5+6*4+7*3+8*2+8*1 = 164 -> 164 % 101 = 63
        assert analyze_text("СНИЛС 123-456-788 63") == {"snils": 1}
        assert "snils" not in analyze_text("СНИЛС 123-456-788 00")

    def test_snils_100_case(self) -> None:
        # 999-999-999: 9*(9+8+7+6+5+4+3+2+1) = 405 -> 405 % 101 = 1 -> контроль 01
        assert analyze_text("999-999-999 01") == {"snils": 1}

    def test_inn_10_valid(self) -> None:
        # 7707083893 — Сбербанк, известный валидный ИНН
        assert analyze_text("ИНН 7707083893") == {"inn": 1}
        assert "inn" not in analyze_text("ИНН 7707083894")

    def test_inn_12_valid(self) -> None:
        # 500100732259 — известный валидный 12-значный ИНН
        assert analyze_text("ИНН 500100732259") == {"inn": 1}
        assert "inn" not in analyze_text("ИНН 500100732260")

    def test_card_luhn(self) -> None:
        assert analyze_text("карта 4111 1111 1111 1111") == {"card": 1}
        assert "card" not in analyze_text("карта 4111 1111 1111 1112")
        assert analyze_text("4111-1111-1111-1111") == {"card": 1}

    def test_empty_text(self) -> None:
        assert analyze_text("") == {}

    def test_combined(self) -> None:
        text = "email: a@b.ru, тел: +7 912 345-67-89, ИНН 7707083893"
        hits = analyze_text(text)
        assert hits == {"email": 1, "phone": 1, "inn": 1}


class TestAnalyzeFile:
    def test_csv(self, tmp_path: Path) -> None:
        target = tmp_path / "export.csv"
        target.write_text("name,email\nИван,ivanov@example.com\n", encoding="utf-8")
        assert analyze_file(target) == {"email": 1}

    def test_non_textual_ignored(self, tmp_path: Path) -> None:
        target = tmp_path / "photo.jpg"
        target.write_bytes(b"a@b.com")
        assert analyze_file(target) == {}

    def test_docx_as_zip(self, tmp_path: Path) -> None:
        target = tmp_path / "letter.docx"
        with zipfile.ZipFile(target, "w") as zf:
            zf.writestr("word/document.xml", "<xml>office@example.com</xml>")
            zf.writestr("word/sharedStrings.xml", "<xml>+7 912 345-67-89</xml>")
        assert analyze_file(target) == {"email": 1, "phone": 1}

    def test_xlsx_shared_strings(self, tmp_path: Path) -> None:
        target = tmp_path / "table.xlsx"
        with zipfile.ZipFile(target, "w") as zf:
            zf.writestr("xl/sharedStrings.xml", "<xml>worker@example.com</xml>")
        assert analyze_file(target) == {"email": 1}

    def test_corrupt_zip_returns_empty(self, tmp_path: Path) -> None:
        target = tmp_path / "broken.docx"
        target.write_bytes(b"not a zip at all" * 10)
        assert analyze_file(target) == {}

    def test_read_limit(self, tmp_path: Path) -> None:
        target = tmp_path / "big.log"
        # email за пределами лимита не должен считаться
        target.write_bytes(b"a@before.com" + b"x" * 1000 + b"a@after.com")
        hits = analyze_file(target, read_limit=100)
        assert hits == {"email": 1}

    def test_unreadable_returns_empty(self, tmp_path: Path) -> None:
        target = tmp_path / "note.txt"
        target.write_text("a@b.com")
        target.chmod(0)
        try:
            assert analyze_file(target) == {}
        finally:
            target.chmod(0o644)


def test_defaults() -> None:
    assert DEFAULT_READ_LIMIT == 20 * 1024 * 1024
    assert ".csv" in TEXTUAL_EXTS and ".log" in TEXTUAL_EXTS
    assert ".pdf" not in TEXTUAL_EXTS
