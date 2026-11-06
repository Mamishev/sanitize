#!/usr/bin/env python3
"""Сверка сгенерированного b_file.sql с дампом БД (без подключения к БД).

Проверяет, какие пары (FILE_NAME, SUBDIR) из SQL реально существуют в таблице
b_file дампа. Несовпадающие UPDATE — безопасные no-op (WHERE не найдёт строк).

Использование:
    python scripts/check_b_file_sql.py            # значения по умолчанию
    python scripts/check_b_file_sql.py DUMP SQL   # свои пути

Позиции колонок SUBDIR=8, FILE_NAME=9 соответствуют стандартной схеме b_file
(см. schema.sql); при нестандартной схеме поправьте константы ниже.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

DEFAULT_DUMP = "/home/alex/epkr/src/bitrix_db_20261103.sql"
DEFAULT_SQL = "/tmp/opencode/zero_test/b_file.sql"

#: 0-based индексы колонок SUBDIR и FILE_NAME в VALUES (стандартная схема b_file).
SUBDIR_IDX = 7
FILE_NAME_IDX = 8

INSERT_RE = re.compile(rb"INSERT INTO `b_file` VALUES")


def split_rows(statement: bytes) -> list[bytes]:
    """Разбивает extended-INSERT на строки (...) с учётом кавычек."""
    rows: list[bytes] = []
    depth = 0
    in_string = False
    escaped = False
    start = -1
    for pos, byte in enumerate(statement):
        ch = chr(byte)
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "'":
                in_string = False
            continue
        if ch == "'" and depth > 0:
            in_string = True
        elif ch == "(":
            if depth == 0:
                start = pos
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and start >= 0:
                rows.append(statement[start + 1 : pos])
                start = -1
    return rows


def split_values(row: bytes) -> list[str]:
    """Разбивает строку VALUES на значения с учётом кавычек, декодирует."""
    values: list[str] = []
    in_string = False
    escaped = False
    current = bytearray()
    for byte in row:
        ch = chr(byte)
        if in_string:
            current.append(byte)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "'":
                in_string = False
            continue
        if ch == ",":
            values.append(current.decode("utf-8", errors="replace"))
            current = bytearray()
            continue
        current.append(byte)
        if ch == "'":
            in_string = True
    values.append(current.decode("utf-8", errors="replace"))
    return values


def unescape(value: str) -> str:
    if value.startswith("'") and value.endswith("'"):
        value = value[1:-1]
    return value.replace("\\'", "'").replace("''", "'").replace("\\\\", "\\")


def dump_pairs(dump_path: Path) -> set[tuple[str, str]]:
    data = dump_path.read_bytes()
    pairs: set[tuple[str, str]] = set()
    bad_rows = 0
    for match in INSERT_RE.finditer(data):
        end = data.find(b";\n", match.end())
        statement = data[match.end() : end if end != -1 else len(data)]
        for row in split_rows(statement):
            values = split_values(row)
            if len(values) <= max(SUBDIR_IDX, FILE_NAME_IDX):
                bad_rows += 1
                continue
            subdir_raw, name_raw = values[SUBDIR_IDX], values[FILE_NAME_IDX]
            if subdir_raw.upper() == "NULL" or name_raw.upper() == "NULL":
                continue
            pairs.add((unescape(name_raw), unescape(subdir_raw)))
    if bad_rows:
        print(f"  строк с малым числом колонок: {bad_rows}")
    return pairs


def sql_pairs(sql_path: Path) -> set[tuple[str, str]]:
    pattern = re.compile(
        r"UPDATE b_file SET FILE_SIZE = 0 WHERE FILE_NAME = '(.*)' "
        r"AND SUBDIR = '(.*)' AND FILE_SIZE > 0;"
    )
    pairs: set[tuple[str, str]] = set()
    for line in sql_path.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line.strip())
        if match:
            pairs.add((match.group(1), match.group(2)))
    return pairs


def main(argv: list[str]) -> int:
    dump_path = Path(argv[1]) if len(argv) > 1 else Path(DEFAULT_DUMP)
    sql_path = Path(argv[2]) if len(argv) > 2 else Path(DEFAULT_SQL)
    db = dump_pairs(dump_path)
    ours = sql_pairs(sql_path)
    print(f"пар (FILE_NAME, SUBDIR) в дампе b_file: {len(db)}")
    print(f"пар в {sql_path.name}:{' ' * (22 - len(sql_path.name))}{len(ours)}")
    matched = ours & db
    missing = ours - db
    print(
        f"пары найдены в дампе: {' ' * 12}{len(matched)} из {len(ours)} "
        f"({len(matched) * 100 // max(len(ours), 1)}%)"
    )
    for name, subdir in sorted(missing)[:10]:
        print(f"  нет в дампе (UPDATE будет no-op): SUBDIR='{subdir}' FILE_NAME='{name}'")
    print(f"пар в дампе вне SQL (изображения и пр.): {len(db - ours)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
