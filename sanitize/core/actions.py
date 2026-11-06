"""Действия над файлами: zero / delete / stub с сохранением атрибутов (AGENTS.md, раздел 9).

Гарантии:
- report_only-категории никогда не обрабатываются (защита на уровне ядра);
- симлинки пропускаются (note="skipped_symlink"), цель не трогается;
- до изменения считается sha256 (стримингом), если не передан no_hash;
- ZERO/STUB восстанавливают uid/gid/mode/atime/mtime; пустые файлы при ZERO
  пропускаются (note="skipped_empty");
- идемпотентность: повторный ZERO -> skipped_empty, повторный DELETE -> already_absent;
- каталоги никогда не удаляются.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import stat
import threading
import zipfile
from collections.abc import Callable, Iterable
from pathlib import Path

from sanitize.core.models import Action, ActionResult, FileEntry
from sanitize.core.presets import Preset

logger = logging.getLogger(__name__)

_HASH_CHUNK = 4 * 1024 * 1024


def sha256_of(path: Path) -> str:
    """Стриминговый sha256 файла."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _restore_attrs(path: Path, st: os.stat_result) -> None:
    """Восстанавливает владельца, права и время после перезаписи содержимого."""
    os.chown(path, st.st_uid, st.st_gid)
    os.chmod(path, stat.S_IMODE(st.st_mode))
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))


def _zero(path: Path, st: os.stat_result) -> None:
    """Обнуляет файл, сохраняя атрибуты."""
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
    os.close(fd)
    _restore_attrs(path, st)


def _write_preserving(path: Path, content: bytes, st: os.stat_result) -> None:
    """Перезаписывает содержимое, сохраняя атрибуты."""
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
    try:
        os.write(fd, content)
    finally:
        os.close(fd)
    _restore_attrs(path, st)


def _build_stub_pdf() -> bytes:
    """Минимально валидный одностраничный PDF с текстом SANITIZED."""
    text = b"BT /F1 12 Tf (SANITIZED) Tj ET\n"
    stream = b"<< /Length %d >>\nstream\n%sendstream" % (len(text), text)
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents 4 0 R >>",
        stream,
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (number, body)
    xref_offset = len(out)
    out += b"xref\n0 %d\n" % (len(objects) + 1)
    out += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref_offset,
    )
    return bytes(out)


def _build_stub_zip() -> bytes:
    """Пустой валидный zip-контейнер (для .zip/.docx/.xlsx/.pptx)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as zf:
        zf.comment = b"sanitized"
    return buffer.getvalue()


_STUB_TEXT_EXT = frozenset({".txt", ".csv", ".tsv", ".md", ".log"})
_STUB_ZIP_EXT = frozenset({".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"})


def stub_content(name: str) -> bytes | None:
    """Содержимое заглушки по имени файла; None — заменить обнулением."""
    lowered = name.lower()
    if lowered.endswith(".pdf"):
        return _build_stub_pdf()
    if any(lowered.endswith(ext) for ext in _STUB_ZIP_EXT):
        return _build_stub_zip()
    if any(lowered.endswith(ext) for ext in _STUB_TEXT_EXT):
        return b"\n"
    return None


def _process(
    entry: FileEntry,
    action: Action,
    report_only_ids: frozenset[str],
    no_hash: bool,
) -> ActionResult:
    path = entry.path
    if entry.category_id in report_only_ids:
        return ActionResult(
            entry, action, ok=False, error="report_only: категория защищена от изменений"
        )
    try:
        if path.is_symlink():
            return ActionResult(entry, action, ok=True, note="skipped_symlink")

        if action is Action.DELETE:
            digest: str | None = None
            if not no_hash:
                try:
                    digest = sha256_of(path)
                except FileNotFoundError:
                    digest = None  # файл уже удалён — идемпотентный повтор
            try:
                os.remove(path)
            except FileNotFoundError:
                return ActionResult(entry, action, ok=True, sha256=digest, note="already_absent")
            return ActionResult(entry, action, ok=True, sha256=digest)

        if action not in (Action.ZERO, Action.STUB):
            return ActionResult(entry, action, ok=False, error=f"неизвестное действие: {action}")

        st = os.stat(path)
        if st.st_size == 0 and action is Action.ZERO:
            return ActionResult(entry, action, ok=True, note="skipped_empty")
        digest = None if no_hash else sha256_of(path)

        if action is Action.STUB:
            content = stub_content(path.name)
            if content is None:
                _zero(path, st)
            else:
                _write_preserving(path, content, st)
        else:
            _zero(path, st)
        return ActionResult(entry, action, ok=True, sha256=digest)
    except OSError as exc:
        logger.warning("Ошибка обработки %s: %s", path, exc)
        return ActionResult(entry, action, ok=False, error=str(exc))


def apply(
    entries: Iterable[FileEntry],
    action: Action,
    *,
    preset: Preset,
    no_hash: bool = False,
    cancel_event: threading.Event | None = None,
    on_result: Callable[[ActionResult], None] | None = None,
) -> list[ActionResult]:
    """Применяет действие к каждому файлу, возвращает результаты по-файлово.

    QUARANTINE пока не поддерживается (фаза 6, AGENTS.md).
    """
    if action is Action.QUARANTINE:
        raise NotImplementedError("QUARANTINE реализуется в фазе 6 (AGENTS.md, раздел 10)")

    report_only_ids = frozenset(cat.id for cat in preset.categories if cat.report_only)
    results: list[ActionResult] = []
    for entry in entries:
        if cancel_event is not None and cancel_event.is_set():
            break
        result = _process(entry, action, report_only_ids, no_hash)
        results.append(result)
        if on_result is not None:
            on_result(result)
    return results
