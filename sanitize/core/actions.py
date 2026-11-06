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

import contextlib
import hashlib
import io
import json
import logging
import os
import re
import socket
import stat
import tarfile
import threading
import time
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
    quarantine_dir: Path | None = None,
    no_hash: bool = False,
    cancel_event: threading.Event | None = None,
    on_result: Callable[[ActionResult], None] | None = None,
) -> list[ActionResult]:
    """Применяет действие к каждому файлу, возвращает результаты по-файлово.

    QUARANTINE требует quarantine_dir (вне корня проекта — проверяется
    и здесь, и в safety.check_quarantine_dir на уровне CLI/GUI).
    """
    report_only_ids = frozenset(cat.id for cat in preset.categories if cat.report_only)
    if action is Action.QUARANTINE:
        if quarantine_dir is None:
            raise ValueError("QUARANTINE требует quarantine_dir")
        return _quarantine(
            entries,
            Path(quarantine_dir),
            report_only_ids,
            no_hash=no_hash,
            cancel_event=cancel_event,
            on_result=on_result,
        )

    results: list[ActionResult] = []
    for entry in entries:
        if cancel_event is not None and cancel_event.is_set():
            break
        result = _process(entry, action, report_only_ids, no_hash)
        results.append(result)
        if on_result is not None:
            on_result(result)
    return results


# --------------------------- карантин (фаза 6) ---------------------------

_MANIFEST_NAME = "manifest.json"
_MEMBER_RE = re.compile(r"^files/\d{6}(?:\.[A-Za-z0-9]+)?$")


@dataclass(frozen=True)
class RestoreEntryResult:
    """Результат восстановления одного файла из архива карантина."""

    path: Path
    ok: bool
    error: str | None = None
    note: str | None = None  # "exists", "dry_run"


def _quarantine(
    entries: Iterable[FileEntry],
    quarantine_dir: Path,
    report_only_ids: frozenset[str],
    *,
    no_hash: bool,
    cancel_event: threading.Event | None,
    on_result: Callable[[ActionResult], None] | None,
) -> list[ActionResult]:
    """Упаковывает файлы в tar.gz с manifest.json, затем удаляет оригиналы."""
    dir_resolved = quarantine_dir.expanduser().resolve()
    for entry in entries:
        # absolute() без разрешения симлинков: линк-файл сам по себе не
        # «находится» в каталоге карантина, даже если его цель — там.
        resolved = entry.path.expanduser().absolute()
        if dir_resolved == resolved or dir_resolved in resolved.parents:
            raise ValueError(
                f"Каталог карантина {dir_resolved} содержит обрабатываемые файлы "
                f"({resolved}) — укажите каталог вне корня проекта."
            )
    dir_resolved.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    archive_path = dir_resolved / f"sanitize-quarantine-{stamp}.tar.gz"

    results: list[ActionResult] = []
    manifest_rows: list[dict[str, Any]] = []
    cancelled = False

    with tarfile.open(archive_path, "w:gz") as tar:
        for index, entry in enumerate(entries):
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                break
            result = _quarantine_one(entry, index, tar, manifest_rows, report_only_ids, no_hash)
            results.append(result)
            if on_result is not None:
                on_result(result)

        if manifest_rows:
            manifest = {
                "sanitize_version": _version(),
                "created_at": datetime.now(UTC).isoformat(),
                "host": socket.gethostname(),
                "cancelled": cancelled,
                "entries": manifest_rows,
            }
            payload = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
            info = tarfile.TarInfo(name=_MANIFEST_NAME)
            info.size = len(payload)
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(payload))

    if not manifest_rows:
        # Нечего архивировать (отмена до старта / все пропущены) — пустой архив не оставляем
        with contextlib.suppress(OSError):
            archive_path.unlink()
    return results


def _quarantine_one(
    entry: FileEntry,
    index: int,
    tar: tarfile.TarFile,
    manifest_rows: list[dict[str, Any]],
    report_only_ids: frozenset[str],
    no_hash: bool,
) -> ActionResult:
    path = entry.path
    if entry.category_id in report_only_ids:
        return ActionResult(
            entry, Action.QUARANTINE, ok=False, error="report_only: категория защищена от изменений"
        )
    try:
        if path.is_symlink():
            return ActionResult(entry, Action.QUARANTINE, ok=True, note="skipped_symlink")
        st = os.stat(path)
        digest = None if no_hash else sha256_of(path)

        suffix = path.suffix.lower() if re.fullmatch(r"\.[A-Za-z0-9]+", path.suffix) else ""
        member = f"files/{index:06d}{suffix}"
        info = tarfile.TarInfo(name=member)
        info.size = st.st_size
        info.mtime = int(st.st_mtime)
        info.mode = stat.S_IMODE(st.st_mode)
        with open(path, "rb") as fh:
            tar.addfile(info, fh)

        try:
            os.remove(path)
        except FileNotFoundError:
            return ActionResult(
                entry, Action.QUARANTINE, ok=True, sha256=digest, note="already_absent"
            )

        manifest_rows.append(
            {
                "member": member,
                "path": str(path),
                "size": st.st_size,
                "mtime": st.st_mtime,
                "uid": st.st_uid,
                "gid": st.st_gid,
                "mode": oct(st.st_mode),
                "sha256": digest,
                "category": entry.category_id,
            }
        )
        return ActionResult(entry, Action.QUARANTINE, ok=True, sha256=digest)
    except OSError as exc:
        logger.warning("Ошибка карантина %s: %s", path, exc)
        return ActionResult(entry, Action.QUARANTINE, ok=False, error=str(exc))


def restore_archive(
    archive: Path,
    *,
    dry_run: bool = False,
    cancel_event: threading.Event | None = None,
) -> list[RestoreEntryResult]:
    """Восстанавливает файлы из архива карантина по manifest.json.

    Существующие файлы не перезаписываются (note="exists").
    Владелец восстанавливается best-effort (без root — пропускается).
    """
    archive_resolved = archive.expanduser().resolve()
    if not archive_resolved.is_file():
        raise FileNotFoundError(f"Архив не найден: {archive_resolved}")

    results: list[RestoreEntryResult] = []
    with tarfile.open(archive_resolved, "r:gz") as tar:
        members = tar.getnames()
        try:
            manifest_member = tar.extractfile(_MANIFEST_NAME)
        except KeyError:
            manifest_member = None
        if manifest_member is None:
            raise ValueError(f"{archive_resolved}: нет {_MANIFEST_NAME} — это не архив карантина")
        manifest = json.loads(manifest_member.read().decode("utf-8"))

        for row in manifest.get("entries", []):
            if cancel_event is not None and cancel_event.is_set():
                break
            results.append(_restore_one(row, tar, members, dry_run))
    return results


def _restore_one(
    row: dict[str, Any],
    tar: tarfile.TarFile,
    members: list[str],
    dry_run: bool,
) -> RestoreEntryResult:
    member = str(row.get("member", ""))
    raw_path = str(row.get("path", ""))
    if not _MEMBER_RE.match(member) or member not in members:
        return RestoreEntryResult(
            Path(raw_path or member), ok=False, error=f"небезопасный member: {member!r}"
        )
    try:
        target = Path(raw_path).resolve()
    except (OSError, ValueError):
        return RestoreEntryResult(Path(raw_path), ok=False, error="некорректный путь в манифесте")
    if not target.is_absolute() or ".." in target.parts:
        return RestoreEntryResult(Path(raw_path), ok=False, error="некорректный путь в манифесте")

    if dry_run:
        return RestoreEntryResult(target, ok=True, note="dry_run")
    if target.exists():
        return RestoreEntryResult(target, ok=True, note="exists")

    extracted = tar.extractfile(member)
    if extracted is None:
        return RestoreEntryResult(target, ok=False, error=f"member не найден: {member}")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = extracted.read()
        target.write_bytes(payload)
        os.chmod(target, int(str(row.get("mode", "0o644")), 8))
        mtime = float(row.get("mtime", time.time()))
        os.utime(target, (mtime, mtime))
        with contextlib.suppress(PermissionError):
            os.chown(target, int(row.get("uid", -1)), int(row.get("gid", -1)))
        return RestoreEntryResult(target, ok=True)
    except OSError as exc:
        return RestoreEntryResult(target, ok=False, error=str(exc))


def _version() -> str:
    from sanitize import __version__

    return __version__
