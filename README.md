# sanitize

**English** | [Русский](README.ru.md)

A Linux utility with CLI, Qt GUI, and optional TUI for finding and sanitizing
files that may contain personal data or secrets in web projects, especially
1C-Bitrix sites. It scans recursively for documents, spreadsheets, archives,
keys, signatures, backups, mail, and logs.

By default, sanitize **truncates files to zero bytes** while preserving their
ownership, permissions, and modification time. It can also delete files, replace
them with stubs, or move them into a quarantine archive. The Bitrix preset skips
CMS service directories; truncation keeps the file paths referenced by `b_file`.
Check the website after sanitizing a copy of your project.

## Download the application

[Download AppImage 1.0.2 for Linux x86_64](https://github.com/Mamishev/sanitize/releases/download/v1.0.2/sanitize-1.0.2-x86_64.AppImage)
— no Python installation required.

[Release files, source archives, and SHA256 checksums](https://github.com/Mamishev/sanitize/releases/tag/v1.0.2)

```bash
chmod +x sanitize-1.0.2-x86_64.AppImage
./sanitize-1.0.2-x86_64.AppImage
```

Running the AppImage without arguments opens the GUI. Pass CLI arguments to use
it from a terminal:

```bash
./sanitize-1.0.2-x86_64.AppImage --path /var/www/site --dry-run
```

The AppImage has passed container smoke tests on Ubuntu 24.04/26.04 and Debian 13
with X11 and Wayland. Local startup was also tested on CachyOS x86_64; fontconfig
warnings about newer system font rules may appear there. Windows and macOS are
not supported.

If FUSE is unavailable:

```bash
APPIMAGE_EXTRACT_AND_RUN=1 ./sanitize-1.0.2-x86_64.AppImage
```

## Install the Python package

Requires Linux and **Python 3.11+**. Install the tagged source into an isolated
environment using pipx:

```bash
# CLI only
pipx install 'git+https://github.com/Mamishev/sanitize.git@v1.0.2'

# CLI and GUI (PySide6)
pipx install 'sanitize[gui] @ git+https://github.com/Mamishev/sanitize.git@v1.0.2'

# CLI, GUI, file signatures, and TUI
pipx install 'sanitize[gui,magic,tui] @ git+https://github.com/Mamishev/sanitize.git@v1.0.2'
```

Alternatively, use uv:

```bash
uv tool install 'sanitize[gui,magic,tui] @ git+https://github.com/Mamishev/sanitize.git@v1.0.2'
```

The optional `magic` extra also needs the system libmagic library. The project is
not published to PyPI; use the Git URL above or a wheel from GitHub Releases.

The application UI and CLI messages are currently in Russian. The detailed user
guide and Bitrix notes linked below are also in Russian.

## Quick start

Always inspect the results on a development or test copy first:

```bash
# Preview files and category totals without changing anything
sanitize --path /var/www/site --dry-run

# Truncate matching files; --yes bypasses the confirmation prompt
sanitize --path /var/www/site --zero --yes

# Save a scan report for review
sanitize --path /var/www/site --dry-run --report report.json
sanitize --path /var/www/site --dry-run --report report.md
```

### Actions

| Option | Behavior |
|---|---|
| `--zero` (default) | Truncate files while preserving uid/gid, permissions, and mtime. Keep paths referenced by `b_file`. |
| `--delete` | Delete files. Interactive confirmation requires typing `DELETE`. |
| `--stub` | Replace content with minimal stubs (PDF/ZIP/text). |
| `--quarantine DIR` | Create a tar.gz archive with `manifest.json`, then remove the originals. `DIR` must be outside the project root. |

### Restore quarantined files

```bash
sanitize restore /var/quarantine/sanitize-quarantine-20261106-120000-000000.tar.gz --dry-run
sanitize restore /var/quarantine/sanitize-quarantine-20261106-120000-000000.tar.gz
```

Existing files are not overwritten. Permissions and mtime are restored;
restoring ownership is best effort and depends on privileges.

### Useful options

```text
--dry-run                      Preview without changing files
--preset bitrix|generic        Select a scan profile
--category docs,archives,keys  Scan selected categories
--ext .foo,.bar                Add file extensions
--exclude 'upload/private/**'  Exclude a glob; repeat as needed
--include-hidden              Include .env, .htpasswd, and other hidden files
--min-size 1M --older-than 90d Filter by size and age
--magic                        Detect file types by signature when not recognized by name
--deep-scan                    Look for personal data in supported file contents
--threads N                    Parallel traversal of supported subdirectory groups
--sql FILE                     Generate b_file FILE_SIZE = 0 SQL after --zero
--tui                          Open the Textual terminal interface (tui extra)
--json                         Write machine-readable output to stdout
--report FILE.json|FILE.md     Save a report
--yes                          Bypass interactive confirmation
```

Deep scanning detects email addresses, Russian phone and passport numbers,
SNILS and INN identifiers, and payment card numbers. It uses checksums where
supported and reads up to a configured size limit per file.
The optional SQL output is a script for review; sanitize does not connect to the database.

### Ignore rules

Place `.sanitizeignore` in the project root to exclude paths using a subset of
gitignore syntax:

```gitignore
# Ignore old uploads and logs
upload/old_forms/
*.log
/public_docs/**
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Some files could not be processed, for example due to permissions |
| `2` | Report-only configuration files containing potential secrets were found; useful in CI/hooks |
| `3` | Refused: unsafe path, missing confirmation, or invalid arguments |
| `130` | Interrupted by the user |

### Bitrix categories

Documents · Spreadsheets/exports · Presentations · Archives · Keys/signatures ·
Backups/dumps · Mail/contacts · Audio/video (disabled by default) · Logs/cache ·
Configuration files with potential secrets (report only).

Images are intentionally excluded. See the [Bitrix notes](docs/bitrix-notes.md)
and [user guide](docs/user-guide.md) (Russian) for profile details.

## GUI

```bash
sanitize --gui
# or
sanitize-gui
```

A single window contains scan settings, progress, a filterable results tree with
tri-state checkboxes, and action controls. Scans and actions run in background
threads and support cancellation. Configuration files with potential secrets are
visible but cannot be selected for modification. File context actions let you
open a directory, copy a path, or exclude a directory from subsequent scans.

Keyboard shortcuts: `Ctrl+F` focuses the path field, `Enter` in that field starts
a scan, and `Esc` stops it (or closes an open help popup).
Settings are stored under `~/.config/sanitize/`.

## TUI over SSH

```bash
sanitize --tui
```

Requires the `tui` extra (Textual). Provides a path field, category selection,
results, and zero/delete actions with confirmation.

## Development

```bash
git clone https://github.com/Mamishev/sanitize.git
cd sanitize
uv sync --all-extras
uv run sanitize --help
uv run sanitize --gui
uv run pytest -q
QT_QPA_PLATFORM=offscreen uv run pytest tests/test_gui.py
uv run ruff check .
uv run ruff format --check .
uv run mypy sanitize/core
```

Read [AGENTS.md](AGENTS.md) and the [contribution guidelines](CONTRIBUTING.md)
before making changes. Destructive tests must use temporary fixtures.

## Safety and limitations

- `--dry-run` does not modify scanned files.
- Without `--yes`, changes require confirmation in a TTY; otherwise the CLI exits with code `3`.
- Interactive deletion requires typing `DELETE`; `--yes` bypasses this prompt.
- System roots such as `/`, `/home`, `/usr`, `/etc`, and `/var` are rejected.
- Report-only configurations such as `.env`, `bitrix/.settings.php`, and `dbconn.php` are never modified.
- Symlinks are skipped during actions; external targets are not modified.
- File cleanup is not full anonymization. Images, database contents, Git history,
  and other sources outside the scan scope may still contain personal data or secrets.
- Verification that the public website and Bitrix admin interface work after cleanup
  on a running staging copy remains a separate acceptance check.

## Help and contributions

[Report a bug](https://github.com/Mamishev/sanitize/issues) ·
[Contribute](CONTRIBUTING.md) · [Report a vulnerability](SECURITY.md)

## License

Project code and documentation are released under the [0BSD license](LICENSE).
Dependencies retain their own licenses; see [third-party components](docs/third-party.md).
Icon provenance is documented [here](sanitize/gui/icons/README.md).

See the [distribution guide](docs/distribution.md) (Russian) for packaging and
installation details.
