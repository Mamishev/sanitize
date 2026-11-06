# AGENTS.md — проект `sanitize`

Инструкции для агентов и разработчиков, работающих с этим репозиторием.
Прочитай целиком перед внесением изменений.

---

## 1. Назначение проекта

`sanitize` — утилита для Linux (CLI + GUI на Qt), которая рекурсивно находит в веб-проекте
(в первую очередь — CMS 1С-Битрикс) файлы, потенциально содержащие персональные данные и секреты
(документы, таблицы, презентации, архивы, подписи/ключи, бэкапы/дампы, почта, логи),
и **обнуляет их (по умолчанию) или удаляет (`--delete`)**.

Цель — подготовка dev-стенда для агентной работы с веб-проектом: после прогона утилиты на стенде
не должно остаться файлов с ПДн пользователей, при этом **сайт на Битрикс должен продолжать работать**.

Ключевые принципы:
1. **Безопасность по умолчанию**: `--dry-run` ничего не меняет; без явного подтверждения ничего не удаляется.
2. **Не ломать CMS**: служебные каталоги Битрикс не трогаем; обнуление вместо удаления сохраняет валидность записей `b_file`.
3. **Идемпотентность**: повторный запуск на уже очищенном стенде ничего не делает и не падает.
4. **Воспроизводимость**: каждое действие фиксируется в отчёте (JSON) с путём, размером, sha256, владельцем, правами.
5. **Один `core` — несколько интерфейсов**: CLI, GUI (PySide6) и опционально TUI используют один и тот же код ядра.

---

## 2. Стек и требования

- Python **3.11+**
- GUI: **PySide6** (Qt 6)
- CLI: `argparse` (без внешних зависимостей в ядре)
- Опционально (extras): `python-magic` (определение типа по сигнатуре), `textual` (TUI)
- Тесты: `pytest`, `pytest-qt`
- Линтеры/форматтеры: `ruff` (lint + format), `mypy --strict` для `sanitize/core`
- Сборка/упаковка: `pyproject.toml` (PEP 621), установка через `pipx`; AppImage — отдельной задачей
- Целевая ОС: Linux (Debian/Ubuntu, RHEL-семейство). Windows/macOS **не поддерживаем** и не тратим на них время.

Менеджер зависимостей: `uv` (предпочтительно) или `pip` + `venv`. Не добавляй зависимости в ядро без необходимости.

---

## 3. Структура репозитория

```
sanitize/
├── AGENTS.md
├── README.md
├── pyproject.toml
├── sanitize/
│   ├── __init__.py          # __version__
│   ├── __main__.py          # python -m sanitize → cli.main()
│   ├── core/                # Ядро. Без Qt, без print(), только logging.
│   │   ├── __init__.py
│   │   ├── models.py        # dataclasses: FileEntry, Category, ScanResult, ActionResult, ScanOptions
│   │   ├── presets.py       # загрузка профилей из presets/*.toml
│   │   ├── scanner.py       # обход ФС, классификация, фильтры, отмена, прогресс-колбэки
│   │   ├── actions.py       # zero / delete / stub / quarantine, сохранение атрибутов
│   │   ├── content.py       # опц.: поиск ПДн по содержимому (regex)
│   │   ├── magic.py         # опц.: определение типа по сигнатуре (graceful fallback без python-magic)
│   │   ├── report.py        # JSON/Markdown-отчёт, манифест карантина
│   │   └── safety.py        # защита от опасных путей, проверка маркеров проекта
│   ├── presets/
│   │   ├── bitrix.toml
│   │   └── generic.toml
│   ├── cli.py               # argparse, вывод в терминал, exit-коды
│   ├── tui.py               # опц.: Textual (фаза 6)
│   └── gui/
│       ├── __init__.py
│       ├── app.py           # точка входа GUI: sanitize --gui / sanitize-gui
│       ├── main_window.py   # единственное окно по макету (раздел 7)
│       ├── worker.py        # QObject+QThread обёртки над scanner/actions, сигналы прогресса
│       ├── results_model.py # QAbstractItemModel: категории → файлы, tri-state чекбоксы
│       ├── dialogs.py       # подтверждение действия, итоговая сводка
│       └── settings.py      # QSettings (~/.config/sanitize/)
├── tests/
│   ├── conftest.py          # фикстура fake_bitrix_tree(tmp_path)
│   ├── test_scanner.py
│   ├── test_actions.py
│   ├── test_presets.py
│   ├── test_safety.py
│   ├── test_cli.py
│   ├── test_report.py
│   └── test_gui.py          # pytest-qt, offscreen (QT_QPA_PLATFORM=offscreen)
└── docs/
    └── bitrix-notes.md      # что и почему исключено/включено для Битрикс
```

Правила слоёв:
- `core` **не импортирует** `PySide6`, `cli`, `gui`. Нарушение — блокер ревью.
- `gui` и `cli` не содержат логики классификации/удаления — только вызовы `core`.
- Прогресс из `core` передаётся через колбэки/генераторы; отмена — через `threading.Event`.

---

## 4. Команды разработки

```bash
uv sync --all-extras                  # установка зависимостей
uv run sanitize --help                # CLI
uv run sanitize --gui                 # GUI
uv run pytest -q                      # тесты
QT_QPA_PLATFORM=offscreen uv run pytest tests/test_gui.py
uv run ruff check . && uv run ruff format --check .
uv run mypy sanitize/core
```

Перед коммитом: `ruff`, `mypy` (для core), `pytest` — зелёные. CI повторяет те же команды.

---

## 5. Модель данных (`core/models.py`)

```python
class Action(Enum): ZERO, DELETE, STUB, QUARANTINE

@dataclass(frozen=True)
class Category:
    id: str              # "docs", "sheets", "slides", "archives", "keys", "backups", "mail", "media", "logs", "secrets_report"
    title: str
    extensions: frozenset[str]        # нижний регистр, с точкой; поддержка двойных: ".tar.gz"
    names: frozenset[str] = ()        # точные имена без расширения: "id_rsa", ".env"
    only_under: tuple[str, ...] = ()  # ограничить поиском внутри путей (например, ".txt" только в /upload/)
    default_enabled: bool = True
    risk: Literal["low", "medium", "high"] = "medium"
    report_only: bool = False         # показывать, но никогда не изменять (конфиги с секретами)

@dataclass
class FileEntry:
    path: Path
    size: int
    mtime: float
    uid: int; gid: int; mode: int
    category_id: str
    risk_dirs: tuple[str, ...]        # совпавшие рискованные каталоги (webform, sale, backup, …)
    detected_by: Literal["ext", "name", "magic"]
    content_hits: dict[str, int] = field(default_factory=dict)  # "email": 12, "phone": 3 (deep-scan)

@dataclass
class ScanOptions:
    root: Path
    preset: str = "bitrix"
    categories: set[str] | None = None     # None = default_enabled из профиля
    extra_extensions: set[str] = ()
    exclude_globs: list[str] = ()
    include_hidden: bool = False
    follow_symlinks: bool = False          # по умолчанию НЕ следуем
    one_filesystem: bool = True
    min_size: int = 0
    older_than: timedelta | None = None
    use_magic: bool = False
    deep_scan: bool = False
    threads: int = 4

@dataclass
class ActionResult:
    entry: FileEntry
    action: Action
    ok: bool
    error: str | None = None
    sha256: str | None = None              # считается до изменения (для отчёта)
```

---

## 6. Профиль `bitrix` (`presets/bitrix.toml`) — содержание

### 6.1 Категории и расширения

| id | Расширения / имена | default | risk |
|---|---|---|---|
| `docs` | `.pdf .doc .docx .docm .dot .dotx .rtf .odt .ott .pages .epub .djvu .xps .oxps`; `.txt .md` — только под `upload/` | on | medium |
| `sheets` | `.xls .xlsx .xlsm .xlsb .ods .csv .tsv .numbers`; `.xml .json .yaml .yml` — только под `upload/` | on | high |
| `slides` | `.ppt .pptx .pptm .pps .ppsx .odp .key` | on | medium |
| `archives` | `.zip .rar .7z .tar .gz .tgz .bz2 .xz .zst .tar.gz .tar.bz2 .tar.xz .cab .arj .lzh .iso .dmg` | on | high |
| `keys` | `.sig .p7s .p7b .cer .crt .der .pem .key .p12 .pfx .jks .keystore .ppk .asc .gpg .pgp .kdbx .kdb`; имена `id_rsa id_dsa id_ecdsa id_ed25519` | on | high |
| `backups` | `.sql .sql.gz .dump .bak .backup .enc .mdb .accdb .sqlite .sqlite3 .db .fdb .dbf`; всё содержимое `bitrix/backup/` | on | high |
| `mail` | `.eml .msg .pst .ost .mbox .vcf .ics` | on | high |
| `media` | `.mp3 .wav .ogg .m4a .amr .mp4 .webm .mov .avi .mkv` | **off** | low |
| `logs` | `.log .log.* .tmp .temp .swp .~lock*`; каталоги `bitrix/tmp/ upload/tmp/ bitrix/cache/ bitrix/managed_cache/ bitrix/stack_cache/ bitrix/html_pages/` | on | medium |
| `secrets_report` | `bitrix/.settings.php bitrix/.settings_extra.php bitrix/php_interface/dbconn.php .env .env.* .htpasswd .my.cnf .pgpass .netrc` | on, `report_only=true` | high |

Изображения (`.jpg .png .gif .webp .svg …`) **намеренно не включены**.

### 6.2 Исключённые каталоги (никогда не обходим)

```
bitrix/modules bitrix/components bitrix/templates bitrix/js bitrix/themes bitrix/wizards
bitrix/gadgets bitrix/activities bitrix/panel bitrix/images bitrix/css bitrix/fonts
local/ vendor/ node_modules/ .git/ .svn/ .hg/ .idea/ .vscode/ upload/resize_cache/
```

### 6.3 Рискованные каталоги (подсветка в отчёте и GUI)

```
upload/webform upload/form upload/sale upload/crm upload/support upload/mail upload/tasks
upload/disk upload/1c_exchange upload/1c_catalog upload/iblock upload/main upload/medialibrary
bitrix/backup
```

### 6.4 Маркеры проекта

Если в корне нет ни `bitrix/`, ни `upload/` — CLI предупреждает и требует подтверждения (или `--yes`); GUI показывает предупреждение в диалоге подтверждения.

---

## 7. Спецификация CLI

```
sanitize [--path DIR] [--dry-run]
         [--zero | --delete | --stub | --quarantine DIR]
         [--preset bitrix|generic] [--category ID,...] [--ext .x,.y]
         [--exclude GLOB]... [--include-hidden] [--follow-symlinks] [--no-one-filesystem]
         [--min-size SIZE] [--older-than DURATION]
         [--magic] [--deep-scan] [--threads N]
         [--report FILE.json] [--json] [--yes] [--quiet] [--verbose]
         [--gui] [--version]
```

Поведение:
- `--path` по умолчанию — текущая папка. Путь нормализуется через `Path.resolve()`.
- Действие по умолчанию — `--zero`. `--delete` — удаление. Флаги действий взаимоисключающие.
- `--dry-run` — только вывод списка и сводки (количество, суммарный размер по категориям), ничего не меняет.
- Без `--dry-run` и без `--yes` — интерактивное подтверждение с итогом; для `--delete` требуется ввести `DELETE`.
- Если stdin не TTY и нет `--yes` — завершение с кодом 3 и сообщением.
- `--json` — машиночитаемый вывод в stdout (для `--dry-run` и для результатов действий).
- Exit-коды: `0` — успех; `1` — часть файлов не удалось обработать (нет доступа); `2` — найдены `report_only` файлы (секреты в конфигах) — для использования в CI/hook; `3` — отказ (небезопасный путь, нет подтверждения, неверные аргументы); `130` — прервано пользователем.
- `safety.py` отказывается работать (код 3) с `/`, `/home`, `/root`, `/usr`, `/etc`, `/var`, `/opt`, `/srv`, `/tmp` как с корнем целиком (подкаталоги разрешены, например `/var/www/site`).

---

## 8. Спецификация GUI (единственное окно)

```
┌──────────────────────────────────────────────────────────────────┐
│ Путь: [/var/www/site________________] [Обзор…]   [🔍 Найти] [⏹] │
│ Профиль: (•) Битрикс ( ) Общий                                   │
│ ☑ Документы ☑ Таблицы/экспорт ☑ Презентации ☑ Архивы             │
│ ☑ Подписи/ключи ☑ Бэкапы/дампы ☑ Почта/контакты ☐ Аудио/видео    │
│ ☑ Логи и кэш  ☑ Исключить служебные каталоги Битрикс             │
│ ☐ Проверять по сигнатуре (magic) ☐ Глубокий поиск ПДн            │
│ ☐ Следовать по симлинкам  ☐ Скрытые файлы                        │
├──────────────────────────────────────────────────────────────────┤
│ [████████████░░░░░░░░░] 61%  Сканирую: /upload/iblock/4f3/…      │
│ Найдено: 1 234 файла, 3,4 ГБ · Пропущено: 15 (нет доступа)       │
├──────────────────────────────────────────────────────────────────┤
│ Фильтр: [__________]                            [Свернуть всё]   │
│ ☑ ▸ 📄 Документы (812, 1,2 ГБ)                                    │
│ ☑ ▾ 💾 Бэкапы и дампы (3, 1,9 ГБ)  ⚠️ высокий риск                │
│   ☑ /bitrix/backup/20260105_full.tar.gz   1,8 ГБ   2026-01-05     │
│ ☐ ▸ ⚠️ Конфиги с секретами — только отчёт (3)                     │
├──────────────────────────────────────────────────────────────────┤
│ Действие: (•) Обнулить  ( ) Удалить (--delete)  ( ) Карантин → […]│
│ ☑ Сохранять владельца/права/mtime                                 │
│ [Сохранить отчёт…]                    [▶ Выполнить для выбранных] │
└──────────────────────────────────────────────────────────────────┘
```

Требования:
- Три блока сверху вниз: **параметры поиска → прогресс → результаты → действия**. Окно одно, без вкладок.
- Сканирование и действия выполняются в `QThread` (`gui/worker.py`), UI не блокируется. Кнопка «⏹» ставит `cancel_event`.
- Прогресс: фаза 1 — indeterminate («Подсчёт каталогов…»), фаза 2 — determinate по числу обработанных записей; текст текущего пути обрезается слева (`elide left`).
- Результаты — `QTreeView` + `results_model.py`: уровень 1 — категории (счётчик файлов, суммарный размер, метка риска), уровень 2 — файлы (путь относительно корня, размер, дата). Tri-state чекбоксы. Категория `secrets_report` по умолчанию снята и **не выбираема** для действий (только просмотр и попадание в отчёт).
- Контекстное меню файла: «Открыть каталог», «Копировать путь», «Исключить каталог из поиска» (добавляет в `exclude_globs` на текущую сессию).
- Фильтр по подстроке пути (`QSortFilterProxyModel`, рекурсивная фильтрация).
- Кнопка «Выполнить» активна только при наличии выбранных файлов. Диалог подтверждения показывает: действие, число файлов, объём, предупреждение о маркерах проекта. Для «Удалить» — поле ввода `DELETE`.
- После выполнения: сводка (успешно / ошибки) и кнопка «Открыть отчёт»; обработанные файлы в дереве помечаются серым/зачёркнуто, не исчезают.
- При ошибках доступа — предлагать команду для копирования: `sudo sanitize --path … --report … [--delete]`. GUI под root не запускаем и не рекомендуем.
- Настройки (последний путь, чекбоксы, геометрия) — `QSettings("sanitize", "sanitize")`.
- Горячие клавиши: `Ctrl+F` — фокус на путь, `Enter` в поле пути — Найти, `Esc` — Стоп.

---

## 9. Детали реализации ядра

### scanner.py
- Обход через `os.scandir` (быстрее `os.walk`), рекурсивно; не заходим в симлинки на каталоги, если `follow_symlinks=False`; файлы-симлинки учитываем как симлинки (не трогаем цель).
- `one_filesystem=True` — сравнивать `st_dev` с корнем.
- Классификация: сначала точное имя (`names`), затем двойное расширение (`.tar.gz`), затем одинарное; всё в нижнем регистре. Для категорий с `only_under` — проверка относительного пути.
- Исключённые каталоги проверяются по относительному пути от корня (поддержка Битрикс в подкаталоге: ищем первое вхождение `bitrix/`).
- `use_magic=True` — только для файлов, не распознанных по расширению, и файлов без расширения; при отсутствии `python-magic` — предупреждение, не падение.
- Прогресс: колбэк `on_progress(done: int, total: int | None, current: Path)` не чаще ~20 раз/сек (троттлинг в scanner, не в GUI).
- Ошибки доступа (`PermissionError`) собираются в `ScanResult.skipped`, не прерывают обход.

### actions.py
- **ZERO**: `os.stat` → открыть `O_WRONLY|O_TRUNC` → восстановить `chown`, `chmod`, `utime`. Уже пустые файлы пропускаются (`ok=True`, `error=None`, помечаются `skipped_empty`).
- **DELETE**: `os.remove`. Каталоги не удаляем, даже если опустели.
- **STUB**: минимально валидный файл по типу (`.pdf` — однострочный PDF с текстом `SANITIZED`, `.zip`/`.docx`/`.xlsx`/`.pptx` — пустой zip-контейнер, `.csv`/`.txt` — пустая строка); для неизвестных — как ZERO. Атрибуты сохраняются.
- **QUARANTINE**: `tar.gz` в указанный каталог (должен быть **вне** `root`, иначе отказ) + `manifest.json`; после упаковки исходники удаляются. Отдельная команда `sanitize restore ARCHIVE` — фаза 6.
- Для всех действий до изменения считается `sha256` (стримингом; для файлов > 1 ГБ — опционально через `--no-hash`).
- Никогда не обрабатываем `report_only` категории — защита на уровне `actions.py`, не только GUI/CLI.
- Не следуем по симлинкам при действиях: для symlink-файла — удаляем/обнуляем сам линк? **Нет**: симлинки пропускаем с пометкой `skipped_symlink`.

### safety.py
- Чёрный список корней (раздел 7), проверка, что `root` существует и это каталог, проверка маркеров проекта.
- Проверка, что `quarantine_dir` не внутри `root`.

### report.py
- JSON: метаданные запуска (версия, время, host, root, опции), сводка по категориям, список `ActionResult`/`FileEntry`, ошибки.
- Markdown-версия для людей (`--report file.md` — по расширению).

---

## 10. План работ (фазы и задачи)

Отмечай выполненные пункты `[x]`. Не переходи к следующей фазе, пока тесты текущей не зелёные.

### Фаза 0 — Каркас
- [x] `pyproject.toml`: метаданные, `[project.scripts] sanitize = "sanitize.cli:main"`, `sanitize-gui = "sanitize.gui.app:main"`, extras `gui`, `magic`, `tui`, `dev`
- [x] `ruff`, `mypy`, `pytest` конфигурация; `.github/workflows/ci.yml` (lint + tests, `QT_QPA_PLATFORM=offscreen`)
- [x] Структура каталогов из раздела 3, пустые модули с докстрингами
- [x] `tests/conftest.py`: фикстура `fake_bitrix_tree` — создаёт дерево с `bitrix/{modules,backup,cache,.settings.php}`, `upload/{iblock,webform,resize_cache,tmp}`, `local/`, файлы всех категорий, симлинк наружу, файл без прав

### Фаза 1 — Ядро: модели, профили, сканер
- [x] `models.py` по разделу 5
- [x] `presets.py` + `presets/bitrix.toml`, `presets/generic.toml` (generic = те же категории без `only_under`, без Битрикс-исключений); валидация профиля при загрузке
- [x] `scanner.py`: обход, классификация, исключения, `only_under`, рискованные каталоги, симлинки, `one_filesystem`, фильтры размера/даты, отмена, прогресс
- [x] Тесты: каждая категория находится; `resize_cache` и `bitrix/modules` не обходятся; `.tar.gz` → `archives`, а не `.gz`; `.txt` вне `upload/` игнорируется; симлинк наружу не обходится; `PermissionError` → `skipped`; отмена останавливает обход; регистр расширений

### Фаза 2 — Ядро: действия, отчёт, безопасность
- [x] `actions.py`: ZERO, DELETE с сохранением атрибутов, идемпотентность, пропуск `report_only` и симлинков, sha256
- [x] `safety.py`: чёрный список корней, маркеры проекта
- [x] `report.py`: JSON + Markdown
- [x] Тесты: после ZERO `size == 0`, `uid/gid/mode/mtime` сохранены; повторный ZERO — `skipped_empty`; DELETE удаляет файл и не трогает каталог; попытка действия над `secrets_report` → отказ; симлинк → `skipped_symlink`; отчёт валиден по схеме; `safety` отвергает `/` и `/home`

### Фаза 3 — CLI
- [x] `cli.py` по разделу 7: аргументы, взаимоисключающие действия, `--dry-run`, подтверждение, `DELETE`-ввод, `--json`, exit-коды, человекочитаемая сводка по категориям с размерами
- [x] `__main__.py`
- [x] Тесты через `subprocess`/`CliRunner`-аналог: dry-run ничего не меняет; `--yes --zero` обнуляет; без TTY и без `--yes` → код 3; наличие `.env` → код 2; `--json` парсится
- [x] README: быстрый старт CLI

### Фаза 4 — GUI (PySide6)
- [x] `gui/app.py`: `QApplication`, тема по умолчанию, запуск из `sanitize --gui`
- [x] `gui/worker.py`: `ScanWorker`, `ActionWorker` в `QThread`, сигналы `progress(int,int,str)`, `finished(result)`, `failed(str)`, поддержка отмены
- [x] `gui/results_model.py`: модель дерева с tri-state чекбоксами, сортировкой, прокси-фильтром
- [x] `gui/main_window.py`: макет из раздела 8, связывание сигналов, состояние кнопок (Найти/Стоп/Выполнить), горячие клавиши
- [x] `gui/dialogs.py`: подтверждение (с вводом `DELETE`), сводка результата, подсказка с `sudo`-командой
- [x] `gui/settings.py`: сохранение/восстановление настроек
- [x] Тесты `pytest-qt`: сканирование fake-дерева заполняет модель; снятие чекбокса категории снимает детей; «Выполнить» недоступно без выбора; dry-run из GUI не меняет ФС; отмена сканирования завершает поток
- [ ] Ручная проверка на реальной копии Битрикс-проекта; результат — в `docs/bitrix-notes.md`

### Фаза 5 — Расширения ядра
- [x] `magic.py`: `--magic`, graceful fallback
- [x] `content.py`: `--deep-scan` для текстовых форматов (csv, txt, xml, json, log, sql; docx/xlsx — как zip с `document.xml`/`sharedStrings.xml`): e-mail, телефон РФ, паспорт, СНИЛС (с контрольной суммой), ИНН (с контрольной суммой), номер карты (Луна). Лимит чтения на файл (по умолчанию 20 МБ). Результат — `content_hits`, показ счётчиков в GUI/CLI
- [x] STUB-действие с генераторами минимально валидных файлов
- [x] `.sanitizeignore` в корне проекта (синтаксис gitignore, библиотека `pathspec` в extras или собственный минимальный парсер)
- [x] Многопоточный обход (`ThreadPoolExecutor` по подкаталогам первого уровня `upload/`), замер на дереве ≥ 200k файлов

### Фаза 6 — Карантин, восстановление, упаковка
- [ ] QUARANTINE + `manifest.json`; `sanitize restore ARCHIVE [--dry-run]`
- [ ] Предупреждение о `.git` в корне (файлы могут оставаться в истории)
- [ ] Опциональная генерация SQL для консистентности `b_file` (`FILE_SIZE = 0`) — только файл-скрипт, без подключения к БД
- [ ] `tui.py` на Textual (минимум: путь, чекбоксы, список, действие) — для headless-стендов по SSH
- [ ] AppImage / `pipx` инструкция, `CHANGELOG.md`, версия 1.0.0

---

## 11. Критерии приёмки (Definition of Done для 1.0)

1. На копии реального Битрикс-проекта после `sanitize --zero --yes` сайт открывается, админка работает, публичная часть не отдаёт 500.
2. `sanitize --dry-run` не изменяет ни одного байта (проверяется хэшем дерева в тесте).
3. Повторный запуск — 0 изменённых файлов, код выхода 0 (или 2 при наличии `secrets_report`).
4. Ни один файл из исключённых каталогов не появляется в результатах.
5. Симлинки за пределы корня не обходятся и не изменяются.
6. Все действия отражены в JSON-отчёте с sha256.
7. GUI не блокируется на дереве из 100k файлов; отмена срабатывает < 1 с.
8. `ruff`, `mypy sanitize/core --strict`, `pytest` — зелёные в CI.

---

## 12. Правила для агентов

- **Никогда** не запускай утилиту (даже тесты) против реальных каталогов вне `tmp_path`/фикстур. Любые интеграционные прогоны — только на явно указанной копии проекта по запросу человека.
- Не добавляй в профиль `bitrix` расширения изображений и не снимай исключения служебных каталогов без обсуждения — это ломает принцип «не ломать CMS».
- Любое новое расширение/каталог в профиле сопровождай тестом в `test_scanner.py` и строкой в `docs/bitrix-notes.md` с обоснованием.
- Не вызывай `print()` в `core` — только `logging`. В CLI вывод через `rich`-подобные обёртки не нужен; стандартный `print` допустим только в `cli.py`.
- Не используй `shell=True`, `os.system`, `rm -rf`. Все файловые операции — через `os`/`pathlib` с явной обработкой `PermissionError`, `FileNotFoundError`, `IsADirectoryError`.
- Сохраняй совместимость сигнатур публичных функций `core` (`scan()`, `apply()`, `load_preset()`); при изменении обновляй CLI, GUI и тесты в одном коммите.
- Коммиты атомарные, сообщение в формате `phase-N: краткое описание` (например, `phase-2: actions.zero сохраняет uid/gid/mode/mtime`).
- Перед завершением задачи: обнови чекбоксы в разделе 10, прогони полный набор команд из раздела 4, укажи в PR, что проверено вручную.
- Если требования неоднозначны (например, нестандартная структура проекта без `bitrix/`), — не угадывай: добавь опцию/предупреждение и опиши вопрос в PR.
