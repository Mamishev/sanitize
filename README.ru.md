# sanitize

[English](README.md) | **Русский**

Утилита для Linux (CLI + GUI на Qt), которая рекурсивно находит в веб-проекте
(в первую очередь — CMS 1С-Битрикс) файлы с персональными данными и секретами
(документы, таблицы, архивы, ключи/подписи, бэкапы, почта, логи) и **обнуляет
их (по умолчанию) или удаляет (`--delete`)**. Служебные каталоги Битрикс не
затрагиваются, а обнуление сохраняет файлы, на которые ссылается `b_file`.
После очистки работу конкретного сайта нужно проверить.

## Установка

```bash
# pipx (рекомендуется для CLI-инструмента):
pipx install 'git+https://github.com/Mamishev/sanitize.git@v1.0.2'                 # только CLI
pipx install 'sanitize[gui] @ git+https://github.com/Mamishev/sanitize.git@v1.0.2'          # CLI + GUI (PySide6)
pipx install 'sanitize[gui,magic,tui] @ git+https://github.com/Mamishev/sanitize.git@v1.0.2' # всё extras

# из исходников (разработка):
uv sync --all-extras
uv run sanitize --help
```

## Готовое приложение

[Скачать AppImage 1.0.2 для Linux x86_64](https://github.com/Mamishev/sanitize/releases/download/v1.0.2/sanitize-1.0.2-x86_64.AppImage).
Python устанавливать не нужно. [Все файлы релиза и контрольные суммы](https://github.com/Mamishev/sanitize/releases/tag/v1.0.2).

```bash
chmod +x sanitize-1.0.2-x86_64.AppImage
./sanitize-1.0.2-x86_64.AppImage
```

Проверены Ubuntu 24.04/26.04, Debian 13 и запуск на CachyOS x86_64.
Подробности и ограничения — в [инструкции по распространению](docs/distribution.md).

## Быстрый старт (CLI)

```bash
# 1. Посмотреть, что будет найдено (ничего не меняется):
sanitize --path /var/www/site --dry-run

# 2. Обнулить найденные файлы (владелец/права/mtime сохраняются):
sanitize --path /var/www/site --zero --yes

# 3. Отчёт для аудита:
sanitize --path /var/www/site --dry-run --report report.json
sanitize --path /var/www/site --dry-run --report report.md
```

### Действия

| Флаг | Действие |
|---|---|
| `--zero` (по умолчанию) | обнулить файл, сохранив uid/gid/mode/mtime — записи `b_file` остаются валидными |
| `--delete` | удалить файлы (в интерактиве требует ввода `DELETE`) |
| `--stub` | заменить минимально валидной заглушкой (PDF/zip/текст) |
| `--quarantine DIR` | упаковать в tar.gz с `manifest.json` в DIR (вне корня!) |

### Восстановление из карантина

```bash
sanitize restore /var/quarantine/sanitize-quarantine-20261106-120000-000000.tar.gz --dry-run
sanitize restore /var/quarantine/sanitize-quarantine-20261106-120000-000000.tar.gz
```

Существующие файлы не перезаписываются; права и mtime восстанавливаются,
владелец — best-effort (без root).

### Полезные опции

```bash
--dry-run            # ничего не менять
--preset bitrix|generic
--category docs,archives,keys   # только выбранные категории
--ext .foo,.bar                 # дополнительные расширения
--exclude 'upload/private/**'   # исключить glob (можно повторять)
--include-hidden                # учитывать .env, .htpasswd и др.
--min-size 1M --older-than 90d
--magic                         # тип по сигнатуре для файлов без расширения
--deep-scan                     # поиск ПДн по содержимому (email/телефон/СНИЛС/ИНН/карта)
--threads N                     # параллельный обход (по подкаталогам первого уровня)
--sql FILE                      # SQL-скрипт для b_file (FILE_SIZE = 0) после --zero
--tui                           # терминальный интерфейс (Textual, extras tui)
--json                          # машиночитаемый вывод в stdout
--report FILE.json|FILE.md      # файл отчёта (по расширению)
--yes                           # без подтверждения (CI)
```

### Файл `.sanitizeignore`

Положите `.sanitizeignore` в корень проекта, чтобы исключить пути из поиска
(подмножество gitignore-синтаксиса):

```gitignore
# комментарий
upload/old_forms/
*.log
/public_docs/**
```

### Exit-коды

| Код | Значение |
|---|---|
| 0 | успех |
| 1 | часть файлов не обработана (нет доступа) |
| 2 | найдены конфиги с секретами (`report_only`) — для CI/hook |
| 3 | отказ: небезопасный путь, нет подтверждения, неверные аргументы |
| 130 | прервано пользователем |

### Категории профиля bitrix

Документы · Таблицы/экспорт · Презентации · Архивы · Подписи/ключи ·
Бэкапы/дампы · Почта/контакты · Аудио/видео *(выкл. по умолчанию)* ·
Логи и кэш · Конфиги с секретами *(только отчёт, никогда не изменяются)*.

Подробности профиля и обоснования — `docs/bitrix-notes.md` и
[руководство пользователя](docs/user-guide.md).

## GUI

```bash
uv run sanitize --gui        # или sanitize-gui (нужен extras gui)
```

Единственное окно: параметры поиска → прогресс → результаты (дерево
категорий с tri-state чекбоксами и фильтром) → действия (обнулить /
удалить / карантин). Сканер и действия работают в фоновых потоках, UI
не блокируется; «Стоп» прерывает операцию. Конфиги с секретами
отображаются, но недоступны для действий. Контекстное меню файла:
открыть каталог, копировать путь, исключить каталог из поиска.
Горячие клавиши: `Ctrl+F` — фокус на путь, `Enter` — Найти, `Esc` — Стоп.
Настройки (последний путь, чекбоксы, геометрия) — `~/.config/sanitize/`.

## TUI (headless-стенды по SSH)

```bash
uv run sanitize --tui        # extras tui (textual)
```

Минимум: путь, чекбоксы категорий, таблица найденного, обнуление/удаление
с подтверждением.

## Разработка

```bash
uv sync --all-extras          # зависимостей
uv run pytest -q              # тесты
uv run ruff check .           # линтер
uv run ruff format --check .  # форматирование
uv run mypy sanitize/core     # типы ядра (strict)
```

## Безопасность

- `--dry-run` не меняет ни одного байта.
- Без `--yes` и TTY утилита не выполняет действий (exit 3).
- Для `--delete` требуется ввести `DELETE` вручную.
- Системные корни (`/`, `/home`, `/usr`, `/etc`, `/var`, …) запрещены —
  работаем только с подкаталогами проекта.
- Конфиги с секретами (`bitrix/.settings.php`, `.env`, `dbconn.php`, …)
  попадают только в отчёт и никогда не изменяются.

## Помощь и участие

[Сообщить об ошибке](https://github.com/Mamishev/sanitize/issues) ·
[Участие в разработке](CONTRIBUTING.md) · [Безопасность](SECURITY.md).

Очистка файлов не является полной анонимизацией: изображения, содержимое БД
и история Git могут сохранять персональные данные и секреты.

## Лицензия и релизы

Собственный код: [0BSD](LICENSE). [Распространение](docs/distribution.md).
