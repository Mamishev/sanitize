# Распространение sanitize 1.0.2

Репозиторий: https://github.com/Mamishev/sanitize . Тег v1.0.2 и публичный
релиз пока не опубликованы. До публикации используйте локальный wheel/AppImage.

## Готовый GUI и CLI

```sh
chmod +x sanitize-1.0.2-x86_64.AppImage
./sanitize-1.0.2-x86_64.AppImage
./sanitize-1.0.2-x86_64.AppImage --help
./sanitize-1.0.2-x86_64.AppImage --path /путь/к/копии/проекта --dry-run
```

Без аргументов открывается GUI. Для headless CLI не нужны Python или Qt
в системе. На рабочем столе нужны обычные системные графические библиотеки.
Проверены Ubuntu 24.04/26.04, Debian 13 и CachyOS x86_64 (контейнерные smoke-тесты).
X11 проверяется Xvfb, Wayland — Weston headless. Это не полная ручная проверка
всех desktop-окружений. CachyOS дополнительно проверен в локальной Wayland-сессии:
GUI запускается, но fontconfig предупреждает о новых системных правилах шрифтов.
Другие ОС и архитектуры не заявлены.

Если FUSE недоступен:

```sh
APPIMAGE_EXTRACT_AND_RUN=1 ./sanitize-1.0.2-x86_64.AppImage
# либо извлечь один раз:
./sanitize-1.0.2-x86_64.AppImage --appimage-extract
./squashfs-root/AppRun
```

Для меню Linux создайте пользовательский .desktop-файл в
`~/.local/share/applications/` с Type=Application, Name=sanitize,
Exec=/абсолютный/путь/к/AppImage, Icon=/абсолютный/путь/к/иконке и Terminal=false.
Автоматической установки и автообновления нет. Для обновления закройте приложение
и замените AppImage; настройки QSettings остаются в пользовательском профиле.

## Python-пакет

```sh
uv tool install ./sanitize-1.0.2-py3-none-any.whl
# GUI из локального wheel:
uv tool install ./sanitize-1.0.2-py3-none-any.whl --with PySide6
```

Дополнительно: `--with python-magic` (нужна системная libmagic), `--with textual`.
После публикации тега:

```sh
uv tool install 'sanitize @ git+https://github.com/Mamishev/sanitize.git@v1.0.2'
```

PyPI-публикация не настроена. Для разработки используйте `uv tool install
--editable /путь/к/sanitize --with PySide6`, для коллег — wheel или тег.

## Сборка и выпуск

- Dockerfile сборки: packaging/Dockerfile (Ubuntu 24.04, Python 3.12).
- Python-зависимости фиксирует uv.lock; упаковщик PyInstaller 6.16.0.
- packaging/fetch-appimage-tools.sh проверяет SHA256 appimagetool и runtime.
  При изменении upstream continuous сборка остановится; новые хэши нужно проверить.
- packaging/build-container.sh запускается с /src (исходники, read-only),
  /tools (appimagetool/runtime, read-only), /out (результат).
- `COLLECT_SOURCES=1` дополнительно загружает соответствующие исходники зависимостей.
  Отсутствующий source-пакет останавливает сборку релизного комплекта.
- CI по v*-тегу проверяет Python-код, собирает пакеты и AppImage, запускает
  матрицу ОС/X11/Wayland и создаёт только черновик GitHub Release.
- Публичную публикацию выполнять после просмотра артефактов, SHA256SUMS,
  лицензий, соответствующих исходников и отчёта docs/release-verification.md.

## Лицензии и ограничения

Собственный код и документация: 0BSD, Alexander Mamishev, 2026.
[Сторонние компоненты](third-party.md) сохраняют собственные лицензии.
Происхождение иконки: Gemini Nano Banana через AITUNNEL, см.
`sanitize/gui/icons/README.md`.

Очистка файлов не означает полную анонимизацию: БД, изображения, история Git
и другие источники могут содержать данные. Проверка работы сайта и админки
Битрикс после очистки на развёрнутом стенде ещё не завершена.
