# Сторонние компоненты

Код sanitize: 0BSD. Зависимости не перелицензируются под 0BSD.
В AppImage тексты лицензий и METADATA Python-пакетов находятся в
`usr/share/doc/sanitize/licenses`, включая системные copyright-файлы Ubuntu.
Перечень версий Python-компонентов: `licenses/python-packages.json`.

Qt/PySide6: используемые QtCore, QtGui, QtWidgets и сопутствующие платформенные
плагины распространяются по применимым open-source условиям, включая LGPLv3.
Исходники: https://download.qt.io/official_releases/QtForPython/
и https://download.qt.io/official_releases/qt/ . Версию сверять с manifest.
Условия: https://www.qt.io/development/open-source-lgpl-obligations .
К бинарному кандидату приложен архив dependency-sources с исходниками Qt,
PySide6, ICU, системных библиотек Ubuntu, runtime и его build-рецептом.
Версии системных библиотек сопоставлены через dpkg-query; записи находятся
в system-sources.json. Это не юридическое заключение о всех компонентах.

AppImage извлекается командой `./sanitize-1.0.2-x86_64.AppImage --appimage-extract`.
После извлечения запускать `squashfs-root/AppRun`; динамические Qt/PySide6
библиотеки в `usr/bin/_internal` можно заменять совместимыми модификациями.
Обратная разработка для отладки модификаций LGPL-компонентов не запрещается.
Приложение не использует проверку подписи, препятствующую такой замене.

Python: PSF; python-magic и libmagic: соответствующие permissive-лицензии;
Textual и его зависимости: см. точные тексты в комплекте. PyInstaller имеет
исключение для распространения собранных приложений, его bootloader-лицензия
также должна поставляться с бинарным артефактом.

Иконка: см. sanitize/gui/icons/README.md.
