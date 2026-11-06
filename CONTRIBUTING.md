# Участие в разработке

Linux, Python 3.11+. Прочитайте AGENTS.md перед изменениями.

Установка: `uv sync --all-extras`.
Проверки: `uv run ruff check .`, `uv run ruff format --check .`,
`uv run mypy sanitize/core`, `QT_QPA_PLATFORM=offscreen uv run pytest`.

Проверяйте очистку только на временных фикстурах. Не прикладывайте реальные
документы, дампы, персональные данные и секреты к issues и pull requests.
Собственный код и документация принимаются под 0BSD.
