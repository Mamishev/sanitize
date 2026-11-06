"""Точка входа `python -m sanitize`."""

from __future__ import annotations

import sys

from sanitize.cli import main

if __name__ == "__main__":
    sys.exit(main())
