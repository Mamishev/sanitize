"""Entry point shared by the portable GUI and CLI."""

import sys

from sanitize.cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or ["--gui"]))
