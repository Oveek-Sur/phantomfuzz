"""Entry point: python -m phantomfuzz ..."""

import sys

from .cli import run

if __name__ == "__main__":
    sys.exit(run())
