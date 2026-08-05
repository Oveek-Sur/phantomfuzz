"""ASCII banner and terminal colors."""

import sys

# Enable ANSI colors on Windows terminals
if sys.platform == "win32":
    import os
    os.system("")


class C:
    """ANSI color codes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    GREY = "\033[90m"

    @staticmethod
    def strip():
        """Disable all colors (for no-color / piped output)."""
        for name in dir(C):
            if name.isupper():
                setattr(C, name, "")


BANNER = r"""{c}{b}
   ___  _                _              ___
  / _ \| |__   __ _ _ __| |_ ___  _ __ / __|   _ ________
 | |_) | '_ \ / _` | '_ \ __/ _ \| '_ \ |  | | | |_  /_  /
 |  __/| | | | (_| | | | | || (_) | | | | |__| |_| |/ / / /
 |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_|\___|\__,_/___/___|
{r}{d}      v{ver}  ·  fast async web fuzzer  ·  authorized testing only{r}
"""


def show(version, quiet=False):
    if quiet:
        return
    print(BANNER.format(c=C.CYAN, b=C.BOLD, r=C.RESET, d=C.DIM, ver=version))
