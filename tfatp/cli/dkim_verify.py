"""CLI entry point for `tfatp.dkim_verify`.

Run as: `python -m tfatp.cli.dkim_verify <path-or-stdin>`.
The library lives at `tfatp.dkim_verify`.
"""

import sys

from tfatp.dkim_verify import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
