"""CLI entry point for `tfatp.analyze_eml`.

Run as: `python -m tfatp.cli.analyze_eml [path] [options]`.
The library lives at `tfatp.analyze_eml`.
"""

import sys

from tfatp.analyze_eml import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
