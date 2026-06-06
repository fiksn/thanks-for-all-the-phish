"""Allow `python -m tfatp` to keep working as the single-user watcher entry point.

The implementation lives in `tfatp.cli.watch_mailbox` alongside the other
runnable scripts; this shim only exists to preserve the documented command.
"""

import sys

from tfatp.cli.watch_mailbox import main


if __name__ == "__main__":
    sys.exit(main(sys.argv))
