"""Entry point for aegisguard-cli.exe (console tool: scan, fix, block, cleanup, ...)."""
import sys

from aegisguard.cli import main

if __name__ == "__main__":
    sys.exit(main())
