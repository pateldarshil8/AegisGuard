"""Entry point for AegisGuard.exe (windowed app). Pass --minimized to start hidden in the system tray."""
import sys

from aegisguard.ui.app import launch

if __name__ == "__main__":
    launch(start_hidden="--minimized" in sys.argv)
