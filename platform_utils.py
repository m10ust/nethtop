"""Platform detection for nethtop cross-platform support."""
import sys

IS_WINDOWS: bool = sys.platform == "win32"
IS_MACOS: bool = sys.platform == "darwin"
IS_LINUX: bool = sys.platform.startswith("linux")
