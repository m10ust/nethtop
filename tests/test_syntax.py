"""Syntax gate: compile nethtop++.py with warnings escalated to errors.

Invalid escape sequences (`"\\ "` in a non-raw string) only surface as
SyntaxWarning on Python 3.12+ (DeprecationWarning earlier), and plain
`py_compile` lets them pass silently — the banner escaped review that way.
This test compiles the file with those warning classes promoted to errors,
so any future regression fails CI/test runs on every Python version.
"""

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE = REPO_ROOT / "nethtop++.py"


class SyntaxGateTests(unittest.TestCase):
    def test_compile_with_warnings_as_errors(self):
        completed = subprocess.run(
            [
                sys.executable,
                "-W",
                "error::SyntaxWarning",
                "-W",
                "error::DeprecationWarning",
                "-m",
                "py_compile",
                str(SOURCE),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"compile with warnings-as-errors failed:\n{completed.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
