"""Syntax gate: compile nethtop++.py with warnings escalated to errors.

Invalid escape sequences (`"\\ "` in a non-raw string) only surface as
SyntaxWarning on Python 3.12+ (DeprecationWarning earlier), and plain
`py_compile` lets them pass silently — the banner escaped review that way.
This test compiles the file with those warning classes promoted to errors,
so any future regression fails CI/test runs on every Python version.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE = REPO_ROOT / "nethtop++.py"


class SyntaxGateTests(unittest.TestCase):
    def test_compile_with_warnings_as_errors(self):
        # py_compile writes __pycache__ next to the source by default. This tool
        # is meant to be run with sudo, so that directory is routinely owned by
        # root and the write fails with a bare "Permission denied" that looks
        # like a syntax failure. Redirect the bytecode cache to a temp dir so the
        # gate tests the source and never depends on the repo being writable.
        with tempfile.TemporaryDirectory() as cache:
            env = dict(os.environ, PYTHONPYCACHEPREFIX=cache)
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
                env=env,
            )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"compile with warnings-as-errors failed:\n{completed.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
