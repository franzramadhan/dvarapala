import subprocess
import sys
import unittest
from pathlib import Path

EXAMPLES = Path(__file__).parent.parent / "examples"


class ExamplesTest(unittest.TestCase):
    def test_server_demo_prints_the_documented_statuses(self):
        out = subprocess.run(
            [sys.executable, str(EXAMPLES / "server.py"), "--demo"],
            capture_output=True, text=True, timeout=30, check=True,
        ).stdout
        self.assertEqual(out.splitlines(), [
            "/ 200",
            "/ 200",
            "/ 429 Retry-After: 1",
            "/wp-admin/ 403",
            "192.0.2.1 dropped: True",
        ])


if __name__ == "__main__":
    unittest.main()
