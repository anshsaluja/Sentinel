"""Host-only regression tests for the read-only local demo preflight."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("preflight-local-demo.sh")


class PreflightTests(unittest.TestCase):
    def run_preflight(self, *args, docker_ok=True, services_ok=True):
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            commands = {
                "java": '#!/bin/sh\necho "openjdk version \\"21.0.5\\"" >&2\n',
                "node": '#!/bin/sh\necho 22\n',
                "npm": '#!/bin/sh\nexit 0\n',
                "mvn": '#!/bin/sh\nexit 0\n',
                "docker": ('#!/bin/sh\n'
                           'if [ "$1" = "compose" ] && [ "$2" = "ps" ]; then echo mongo-id; exit 0; fi\n'
                           f'if [ "$1" = "exec" ]; then exit {0 if services_ok else 1}; fi\n'
                           f'exit {0 if docker_ok else 1}\n'),
                "curl": f'#!/bin/sh\nexit {0 if services_ok else 1}\n',
            }
            for name, content in commands.items():
                path = bin_dir / name
                path.write_text(content)
                path.chmod(0o755)
            env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}")
            return subprocess.run(["bash", str(SCRIPT), *args], env=env,
                                  capture_output=True, text=True, check=False)

    def test_all_prerequisites_succeed(self):
        result = self.run_preflight()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS Docker daemon", result.stdout)
        self.assertIn("Prerequisites passed", result.stdout)

    def test_missing_docker_fails_closed(self):
        result = self.run_preflight(docker_ok=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL Docker daemon", result.stderr)

    def test_service_failures_are_reported(self):
        result = self.run_preflight("--services", services_ok=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL MongoDB replica set primary", result.stderr)
        self.assertIn("FAIL Keycloak OIDC discovery", result.stderr)

    def test_invalid_arguments_do_not_run_checks(self):
        result = self.run_preflight("--unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
