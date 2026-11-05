import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from security_ai_agent.policy import ValidationError
from security_ai_agent.storage import MAX_POLICY_BYTES, MAX_REQUEST_BYTES, load_policy
from tests.test_policy import request_data, target_data


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.policy_path = Path(self.temporary.name) / "scope.json"

    def write_policy(self):
        target = target_data()
        now = datetime.now(timezone.utc)
        target["not_before"] = (now - timedelta(hours=1)).isoformat()
        target["expires_at"] = (now + timedelta(hours=1)).isoformat()
        self.policy_path.write_text(json.dumps({"schema_version": 1, "targets": [target]}))
        self.policy_path.chmod(0o600)

    def run_cli(self, command, payload=b""):
        return subprocess.run(
            [sys.executable, "-m", "security_ai_agent", "--policy", str(self.policy_path), command],
            input=payload, capture_output=True, timeout=5,
        )

    def test_reports_zero_targets_before_registration(self):
        result = self.run_cli("status")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {"target_count": 0})

    def test_returns_a_denial_for_an_unregistered_target(self):
        result = self.run_cli("check", json.dumps(request_data()).encode())
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["reason"], "target_not_registered")

    def test_loads_a_private_policy_and_checks_a_registered_request(self):
        self.write_policy()
        result = self.run_cli("check", json.dumps(request_data()).encode())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "allowed")

    def test_returns_a_distinct_status_when_human_approval_is_required(self):
        self.write_policy()
        request = request_data()
        request["action"] = "restart"
        result = self.run_cli("check", json.dumps(request).encode())
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)["status"], "approval_required")

    def test_rejects_policy_files_accessible_to_other_users(self):
        self.write_policy()
        self.policy_path.chmod(0o644)
        result = self.run_cli("check", json.dumps(request_data()).encode())
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stderr)["status"], "error")

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires no-follow file access")
    def test_rejects_a_symbolic_link_as_the_policy_source(self):
        self.write_policy()
        original = self.policy_path.with_suffix(".private.json")
        self.policy_path.rename(original)
        self.policy_path.symlink_to(original)
        with self.assertRaises(ValidationError):
            load_policy(self.policy_path)

    def test_rejects_a_directory_as_the_policy_source(self):
        self.policy_path.mkdir(mode=0o700)
        with self.assertRaises(ValidationError):
            load_policy(self.policy_path)

    def test_rejects_requests_exceeding_the_input_budget(self):
        result = self.run_cli("check", b" " * (MAX_REQUEST_BYTES + 1))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stderr)["reason"], "request exceeds the size limit")

    def test_rejects_policy_files_exceeding_the_input_budget(self):
        self.policy_path.write_bytes(b" " * (MAX_POLICY_BYTES + 1))
        self.policy_path.chmod(0o600)
        with self.assertRaises(ValidationError):
            load_policy(self.policy_path)

    def test_uses_the_external_configuration_directory_by_default(self):
        environment = os.environ.copy()
        environment["XDG_CONFIG_HOME"] = self.temporary.name
        result = subprocess.run(
            [sys.executable, "-m", "security_ai_agent", "status"],
            capture_output=True, timeout=5, env=environment,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {"target_count": 0})


if __name__ == "__main__":
    unittest.main()
