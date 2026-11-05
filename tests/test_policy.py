import copy
import unittest
from datetime import datetime, timezone

from security_ai_agent.policy import Action, Policy, Request, ValidationError
from security_ai_agent.storage import parse_json


NOW = datetime(2030, 1, 15, tzinfo=timezone.utc)
FINGERPRINT = "a" * 64


def target_data():
    return {
        "target_id": "test-lab",
        "environment": "lab",
        "addresses": ["192.0.2.10", "2001:db8::10"],
        "ports": [22, 443],
        "identity": {"kind": "ssh_host_key", "sha256": FINGERPRINT},
        "actions": [action.value for action in Action],
        "not_before": "2030-01-01T00:00:00Z",
        "expires_at": "2030-02-01T00:00:00Z",
        "limits": {"duration_seconds": 60, "max_requests": 30, "requests_per_second": 2},
    }


def request_data():
    return {
        "target_id": "test-lab",
        "action": "inventory",
        "address": "192.0.2.10",
        "port": 22,
        "identity": {"kind": "ssh_host_key", "sha256": FINGERPRINT},
        "subject": "operating-system",
        "limits": {"duration_seconds": 20, "max_requests": 10, "requests_per_second": 1},
    }


def policy_with(target=None):
    return Policy.from_dict({"schema_version": 1, "targets": [target or target_data()]})


class PolicyTests(unittest.TestCase):
    def test_allows_registered_read_only_operations_within_limits(self):
        for action in ("inventory", "observe", "inspect_settings", "inspect_code", "inspect_dependencies"):
            with self.subTest(action=action):
                data = request_data()
                data["action"] = action
                result = policy_with().evaluate(Request.from_dict(data), now=NOW)
                self.assertEqual(result.status, "allowed")

    def test_denies_operations_on_an_unregistered_machine(self):
        result = Policy().evaluate(Request.from_dict(request_data()), now=NOW)
        self.assertEqual((result.status, result.reason), ("denied", "target_not_registered"))

    def test_denies_unregistered_addresses_and_ports(self):
        for field, value in (("address", "192.0.2.11"), ("port", 8443)):
            with self.subTest(field=field):
                data = request_data()
                data[field] = value
                result = policy_with().evaluate(Request.from_dict(data), now=NOW)
                self.assertEqual(result.reason, "endpoint_not_registered")

    def test_denies_a_machine_with_a_different_identity(self):
        data = request_data()
        data["identity"]["sha256"] = "b" * 64
        result = policy_with().evaluate(Request.from_dict(data), now=NOW)
        self.assertEqual(result.reason, "identity_mismatch")

    def test_matches_the_registered_identity_for_each_supported_transport(self):
        for kind in ("ssh_host_key", "tls_certificate", "agent_key"):
            with self.subTest(kind=kind):
                target = target_data()
                target["identity"]["kind"] = kind
                data = request_data()
                data["identity"]["kind"] = kind
                result = policy_with(target).evaluate(Request.from_dict(data), now=NOW)
                self.assertEqual(result.status, "allowed")

    def test_distinguishes_identity_types_with_the_same_digest(self):
        data = request_data()
        data["identity"]["kind"] = "tls_certificate"
        result = policy_with().evaluate(Request.from_dict(data), now=NOW)
        self.assertEqual(result.reason, "identity_mismatch")

    def test_observes_the_authorization_window_at_its_boundaries(self):
        request = Request.from_dict(request_data())
        for timestamp, expected in (
            ("2029-12-31T23:59:59+00:00", "denied"),
            ("2030-01-01T00:00:00+00:00", "allowed"),
            ("2030-02-01T00:00:00+00:00", "denied"),
        ):
            with self.subTest(timestamp=timestamp):
                result = policy_with().evaluate(request, now=datetime.fromisoformat(timestamp))
                self.assertEqual(result.status, expected)

    def test_denies_an_operation_not_permitted_for_the_target(self):
        target = target_data()
        target["actions"] = ["inventory"]
        data = request_data()
        data["action"] = "attack_diagnostic"
        result = policy_with(target).evaluate(Request.from_dict(data), now=NOW)
        self.assertEqual((result.status, result.reason), ("denied", "action_not_permitted"))

    def test_keeps_the_entire_operation_inside_the_authorization_window(self):
        request = Request.from_dict(request_data())
        for timestamp, expected in (
            ("2030-01-31T23:59:40+00:00", "allowed"),
            ("2030-01-31T23:59:41+00:00", "denied"),
        ):
            with self.subTest(timestamp=timestamp):
                result = policy_with().evaluate(request, now=datetime.fromisoformat(timestamp))
                self.assertEqual(result.status, expected)

    def test_requires_approval_for_defensive_and_attack_operations(self):
        for environment in ("lab", "production"):
            for action in (
                "block_connection", "isolate_host", "update", "restart", "stop_process",
                "rotate_credentials", "attack_diagnostic", "attack_exploit",
            ):
                with self.subTest(environment=environment, action=action):
                    target = target_data()
                    target["environment"] = environment
                    data = request_data()
                    data["action"] = action
                    result = policy_with(target).evaluate(Request.from_dict(data), now=NOW)
                    self.assertEqual(result.status, "approval_required")

    def test_denies_each_execution_limit_when_exceeded(self):
        target = target_data()
        for field, maximum in target["limits"].items():
            with self.subTest(field=field):
                data = request_data()
                data["limits"][field] = maximum + 1
                result = policy_with(target).evaluate(Request.from_dict(data), now=NOW)
                self.assertEqual(result.reason, "execution_limit_exceeded")

    def test_matches_equivalent_numeric_ipv6_addresses(self):
        data = request_data()
        data["address"] = "2001:0db8:0000:0000:0000:0000:0000:0010"
        result = policy_with().evaluate(Request.from_dict(data), now=NOW)
        self.assertEqual(result.status, "allowed")

    def test_binds_the_review_digest_to_the_complete_request(self):
        original = Request.from_dict(request_data()).digest()
        for field, value in (("subject", "service:web"), ("action", "restart"), ("port", 443)):
            with self.subTest(field=field):
                data = request_data()
                data[field] = value
                self.assertNotEqual(original, Request.from_dict(data).digest())
        data = request_data()
        data["limits"]["duration_seconds"] += 1
        self.assertNotEqual(original, Request.from_dict(data).digest())

    def test_rejects_ambiguous_or_malformed_requests(self):
        invalid = [
            ("action", "execute_shell"), ("action", []),
            ("address", "example.test"), ("address", "192.0.2.0/24"),
            ("address", "0.0.0.0"), ("address", "224.0.0.1"),
            ("address", "fe80::1%eth0"), ("port", True), ("port", 65536),
            ("identity", {"kind": "hostname", "sha256": FINGERPRINT}),
            ("identity", {"kind": "ssh_host_key", "sha256": "invalid"}),
            ("subject", ""), ("subject", "line\nbreak"),
        ]
        for field, value in invalid:
            with self.subTest(field=field, value=value):
                data = request_data()
                data[field] = value
                with self.assertRaises(ValidationError):
                    Request.from_dict(data)
        for value in (0, -1, True, 1.5):
            data = request_data()
            data["limits"]["duration_seconds"] = value
            with self.assertRaises(ValidationError):
                Request.from_dict(data)

    def test_rejects_ambiguous_policy_configuration(self):
        target = target_data()
        for policy in (
            {"schema_version": True, "targets": []},
            {"schema_version": 2, "targets": []},
            {"schema_version": 1, "targets": [target, copy.deepcopy(target)]},
            {"schema_version": 1, "targets": [], "allow_all": True},
        ):
            with self.subTest(policy=policy):
                with self.assertRaises(ValidationError):
                    Policy.from_dict(policy)

    def test_requires_valid_timezone_aware_authorization_windows(self):
        for start, end in (
            ("2030-01-01T00:00:00", "2030-02-01T00:00:00Z"),
            ("2030-02-01T00:00:00Z", "2030-01-01T00:00:00Z"),
            ("2030-01-01T00:00:00Z", "2030-01-01T00:00:00Z"),
        ):
            target = target_data()
            target["not_before"], target["expires_at"] = start, end
            with self.assertRaises(ValidationError):
                policy_with(target)

    def test_rejects_ambiguous_json_before_authorization(self):
        for payload in (b'{"schema_version": 1, "schema_version": 2}', b'{"value": NaN}', b'\xff'):
            with self.subTest(payload=payload):
                with self.assertRaises(ValidationError):
                    parse_json(payload)


if __name__ == "__main__":
    unittest.main()
