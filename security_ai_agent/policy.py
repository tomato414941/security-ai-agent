from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class ValidationError(ValueError):
    pass


class Action(StrEnum):
    INVENTORY = "inventory"
    OBSERVE = "observe"
    INSPECT_SETTINGS = "inspect_settings"
    INSPECT_CODE = "inspect_code"
    INSPECT_DEPENDENCIES = "inspect_dependencies"
    BLOCK_CONNECTION = "block_connection"
    ISOLATE_HOST = "isolate_host"
    UPDATE = "update"
    RESTART = "restart"
    STOP_PROCESS = "stop_process"
    ROTATE_CREDENTIALS = "rotate_credentials"
    ATTACK_DIAGNOSTIC = "attack_diagnostic"
    ATTACK_EXPLOIT = "attack_exploit"


READ_ONLY_ACTIONS = frozenset(
    {
        Action.INVENTORY,
        Action.OBSERVE,
        Action.INSPECT_SETTINGS,
        Action.INSPECT_CODE,
        Action.INSPECT_DEPENDENCIES,
    }
)


def _object(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValidationError(f"{context} has missing or unsupported fields")
    return value


def _text(value: Any, context: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not value.isprintable()
    ):
        raise ValidationError(f"{context} must be nonempty printable text")
    return value


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
        raise ValidationError("target_id must be a valid identifier")
    return value


def _positive_integer(value: Any, context: str, maximum: int = 2**31 - 1) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValidationError(f"{context} must be a positive integer within range")
    return value


def _address(value: Any) -> str:
    if not isinstance(value, str) or "%" in value:
        raise ValidationError("address must be a numeric IP address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValidationError("address must be a numeric IP address") from error
    if address.is_unspecified or address.is_multicast:
        raise ValidationError("address must identify a single machine")
    return str(address)


def _time(value: Any, context: str) -> datetime:
    if not isinstance(value, str):
        raise ValidationError(f"{context} must be a timestamp with a timezone")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:
        raise ValidationError(f"{context} must be a timestamp with a timezone") from error


def _action(value: Any) -> Action:
    try:
        return Action(value)
    except (TypeError, ValueError) as error:
        raise ValidationError("unsupported action") from error


def _list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list) or not value:
        raise ValidationError(f"{context} must be a nonempty list")
    return value


@dataclass(frozen=True)
class MachineIdentity:
    kind: str
    sha256: str

    @classmethod
    def from_dict(cls, value: Any) -> MachineIdentity:
        data = _object(value, {"kind", "sha256"}, "identity")
        if data["kind"] not in ("ssh_host_key", "tls_certificate", "agent_key"):
            raise ValidationError("unsupported machine identity kind")
        if not isinstance(data["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", data["sha256"]):
            raise ValidationError("identity sha256 must be a lowercase hexadecimal digest")
        return cls(kind=data["kind"], sha256=data["sha256"])


@dataclass(frozen=True)
class Limits:
    duration_seconds: int
    max_requests: int
    requests_per_second: int

    @classmethod
    def from_dict(cls, value: Any) -> Limits:
        fields = {"duration_seconds", "max_requests", "requests_per_second"}
        data = _object(value, fields, "limits")
        return cls(**{key: _positive_integer(data[key], key) for key in fields})

    def contains(self, requested: Limits) -> bool:
        return all(
            requested_value <= maximum
            for requested_value, maximum in (
                (requested.duration_seconds, self.duration_seconds),
                (requested.max_requests, self.max_requests),
                (requested.requests_per_second, self.requests_per_second),
            )
        )


@dataclass(frozen=True)
class Target:
    target_id: str
    environment: str
    addresses: frozenset[str]
    ports: frozenset[int]
    identity: MachineIdentity
    actions: frozenset[Action]
    not_before: datetime
    expires_at: datetime
    limits: Limits

    @classmethod
    def from_dict(cls, value: Any) -> Target:
        data = _object(
            value,
            {
                "target_id", "environment", "addresses", "ports",
                "identity", "actions", "not_before", "expires_at", "limits",
            },
            "target",
        )
        if data["environment"] not in ("lab", "production"):
            raise ValidationError("environment must be lab or production")
        not_before = _time(data["not_before"], "not_before")
        expires_at = _time(data["expires_at"], "expires_at")
        if not_before >= expires_at:
            raise ValidationError("target must have a positive authorization window")
        return cls(
            target_id=_identifier(data["target_id"]),
            environment=data["environment"],
            addresses=frozenset(_address(item) for item in _list(data["addresses"], "addresses")),
            ports=frozenset(_positive_integer(item, "port", 65535) for item in _list(data["ports"], "ports")),
            identity=MachineIdentity.from_dict(data["identity"]),
            actions=frozenset(_action(item) for item in _list(data["actions"], "actions")),
            not_before=not_before,
            expires_at=expires_at,
            limits=Limits.from_dict(data["limits"]),
        )


@dataclass(frozen=True)
class Request:
    target_id: str
    action: Action
    address: str
    port: int
    identity: MachineIdentity
    subject: str
    limits: Limits

    @classmethod
    def from_dict(cls, value: Any) -> Request:
        data = _object(
            value,
            {"target_id", "action", "address", "port", "identity", "subject", "limits"},
            "request",
        )
        return cls(
            target_id=_identifier(data["target_id"]),
            action=_action(data["action"]),
            address=_address(data["address"]),
            port=_positive_integer(data["port"], "port", 65535),
            identity=MachineIdentity.from_dict(data["identity"]),
            subject=_text(data["subject"], "subject"),
            limits=Limits.from_dict(data["limits"]),
        )

    def digest(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class Decision:
    status: str
    reason: str
    request_digest: str

    @property
    def exit_code(self) -> int:
        return {"allowed": 0, "denied": 2, "approval_required": 3}[self.status]


@dataclass(frozen=True)
class Policy:
    targets: tuple[Target, ...] = ()

    @classmethod
    def from_dict(cls, value: Any) -> Policy:
        data = _object(value, {"schema_version", "targets"}, "policy")
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise ValidationError("unsupported policy schema version")
        if not isinstance(data["targets"], list):
            raise ValidationError("targets must be a list")
        targets = tuple(Target.from_dict(item) for item in data["targets"])
        if len({target.target_id for target in targets}) != len(targets):
            raise ValidationError("target identifiers must be unique")
        return cls(targets)

    def evaluate(self, request: Request, *, now: datetime | None = None) -> Decision:
        instant = now if now is not None else datetime.now(timezone.utc)
        if instant.tzinfo is None:
            raise ValidationError("evaluation time must include a timezone")

        def decide(status: str, reason: str) -> Decision:
            return Decision(status, reason, request.digest())

        target = next((item for item in self.targets if item.target_id == request.target_id), None)
        if target is None:
            return decide("denied", "target_not_registered")
        if not target.not_before <= instant < target.expires_at:
            return decide("denied", "target_not_active")
        if (target.expires_at - instant).total_seconds() < request.limits.duration_seconds:
            return decide("denied", "authorization_window_exceeded")
        if request.address not in target.addresses or request.port not in target.ports:
            return decide("denied", "endpoint_not_registered")
        if request.identity != target.identity:
            return decide("denied", "identity_mismatch")
        if request.action not in target.actions:
            return decide("denied", "action_not_permitted")
        if not target.limits.contains(request.limits):
            return decide("denied", "execution_limit_exceeded")
        if request.action not in READ_ONLY_ACTIONS:
            return decide("approval_required", "human_approval_required")
        return decide("allowed", "registered_read_only_action")
