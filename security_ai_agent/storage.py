from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .policy import Policy, ValidationError


MAX_POLICY_BYTES = 256 * 1024
MAX_REQUEST_BYTES = 16 * 1024


def default_policy_path() -> Path:
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    if not config_home.is_absolute():
        config_home = Path.home() / ".config"
    return config_home / "security-ai-agent" / "scope.json"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("JSON object keys must be unique")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValidationError("JSON numeric constants must be finite")


def parse_json(payload: bytes) -> Any:
    try:
        return json.loads(payload, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValidationError("invalid JSON input") from error


def load_policy(path: Path) -> Policy:
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return Policy()
    except OSError as error:
        raise ValidationError("policy must be an accessible private regular file") from error
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or stat.S_IMODE(details.st_mode) not in (0o400, 0o600):
            raise ValidationError("policy must be a private regular file with mode 0600 or 0400")
        if hasattr(os, "geteuid") and details.st_uid not in (0, os.geteuid()):
            raise ValidationError("policy must belong to the current user or an administrator")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(MAX_POLICY_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_POLICY_BYTES:
        raise ValidationError("policy exceeds the size limit")
    return Policy.from_dict(parse_json(payload))
