from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .policy import Request, ValidationError
from .storage import MAX_REQUEST_BYTES, default_policy_path, load_policy, parse_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="登録済み対象への操作範囲を確認します。操作の実行は行いません。")
    parser.add_argument("--policy", type=Path, default=default_policy_path(), help="管理者が用意した非公開の対象登録ファイル")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="登録済み対象の件数を確認")
    commands.add_parser("check", help="標準入力の操作要求JSONを判定")
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy)
        if args.command == "status":
            print(json.dumps({"target_count": len(policy.targets)}, ensure_ascii=False))
            return 0
        payload = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(payload) > MAX_REQUEST_BYTES:
            raise ValidationError("request exceeds the size limit")
        request = Request.from_dict(parse_json(payload))
        decision = policy.evaluate(request)
        print(json.dumps(asdict(decision), ensure_ascii=False))
        return decision.exit_code
    except (ValidationError, OSError) as error:
        message = str(error) if isinstance(error, ValidationError) else "input could not be read"
        print(json.dumps({"status": "error", "reason": message}), file=sys.stderr)
        return 1
