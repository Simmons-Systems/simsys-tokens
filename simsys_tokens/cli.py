"""Provisioning CLI.

Only `mint --init` may create the store. `list`, `revoke` and `verify` never
create it: the conformance check shells out to `list`, and a list that
auto-created an empty store would report a never-adopted app as clean.

Filter note: `list` shows live AND revoked rows by design (the locked-out
operator and the audit check need the full roster), while GET /api/tokens
defaults to live-only with ?include=revoked opt-in. Same fields, different
default filter — intentional, not drift.
"""

from __future__ import annotations

import argparse
import getpass
import json
import socket
import sqlite3
import sys

from . import events
from .errors import TokenError
from .hashing import token_hash
from .store import Store, ensure_schema, is_expired

_PUBLIC_FIELDS = (
    "label",
    "role",
    "priority",
    "rate_limit",
    "expires_at",
    "created_at",
    "created_by",
    "last_used_at",
    "revoked_at",
    "revoked_by",
)


def _default_db(service: str) -> str:
    return f"/var/lib/{service}/tokens.db"


def _actor() -> str:
    return f"cli:{getpass.getuser()}@{socket.gethostname()}"


def _public(row) -> dict:
    return {k: row[k] for k in _PUBLIC_FIELDS} | {"handle": row["token_sha256"][:16]}


def _classify(row, now=None) -> str:
    if row is None:
        return "unknown"
    if row["revoked_at"] is not None:
        return "revoked"
    if is_expired(row["expires_at"], now):
        return "expired"
    return "live"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="simsys-tokens")
    sub = parser.add_subparsers(dest="cmd", required=True)

    for name in ("mint", "list", "revoke", "verify"):
        p = sub.add_parser(name)
        p.add_argument("--service", required=True)
        p.add_argument("--db")
    mint = sub.choices["mint"]
    mint.add_argument("--role", required=True)
    mint.add_argument("--label", required=True)
    mint.add_argument(
        "--expires-at",
        default=None,
        help="ISO-8601 timestamp after which the token stops authenticating",
    )
    mint.add_argument(
        "--init",
        action="store_true",
        help="create the store if it does not exist (fresh install only)",
    )
    mint.add_argument("--json", action="store_true")
    sub.choices["list"].add_argument("--json", action="store_true")
    sub.choices["revoke"].add_argument("--handle", required=True)
    sub.choices["revoke"].add_argument("--json", action="store_true")
    # --token is read from argv (visible in the process list); stdin is the
    # default so a secret does not land in shell history.
    sub.choices["verify"].add_argument("--token", default=None)
    sub.choices["verify"].add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    db = args.db or _default_db(args.service)

    try:
        ensure_schema(db, create=(args.cmd == "mint" and args.init))
        store = Store(db, args.service)
        if args.cmd == "mint":
            raw, handle = store.mint(args.role, args.label, _actor(), expires_at=args.expires_at)
            events.DEFAULT.token_created(args.service, handle, args.label, args.role, _actor())
            if args.json:
                print(
                    json.dumps(
                        {
                            "handle": handle,
                            "token": raw,
                            "label": args.label,
                            "role": args.role,
                            "expires_at": args.expires_at,
                        }
                    )
                )
            else:
                print(f"handle: {handle}")
                print("SAVE THIS TOKEN — it is shown only once:")
                print(raw)
        elif args.cmd == "list":
            rows, has_more = store.list_rows(include_revoked=True)
            public = [_public(r) for r in rows]
            if args.json:
                print(json.dumps(public, indent=2))
            else:
                for row in public:
                    print(f"{row['handle']}  {row['role']:8}  {row['label']}")
            if has_more:
                # The conformance check parses this output. A silent truncation
                # would let it conclude "no tokens beyond these" from a page.
                print(
                    f"warning: more than {len(public)} tokens exist; output truncated",
                    file=sys.stderr,
                )
                return 1
        elif args.cmd == "revoke":
            row, changed = store.revoke(args.handle, _actor())
            if changed:
                # Pass the real label: handle_delete does, and telemetry that
                # says label=null for CLI revokes only is not queryable.
                events.DEFAULT.token_revoked(args.service, args.handle, row["label"], _actor())
            if args.json:
                print(json.dumps(_public(row) | {"changed": changed}))
            elif changed:
                print(f"revoked {args.handle}")
            else:
                print(f"{args.handle} was already revoked; no change")
        elif args.cmd == "verify":
            presented = args.token
            if presented is None:
                presented = sys.stdin.readline().strip()
            if presented.startswith("Bearer "):
                presented = presented[len("Bearer ") :]
            row = store.find_any(token_hash(presented)) if presented else None
            state = _classify(row)
            if args.json:
                print(
                    json.dumps(
                        {"state": state}
                        | (
                            (
                                {
                                    "handle": row["token_sha256"][:16],
                                    "label": row["label"],
                                    "role": row["role"],
                                }
                            )
                            if row
                            else {}
                        )
                    )
                )
            elif row is None:
                print("unknown — no such token in this service", file=sys.stderr)
            else:
                print(f"{state}  {row['token_sha256'][:16]}  {row['role']}  {row['label']}")
                if state == "expired":
                    print(f"expired at {row['expires_at']}", file=sys.stderr)
            return 0 if state == "live" else 1
    except sqlite3.IntegrityError:
        # handle_create returns 409 for exactly this; without it here the CLI
        # exits on an unhandled traceback and the two write paths disagree on
        # the same failure — the divergence this package exists to remove.
        print(
            f"error: a live token in service {args.service!r} already uses "
            f"label {getattr(args, 'label', '?')!r}",
            file=sys.stderr,
        )
        return 1
    except (TokenError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0
