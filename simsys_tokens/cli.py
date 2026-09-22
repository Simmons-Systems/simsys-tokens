"""Provisioning CLI.

Only `mint --init` may create the store. `list` and `revoke` never create it:
the conformance check shells out to `list`, and a list that auto-created an
empty store would report a never-adopted app as clean.

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
from .store import Store, ensure_schema


def _default_db(service: str) -> str:
    return f"/var/lib/{service}/tokens.db"


def _actor() -> str:
    return f"cli:{getpass.getuser()}@{socket.gethostname()}"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="simsys-tokens")
    sub = parser.add_subparsers(dest="cmd", required=True)

    for name in ("mint", "list", "revoke"):
        p = sub.add_parser(name)
        p.add_argument("--service", required=True)
        p.add_argument("--db")
    mint = sub.choices["mint"]
    mint.add_argument("--role", required=True)
    mint.add_argument("--label", required=True)
    mint.add_argument("--init", action="store_true",
                      help="create the store if it does not exist (fresh install only)")
    sub.choices["list"].add_argument("--json", action="store_true")
    sub.choices["revoke"].add_argument("--handle", required=True)

    args = parser.parse_args(argv)
    db = args.db or _default_db(args.service)

    try:
        ensure_schema(db, create=(args.cmd == "mint" and args.init))
        store = Store(db, args.service)
        if args.cmd == "mint":
            raw, handle = store.mint(args.role, args.label, _actor())
            events.token_created(args.service, handle, args.label, args.role, _actor())
            print(f"handle: {handle}")
            print("SAVE THIS TOKEN — it is shown only once:")
            print(raw)
        elif args.cmd == "list":
            rows, has_more = store.list_rows(include_revoked=True)
            public = [
                {k: r[k] for k in ("label", "role", "priority", "rate_limit",
                                   "created_at", "created_by", "last_used_at", "revoked_at")}
                | {"handle": r["token_sha256"][:16]}
                for r in rows
            ]
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
                events.token_revoked(args.service, args.handle, row["label"], _actor())
                print(f"revoked {args.handle}")
            else:
                print(f"{args.handle} was already revoked; no change")
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
