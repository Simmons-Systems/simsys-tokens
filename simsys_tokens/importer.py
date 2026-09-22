"""Config-token import.

Skip-and-report, never raise: import runs inside install_tokens() at startup, so
raising would take down any app carrying a legacy role — and the instruction to
"rotate it as part of adoption" presupposes the app is reachable to rotate from.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field

from . import events
from .core import validate_policy
from .hashing import token_hash, validate_role
from .store import Store

DIGEST_RE = re.compile(r"[0-9a-f]{64}")


@dataclass
class ImportReport:
    imported: int = 0
    updated: int = 0
    rejected: list[tuple[str, str]] = field(default_factory=list)


def import_entries(store: Store, entries) -> ImportReport:
    report = ImportReport()
    for entry in entries or []:
        role = entry.get("role", "<missing>")
        # `f in entry`, not `entry.get(f)`: an explicitly-supplied empty
        # key_sha256 is falsy, so a truthiness test reports "exactly one of
        # key/key_sha256 required, got []" instead of routing it to the digest
        # validator that can say what is actually wrong with it.
        forms = [f for f in ("key", "key_sha256") if f in entry]
        if len(forms) != 1:
            reason = f"exactly one of key/key_sha256 required, got {forms}"
            report.rejected.append((role, reason))
            events.token_import_rejected(store.service, role, reason)
            continue
        try:
            validate_role(role)
        except ValueError as exc:
            report.rejected.append((role, str(exc)))
            events.token_import_rejected(store.service, role, str(exc))
            continue
        # Dispatch on the `forms` list computed above, NOT on truthiness again.
        # Re-deriving here with entry.get("key") sends {"key": ""} — an unset env
        # var interpolated to empty is the obvious way to get one — down the
        # key_sha256 branch, where it raises KeyError out of install_tokens() at
        # startup and takes the host app down. This module never raises.
        if forms == ["key"]:
            raw_key = entry["key"]
            if not isinstance(raw_key, str) or not raw_key:
                reason = "key must be a non-empty string"
                report.rejected.append((role, reason))
                events.token_import_rejected(store.service, role, reason)
                continue
            digest = token_hash(raw_key)
        else:
            # A supplied digest is unvalidated input from someone's config.
            # Store it unchecked and the row can never match any real token —
            # the caller's auth just fails forever, with nothing to point at.
            #
            # Validate the value AS SUPPLIED: normalising with .strip().lower()
            # would quietly accept 64 uppercase hex, and a supplied digest is
            # "used directly", so normalising would store something the operator
            # did not write.
            digest = entry["key_sha256"]
            if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
                reason = "key_sha256 must be 64 lowercase hex characters"
                report.rejected.append((role, reason))
                events.token_import_rejected(store.service, role, reason)
                continue
        bad = validate_policy(entry)
        if bad:
            report.rejected.append((role, bad))
            events.token_import_rejected(store.service, role, bad)
            continue
        label = entry.get("label") or f"imported:{role}"
        existing = store.find_any(digest)
        if existing is None:
            try:
                handle = store.insert_digest(
                    digest, role, label, "config-import",
                    entry.get("priority"), entry.get("rate_limit"),
                )
            except sqlite3.IntegrityError:
                # Distinguish PK collision from live-label collision. A bare
                # except reports both as "label in use", which misdiagnoses a
                # concurrent import of the SAME secret (multi-worker boot runs
                # import in every worker) as a label conflict. Re-fetch: if the
                # digest now exists, another writer won the race — fall through
                # to the policy-upsert path below instead of rejecting.
                raced = store.find_any(digest)
                if raced is None:
                    reason = f"label {label!r} already in use by a live token"
                    report.rejected.append((role, reason))
                    events.token_import_rejected(store.service, role, reason)
                    continue
                existing = raced
            else:
                events.token_imported(store.service, handle, label, role)
                report.imported += 1
                continue
        # Upsert the POLICY columns only. A pure ignore means an operator
        # editing rate_limit in config and restarting sees no change while
        # the app quietly enforces the stale policy from the store.
        if (existing["priority"], existing["rate_limit"]) != (
            entry.get("priority"), entry.get("rate_limit")
        ):
            store.update_policy(digest, entry.get("priority"), entry.get("rate_limit"))
            report.updated += 1
    return report
