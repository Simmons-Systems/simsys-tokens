/**
 * Config-token import.
 *
 * Skip-and-report, never throw: import runs inside installTokens() at startup, so
 * throwing would take down any app carrying a legacy role. Accepts a raw `key` or
 * a precomputed `key_sha256`; upserts policy columns only, leaving the digest,
 * label and created_by alone on re-import.
 */
import { DEFAULT as DEFAULT_EMITTER, type Emitter } from "./events.js";
import { tokenHash, validateRole } from "./hashing.js";
import { validatePolicy } from "./core.js";
import type { Store } from "./store.js";

const DIGEST_RE = /^[0-9a-f]{64}$/;

export interface ImportReport {
  imported: number;
  updated: number;
  rejected: Array<[string, string]>;
}

export function importEntries(
  store: Store,
  entries: Array<Record<string, unknown>> | null | undefined,
  opts: { emitter?: Emitter } = {},
): ImportReport {
  const emitter = opts.emitter ?? DEFAULT_EMITTER;
  const report: ImportReport = { imported: 0, updated: 0, rejected: [] };
  for (const entry of entries ?? []) {
    const role = typeof entry.role === "string" ? entry.role : "<missing>";
    // Presence, not truthiness: an explicitly-supplied empty key_sha256 must
    // reach the digest validator that can say what is wrong with it.
    const forms = ["key", "key_sha256"].filter((f) => f in entry);
    if (forms.length !== 1) {
      const reason = `exactly one of key/key_sha256 required, got ${JSON.stringify(forms)}`;
      report.rejected.push([role, reason]);
      emitter.tokenImportRejected(store.service, role, reason);
      continue;
    }
    try {
      validateRole(role);
    } catch (err) {
      const reason = (err as Error).message;
      report.rejected.push([role, reason]);
      emitter.tokenImportRejected(store.service, role, reason);
      continue;
    }
    let digest: string;
    if (forms[0] === "key") {
      const rawKey = entry.key;
      if (typeof rawKey !== "string" || rawKey === "") {
        const reason = "key must be a non-empty string";
        report.rejected.push([role, reason]);
        emitter.tokenImportRejected(store.service, role, reason);
        continue;
      }
      digest = tokenHash(rawKey);
    } else {
      // Validate the value AS SUPPLIED — normalising would store something the
      // operator did not write and quietly accept uppercase hex.
      const supplied = entry.key_sha256;
      if (typeof supplied !== "string" || !DIGEST_RE.test(supplied)) {
        const reason = "key_sha256 must be 64 lowercase hex characters";
        report.rejected.push([role, reason]);
        emitter.tokenImportRejected(store.service, role, reason);
        continue;
      }
      digest = supplied;
    }
    const bad = validatePolicy(entry);
    if (bad) {
      report.rejected.push([role, bad]);
      emitter.tokenImportRejected(store.service, role, bad);
      continue;
    }
    const label = typeof entry.label === "string" && entry.label ? entry.label : `imported:${role}`;
    const priority = (entry.priority as number | null | undefined) ?? null;
    const rateLimit = (entry.rate_limit as string | null | undefined) ?? null;
    let existing = store.findAny(digest);
    if (!existing) {
      try {
        const handle = store.insertDigest(digest, role, label, "config-import", { priority, rateLimit });
        emitter.tokenImported(store.service, handle, label, role);
        report.imported += 1;
        continue;
      } catch (err) {
        // Distinguish a primary-key collision from a live-label collision: a
        // concurrent import of the SAME secret (multi-worker boot) must converge
        // to the upsert path, not be reported as a label conflict.
        const raced = store.findAny(digest);
        if (!raced) {
          const reason = `label ${JSON.stringify(label)} already in use by a live token`;
          report.rejected.push([role, reason]);
          emitter.tokenImportRejected(store.service, role, reason);
          continue;
        }
        existing = raced;
      }
    }
    if (existing.priority !== priority || existing.rate_limit !== rateLimit) {
      store.updatePolicy(digest, priority, rateLimit);
      report.updated += 1;
    }
  }
  return report;
}
