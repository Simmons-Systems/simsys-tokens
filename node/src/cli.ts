#!/usr/bin/env node
/**
 * Provisioning CLI.
 *
 * Only `mint --init` may create the store. `list`, `revoke` and `verify` never
 * create it: the conformance check shells out to `list`, and a list that
 * auto-created an empty store would report a never-adopted app as clean.
 *
 * `verify` reads the token from stdin by default, so it does not land in shell
 * history, and exits 0 only when the token is live.
 */
import { readFileSync } from "node:fs";
import { userInfo } from "node:os";

import { DEFAULT as DEFAULT_EMITTER } from "./events.js";
import { tokenHash } from "./hashing.js";
import type { TokenRow } from "./store.js";
import { Store, ensureSchema, isExpired } from "./store.js";

interface Args {
  cmd: string;
  flags: Map<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const [cmd, ...rest] = argv;
  const flags = new Map<string, string | boolean>();
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (!a.startsWith("--")) throw new Error(`unexpected argument ${a}`);
    const key = a.slice(2);
    const next = rest[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags.set(key, next);
      i++;
    } else {
      flags.set(key, true);
    }
  }
  return { cmd: cmd ?? "", flags };
}

function str(args: Args, name: string): string | undefined {
  const v = args.flags.get(name);
  return typeof v === "string" ? v : undefined;
}

function actor(): string {
  return `cli:${userInfo().username}@${process.env.HOSTNAME ?? "unknown"}`;
}

function publicRow(row: TokenRow): Record<string, unknown> {
  return {
    handle: row.token_sha256.slice(0, 16),
    label: row.label,
    role: row.role,
    priority: row.priority,
    rate_limit: row.rate_limit,
    expires_at: row.expires_at,
    created_at: row.created_at,
    created_by: row.created_by,
    last_used_at: row.last_used_at,
    revoked_at: row.revoked_at,
    revoked_by: row.revoked_by,
  };
}

function classify(row: TokenRow | undefined): string {
  if (!row) return "unknown";
  if (row.revoked_at !== null) return "revoked";
  if (isExpired(row.expires_at)) return "expired";
  return "live";
}

/** `io.readStdin` is a seam for tests; production reads fd 0. */
export interface CliIo {
  readStdin?: () => string;
}

export function main(argv: string[], io: CliIo = {}): number {
  let args: Args;
  try {
    args = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 1;
  }
  const service = str(args, "service");
  if (!service) {
    process.stderr.write("error: --service is required\n");
    return 1;
  }
  const dbPath = str(args, "db") ?? `/var/lib/${service}/tokens.db`;
  const asJson = args.flags.get("json") === true;
  const create = args.cmd === "mint" && args.flags.get("init") === true;

  try {
    ensureSchema(dbPath, { create });
    const store = new Store(dbPath, service);

    if (args.cmd === "mint") {
      const role = str(args, "role");
      const label = str(args, "label");
      if (!role || !label) throw new Error("mint requires --role and --label");
      const expiresAt = str(args, "expires-at") ?? null;
      const { raw, handle } = store.mint(role, label, actor(), { expiresAt });
      DEFAULT_EMITTER.tokenCreated(service, handle, label, role, actor());
      if (asJson) {
        process.stdout.write(`${JSON.stringify({ handle, token: raw, label, role, expires_at: expiresAt })}\n`);
      } else {
        process.stdout.write(`handle: ${handle}\nSAVE THIS TOKEN — it is shown only once:\n${raw}\n`);
      }
      return 0;
    }

    if (args.cmd === "list") {
      const { rows, hasMore } = store.listRows({ includeRevoked: true });
      const pub = rows.map(publicRow);
      if (asJson) {
        process.stdout.write(`${JSON.stringify(pub, null, 2)}\n`);
      } else {
        for (const row of pub) {
          process.stdout.write(`${row.handle}  ${String(row.role).padEnd(8)}  ${row.label}\n`);
        }
      }
      if (hasMore) {
        process.stderr.write(`warning: more than ${pub.length} tokens exist; output truncated\n`);
        return 1;
      }
      return 0;
    }

    if (args.cmd === "revoke") {
      const handle = str(args, "handle");
      if (!handle) throw new Error("revoke requires --handle");
      const { row, changed } = store.revoke(handle, actor());
      if (changed) DEFAULT_EMITTER.tokenRevoked(service, handle, row.label, actor());
      if (asJson) {
        process.stdout.write(`${JSON.stringify({ ...publicRow(row), changed })}\n`);
      } else if (changed) {
        process.stdout.write(`revoked ${handle}\n`);
      } else {
        process.stdout.write(`${handle} was already revoked; no change\n`);
      }
      return 0;
    }

    if (args.cmd === "verify") {
      // --token is visible in the process list; stdin is the default.
      let presented = str(args, "token") ?? null;
      if (presented === null) {
        try {
          presented = (io.readStdin ?? (() => readFileSync(0, "utf8")))().trim() || null;
        } catch {
          presented = null;
        }
      }
      if (presented?.startsWith("Bearer ")) presented = presented.slice("Bearer ".length);
      const row = presented ? store.findAny(tokenHash(presented)) : undefined;
      const state = classify(row);
      if (asJson) {
        process.stdout.write(
          `${JSON.stringify({
            state,
            ...(row ? { handle: row.token_sha256.slice(0, 16), label: row.label, role: row.role } : {}),
          })}\n`,
        );
      } else if (!row) {
        process.stderr.write("unknown — no such token in this service\n");
      } else {
        process.stdout.write(`${state}  ${row.token_sha256.slice(0, 16)}  ${row.role}  ${row.label}\n`);
        if (state === "expired") process.stderr.write(`expired at ${row.expires_at}\n`);
      }
      return state === "live" ? 0 : 1;
    }

    throw new Error(`unknown command ${args.cmd}`);
  } catch (err) {
    if (/UNIQUE constraint failed/i.test((err as Error).message ?? "")) {
      process.stderr.write(
        `error: a live token in service ${JSON.stringify(service)} already uses ` +
          `label ${JSON.stringify(str(args, "label") ?? "?")}\n`,
      );
      return 1;
    }
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(main(process.argv.slice(2)));
}
