/**
 * Lifecycle events, emitted through an injectable sink.
 *
 * The default sink writes one JSON line to stdout — no dependencies. An Emitter
 * owns a sink, so a process hosting more than one service gives each its own
 * instead of sharing one global. `DEFAULT` is the process-wide fallback.
 *
 * `token.auth_failed` fires ONLY when a bearer credential was presented and
 * failed to resolve — never on the no-credential path, which runs on effectively
 * every request.
 */
export type EventSink = (event: string, fields: Record<string, unknown>) => void;

export const DEFAULT_SERVICE = "unknown";

export function stdoutSink(event: string, fields: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify({ event, ...fields })}\n`);
}

export class Emitter {
  sink: EventSink;
  service?: string;

  constructor(opts: { sink?: EventSink; service?: string } = {}) {
    this.sink = opts.sink ?? stdoutSink;
    this.service = opts.service;
  }

  emit(event: string, fields: Record<string, unknown> = {}, service?: string): void {
    // A sink that throws must never break the request path: events are
    // observability, not control flow.
    try {
      this.sink(event, { service: service ?? this.service ?? DEFAULT_SERVICE, ...fields });
    } catch {
      /* never propagate */
    }
  }

  tokenCreated(service: string, handle: string, label: string, role: string, actor: string): void {
    this.emit("token.created", { handle, label, role, actor }, service);
  }

  tokenRevoked(service: string, handle: string, label: string, actor: string): void {
    this.emit("token.revoked", { handle, label, actor }, service);
  }

  tokenRelabelled(service: string, handle: string, oldLabel: string, newLabel: string, actor: string): void {
    this.emit("token.relabelled", { handle, old: oldLabel, new: newLabel, actor }, service);
  }

  tokenPolicyChanged(service: string, handle: string, field: string, oldValue: unknown, newValue: unknown, actor: string): void {
    this.emit("token.policy_changed", { handle, field, old: oldValue, new: newValue, actor }, service);
  }

  tokenImported(service: string, handle: string, label: string, role: string): void {
    this.emit("token.imported", { handle, label, role }, service);
  }

  tokenImportRejected(service: string, role: string, reason: string): void {
    this.emit("token.import_rejected", { role, reason }, service);
  }

  tokenAuthFailed(
    service: string,
    fields: { handle?: string | null; label?: string | null; digestPrefix?: string | null; reason: string },
  ): void {
    this.emit(
      "token.auth_failed",
      {
        handle: fields.handle ?? null,
        label: fields.label ?? null,
        digest_prefix: fields.digestPrefix ?? null,
        reason: fields.reason,
      },
      service,
    );
  }

  tokenFirstUse(service: string, handle: string, label: string): void {
    this.emit("token.first_use", { handle, label }, service);
  }
}

export const DEFAULT = new Emitter();

/** Reconfigure the process default's sink, or reset it to stdout. */
export function setSink(sink?: EventSink | null): void {
  DEFAULT.sink = sink ?? stdoutSink;
}
