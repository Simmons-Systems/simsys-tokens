/** Errors a caller is expected to handle. */
export class TokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TokenError";
  }
}

/** Raised with a sentence, never a bare handle — the CLI prints it directly. */
export class NoSuchHandle extends TokenError {
  constructor(message: string) {
    super(message);
    this.name = "NoSuchHandle";
  }
}

export class AmbiguousHandle extends TokenError {
  constructor(message: string) {
    super(message);
    this.name = "AmbiguousHandle";
  }
}
