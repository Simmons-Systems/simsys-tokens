/**
 * Exact-origin CSRF check for mutating management endpoints.
 *
 * Fail closed. A request carrying NEITHER Origin nor Referer is rejected: a
 * default-allow there is a complete bypass, and it is the branch a test must
 * cover explicitly because the foreign-Origin case passes either way.
 */
export function originOf(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return "";
  }
}

export function checkOrigin(
  siteOrigin: string,
  origin: string | null | undefined,
  referer: string | null | undefined,
): boolean {
  const expected = originOf(siteOrigin);
  if (!expected) {
    throw new Error(`site_origin is not a valid absolute origin: ${JSON.stringify(siteOrigin)}`);
  }
  if (origin) return originOf(origin) === expected;
  if (referer) return originOf(referer) === expected;
  return false;
}
