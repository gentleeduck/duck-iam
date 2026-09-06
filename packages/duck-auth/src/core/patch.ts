/**
 * Drop keys explicitly set to `undefined` before a patch is merged or turned
 * into a `SET` clause.
 *
 * `{ ...current, ...patch }` treats `{ profile: undefined }` as "write
 * undefined over profile", which is not what a caller spreading an optional
 * field ever means - `{ profile: maybeProfile }` with nothing to say should
 * leave the column alone, not clear it. Every store does this, so the rule
 * lives in one place: three copies of a semantics this quiet is how the three
 * adapters drift apart.
 */
export function stripUndefined<T extends object>(obj: T): Partial<T> {
  const out: Partial<T> = {}
  for (const key in obj) {
    if (obj[key] !== undefined) out[key] = obj[key]
  }
  return out
}
