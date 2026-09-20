/** Drops keys explicitly set to `undefined` before a patch is merged or turned into a `SET` clause. */
export function stripUndefined<T extends object>(obj: T): Partial<T> {
  const out: Partial<T> = {}
  for (const key in obj) {
    if (obj[key] !== undefined) out[key] = obj[key]
  }
  return out
}

/** The same patch, or `undefined` when it names nothing a store can write. */
export function patchOrNone<T extends object>(obj: T): Partial<T> | undefined {
  const kept = stripUndefined(obj)
  return Object.keys(kept).length === 0 ? undefined : kept
}
