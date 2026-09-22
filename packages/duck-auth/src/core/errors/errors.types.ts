/** The discriminated envelope the auth client speaks. Dependency-free but shape-identical to the usual
 *  `{ ok, code, data } | { ok: false, error }`, so a server already returning that needs no adapter. */
export type Envelope<T, C extends string = string> =
  | { ok: true; code: C; data: T }
  | { ok: false; error: { code: C; cause?: unknown; issues?: readonly string[] } }
