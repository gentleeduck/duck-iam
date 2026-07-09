/**
 * `Envelope` — the discriminated response envelope the auth client speaks.
 *
 * Deliberately dependency-free but shape-identical to a standard `{ ok, code,
 * data } | { ok:false, error }` API envelope, so a server that returns this
 * pattern (like a NestJS `ResponseType`) needs no client-side adapter.
 */
export type Envelope<T, C extends string = string> =
  | { ok: true; code: C; data: T }
  | { ok: false; error: { code: C; cause?: unknown; issues?: readonly string[] } }
