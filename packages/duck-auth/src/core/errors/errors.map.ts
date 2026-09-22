import { type AuthError, asAuthError } from './errors'

/** A mapper and the range it draws from. `codes` is the same table, at runtime. */
export type ErrorMap<C extends AuthError.Code> = {
  /** WARN: wide on purpose, since `asAuthError` passes an already-typed error through with its own
   *  code. */
  (err: unknown): AuthError
  readonly codes: ReadonlySet<C>
}

/** The range an {@link ErrorMap} draws from, so a caller reads it off the map rather than restating it. */
export type RangeOf<M> = M extends ErrorMap<infer C> ? C : never

/** A mapper and the range it draws from, as one value: the only shape an {@link ErrorMap} is built in. */
export function errorMap<const C extends AuthError.Code>(
  map: (err: unknown) => AuthError,
  codes: readonly C[],
): ErrorMap<C> {
  return Object.assign(map, { codes: new Set(codes) })
}

/** An {@link ErrorMap} widened by the codes a store throws itself rather than mapping from its driver. */
export function declares<C extends AuthError.Code, const E extends readonly AuthError.Code[]>(
  map: ErrorMap<C>,
  extra: E,
): ErrorMap<C | E[number]> {
  // Wrapped, not widened in place: `errorMap` assigns onto what it is given, and `map` keeps its own range.
  return errorMap((err: unknown) => map(err), [...map.codes, ...extra])
}

/** What a store with no driver of its own answers with. */
export const GENERIC = errorMap((err: unknown) => asAuthError(err, 'AUTH_ADAPTER_FAILED'), ['AUTH_ADAPTER_FAILED'])
