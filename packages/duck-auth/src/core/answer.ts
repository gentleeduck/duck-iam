import { type AuthError, asAuthError } from './errors'

/** A call's answer and the readers on it: the engine's public surface answers in this, an adapter never does. */
export namespace Answer {
  /** What `wrap` answers: the value, or the error awaiting the call would have thrown. */
  export type Result<T> =
    | { readonly data: T; readonly error: null }
    | { readonly data: null; readonly error: AuthError }

  /** A call in flight. Awaiting it throws; the readers take the failure as a value instead.
   *  `orNull` and `orDefault` answer again, so `wrap` still follows either one. */
  export interface Me<T> extends Promise<T> {
    /** The value, or this one where there was no row. */
    orDefault(fallback: T): Me<T>
    /** The value, or `null` where there was no row. */
    orNull(): Me<T | null>
    /** `{ data, error }`: `error` is null when the call ran, and what it would have thrown otherwise. */
    wrap(): Wrapped<T>
  }

  /** What `wrap` hands back, with the two swallowing readers still on it: absence is the same answer whether
   *  it is swallowed before the wrap or after, so both orders are written and both mean the one thing. */
  export interface Wrapped<T> extends Promise<Result<T>> {
    orDefault(fallback: T): Wrapped<T>
    orNull(): Wrapped<T | null>
  }
}

/** The codes that mean "no row". The swallowing readers take these and rethrow everything else. */
export const ABSENT: ReadonlySet<AuthError.Code> = new Set<AuthError.Code>([
  'AUTH_CREDENTIAL_NOT_FOUND',
  'AUTH_IDEMPOTENCY_MISS',
  'AUTH_IDENTITY_NOT_FOUND',
  'AUTH_IMPERSONATE_WINDOW_CLOSED',
  'AUTH_JWT_INVALID',
  'AUTH_JWT_KEY_UNKNOWN',
  'AUTH_MEMBERSHIP_NOT_FOUND',
  'AUTH_ORG_NOT_FOUND',
  'AUTH_SESSION_EXPIRED',
  'AUTH_SESSION_REVOKED',
])

/**
 * Absence alone as a value, for a caller inside the engine with no answer to put readers on.
 *
 * SECURITY: every other failure still throws, so a store that is down cannot be read as a row that is not
 * there — which is how a signup reads a timed-out lookup as a free email address.
 */
export function orNull<T>(call: Promise<T>): Promise<T | null> {
  return orElse(call, null)
}

/** Only the row that is not there: a call that failed for any other reason still throws. */
function orElse<T, F>(call: Promise<T>, fallback: F): Promise<T | F> {
  return call.catch((thrown: unknown) => {
    if (ABSENT.has(asAuthError(thrown, 'AUTH_ADAPTER_FAILED').code)) return fallback

    throw thrown
  })
}

/** A call with the readers on it. A thunk is taken too, so a body that refuses its arguments before its first
 *  await rejects rather than throwing where the call is written, past the readers. */
export function answer<T>(call: Promise<T> | (() => Promise<T>)): Answer.Me<T> {
  return readers(new Promise<T>((resolve) => resolve(typeof call === 'function' ? call() : call)))
}

/** What `orNull` and `orDefault` hand back carries them too, so `wrap` follows either one. */
function readers<T>(call: Promise<T>): Answer.Me<T> {
  return Object.assign(call, {
    orDefault: (fallback: T): Answer.Me<T> => readers(orElse(call, fallback)),
    orNull: (): Answer.Me<T | null> => readers(orElse(call, null)),
    wrap: (): Answer.Wrapped<T> => wrapped(call),
  })
}

/** The wrap with its own two readers: swallowing a missing row before the wrap or after is the same answer. */
function wrapped<T>(call: Promise<T>): Answer.Wrapped<T> {
  const result = call.then(
    (data): Answer.Result<T> => ({ data, error: null }),
    // A driver's own `Error` never escapes as `error`: it arrives labelled, with the original on `cause`.
    (thrown: unknown): Answer.Result<T> => ({ data: null, error: asAuthError(thrown, 'AUTH_ADAPTER_FAILED') }),
  )

  return Object.assign(result, {
    orDefault: (fallback: T): Answer.Wrapped<T> => wrapped(orElse(call, fallback)),
    orNull: (): Answer.Wrapped<T | null> => wrapped(orElse(call, null)),
  })
}
