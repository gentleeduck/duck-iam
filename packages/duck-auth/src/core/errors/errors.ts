import { AUTH_ERRORS, type Fault, type MetaOf } from './errors.codes'
import { scrubMeta } from './errors.scrub'

export class AuthError<C extends AuthError.Code = AuthError.Code> extends Error {
  readonly code: C
  readonly status: number
  readonly meta: Record<string, unknown>
  readonly origin?: AuthError.Origin

  constructor(code: C, ...args: AuthError.Args<C>) {
    super(code)
    this.name = 'AuthError.IAuthError'
    this.code = code
    this.status = AUTH_ERRORS[code]
    const [meta, origin] = args
    this.meta = { ...meta }
    if (isOrigin(origin)) this.origin = origin
  }

  /** Wire-safe envelope matching ResponseType<T, M> error branch. Never leaks sensitive meta keys. */
  toJSON(): { ok: false; error: { code: C; status: number } & Record<string, unknown> } {
    return { ok: false, error: { code: this.code, status: this.status, ...scrubMeta(this.meta) } }
  }
}

/** Throw a typed AuthError, so no caller constructs `new AuthError(...)` directly. */
export function throwAuthError<C extends AuthError.Code>(code: C, ...args: AuthError.Args<C>): never {
  throw new AuthError(code, ...args)
}

/** An already-typed error as it stands, anything else under the fallback code with what actually failed
 *  on `cause`. The one place an unknown failure becomes a typed one. */
export function asAuthError<C extends AuthError.Code>(error: unknown, code: C, ...args: AuthError.Args<C>): AuthError {
  if (error instanceof AuthError) return error

  // `toJSON` never reads `cause`, so the driver's message stays out of the wire envelope and in the log.
  const typed = new AuthError(code, ...args)
  typed.cause = error
  return typed
}

/** {@link asAuthError}, thrown rather than returned. */
export function rethrowAuthError<C extends AuthError.Code>(error: unknown, code: C, ...args: AuthError.Args<C>): never {
  throw asAuthError(error, code, ...args)
}

/** The second argument a caller passed is only kept when it really is an origin. */
function isOrigin(value: unknown): value is AuthError.Origin {
  return typeof value === 'object' && value !== null
}

/** Where an `AuthError` came from, and the wire shape `toJSON` produces. */
export namespace AuthError {
  export interface Origin {
    providerId?: string
    flow?: string
  }

  /** Every code, at the meta it declared. */
  export type Code = keyof typeof AUTH_ERRORS

  /** Extra fields for a given error code: everything the code itself does not say. */
  export type Meta<C extends AuthError.Code> = MetaOf<(typeof AUTH_ERRORS)[C]>

  /** The codes as a union a caller can match on, each with what it carries. */
  export type Error = { [C in Code]: { code: C } & Meta<C> }[Code]

  /** True when T has at least one non-optional key. */
  export type HasRequired<T> = { [K in keyof T]-?: undefined extends T[K] ? never : K }[keyof T]

  /** The codes an adapter answers with: what a store raises itself, and what a driver refusal becomes. */
  export type Faults = { [C in Code]: (typeof AUTH_ERRORS)[C] extends Fault ? C : never }[Code]

  /** A code that needs nothing beyond itself. Every other one is only ever raised through a helper that supplies
   *  what it carries, so nothing can name a code and leave its meta missing. */
  export type Bare = { [C in Code]: [HasRequired<Meta<C>>] extends [never] ? C : never }[Code]

  /** Conditional rest args: meta optional when no required fields, required otherwise. */
  export type Args<C extends AuthError.Code> = [HasRequired<Meta<C>>] extends [never]
    ? [meta?: Meta<C>, origin?: AuthError.Origin]
    : [meta: Meta<C>, origin?: AuthError.Origin]
}
