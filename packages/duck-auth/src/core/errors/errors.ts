import { createErrorKit, type ErrorKit, type KitError } from '@gentleduck/error'
import { AUTH_ERRORS } from './errors.codes'

const kit = createErrorKit('AuthError', AUTH_ERRORS)

/** The one error class this package throws: a code from `AUTH_ERRORS`, its HTTP status, and its meta. */
export const AuthError = kit.ErrorClass
/** The class as a type, which a `const` binding does not get on its own the way a `class` would. */
export type AuthError<C extends AuthError.Code = AuthError.Code> = KitError<typeof AUTH_ERRORS, C>

/** An `AuthError` as it stands; anything else wrapped under the given code, the original on `cause`. */
export const asAuthError = kit.asError

// Declarations, not `const throwAuthError = kit.throwError`: a const-aliased generic object method
// does not carry its `never` into another file's unreachable-code analysis.
/** Throws an `AuthError` for the code, with the meta that code requires. */
export function throwAuthError<C extends AuthError.Code>(code: C, ...args: AuthError.Args<C>): never {
  return kit.throwError(code, ...args)
}

/** `asAuthError`, thrown rather than returned. */
export function rethrowAuthError<C extends AuthError.Code>(error: unknown, code: C, ...args: AuthError.Args<C>): never {
  return kit.rethrowError(error, code, ...args)
}

/** The types derived from the `AUTH_ERRORS` registry. */
export namespace AuthError {
  /** Every code this package raises. */
  export type Code = ErrorKit.Code<typeof AUTH_ERRORS>
  /** The meta a code carries on `err.meta`. */
  export type Meta<C extends AuthError.Code> = ErrorKit.Meta<typeof AUTH_ERRORS, C>
  /** The codes that carry no required meta. */
  export type Bare = ErrorKit.Bare<typeof AUTH_ERRORS>
  /** The meta argument a code's constructor takes: none, optional, or required. */
  export type Args<C extends AuthError.Code> = ErrorKit.Args<typeof AUTH_ERRORS, C>
}
