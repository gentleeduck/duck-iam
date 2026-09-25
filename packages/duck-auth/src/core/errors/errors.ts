import { createErrorKit, type ErrorKit, type KitError } from '@gentleduck/error'
import { AUTH_ERRORS } from './errors.codes'

const kit = createErrorKit('AuthError', AUTH_ERRORS)

export const AuthError = kit.ErrorClass
/** The value above is the class; this is its type, parameterized by code — a real `class`
 *  declaration gets both automatically under one name, a `const` binding does not, so it is
 *  declared explicitly here. Every existing signature in this package that writes `AuthError` or
 *  `AuthError<C>` as a type depends on this. */
export type AuthError<C extends AuthError.Code = AuthError.Code> = KitError<typeof AUTH_ERRORS, C>

export const asAuthError = kit.asError

// Real function declarations, not `const throwAuthError = kit.throwError`: TypeScript's
// unreachable-code analysis does not reliably carry a `never` return type through a const-aliased
// generic object method across files.
export function throwAuthError<C extends AuthError.Code>(code: C, ...args: AuthError.Args<C>): never {
  return kit.throwError(code, ...args)
}

export function rethrowAuthError<C extends AuthError.Code>(error: unknown, code: C, ...args: AuthError.Args<C>): never {
  return kit.rethrowError(error, code, ...args)
}

export namespace AuthError {
  export type Code = ErrorKit.Code<typeof AUTH_ERRORS>
  export type Meta<C extends AuthError.Code> = ErrorKit.Meta<typeof AUTH_ERRORS, C>
  export type Bare = ErrorKit.Bare<typeof AUTH_ERRORS>
  export type Args<C extends AuthError.Code> = ErrorKit.Args<typeof AUTH_ERRORS, C>
}
