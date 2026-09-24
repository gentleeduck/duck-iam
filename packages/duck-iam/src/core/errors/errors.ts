import { createErrorKit, type ErrorKit, type KitError } from '@gentleduck/errors'
import { IAM_ERRORS } from './errors.codes'

const kit = createErrorKit('IamError', IAM_ERRORS)

export const IamError = kit.ErrorClass
/** The value above is the class; this is its type, parameterized by code — a real `class` declaration gets
 *  both automatically under one name, a `const` binding does not, so it is declared explicitly here. Every
 *  existing signature in this package that writes `IamError` or `IamError<C>` as a type depends on this. */
export type IamError<C extends IamError.Code = IamError.Code> = KitError<typeof IAM_ERRORS, C>

export const fail = kit.fail
export const asIamError = kit.asError
export const hasIamErrorCode = kit.hasErrorCode
export const metaOf = kit.metaOf

// Real function declarations, not `const throwIamError = kit.throwError`: TypeScript's unreachable-code
// analysis does not reliably carry a `never` return type through a const-aliased generic object method
// across files — callers like `readInstant` (shared/assign-options.ts), which rely on the call after this
// one being unreachable to satisfy a non-`never` return type without an explicit `return`, need the
// annotation on a real declaration to trust it.
export function throwIamError<C extends IamError.Code>(code: C, ...args: IamError.Args<C>): never {
  return kit.throwError(code, ...args)
}

export function rethrowIamError<C extends IamError.Code>(error: unknown, code: C, ...args: IamError.Args<C>): never {
  return kit.rethrowError(error, code, ...args)
}

export namespace IamError {
  export type Code = ErrorKit.Code<typeof IAM_ERRORS>
  export type Meta<C extends IamError.Code> = ErrorKit.Meta<typeof IAM_ERRORS, C>
  export type Error = { [C in Code]: { code: C } & Meta<C> }[Code]
  export type HasRequired<T> = ErrorKit.HasRequired<T>
  export type Faults = ErrorKit.Faults<typeof IAM_ERRORS>
  export type Bare = ErrorKit.Bare<typeof IAM_ERRORS>
  export type Args<C extends IamError.Code> = ErrorKit.Args<typeof IAM_ERRORS, C>
}
