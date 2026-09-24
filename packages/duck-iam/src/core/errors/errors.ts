import { type Fault, IAM_ERRORS, type MetaOf } from './errors.codes'
import { scrubMeta } from './errors.scrub'

export class IamError<C extends IamError.Code = IamError.Code> extends Error {
  readonly code: C
  readonly status: number
  /** Same value as `status`, under the name Nest's base exception filter reads: it answers 500 for a
   *  non-`HttpException` unless the thrown value has both `statusCode` and `message`. */
  readonly statusCode: number
  readonly meta: Record<string, unknown>

  constructor(code: C, ...args: IamError.Args<C>) {
    super(code)
    this.name = 'IamError'
    this.code = code
    this.status = IAM_ERRORS[code]
    this.statusCode = this.status
    const [meta] = args
    this.meta = { ...meta }
  }

  /** Wire-safe envelope. Never reads `.cause`, so driver internals stay out of the response and in the log. */
  toJSON(): { ok: false; error: { code: C; status: number } & Record<string, unknown> } {
    return { ok: false, error: { code: this.code, status: this.status, ...scrubMeta(this.meta) } }
  }
}

/** Reads `err.meta` at the shape `code` declares. Safe because the caller has just confirmed `err.code === code`
 *  (directly, or via {@link IamError.prototype}'s own `code` field after an `instanceof` + equality check) — the
 *  one place this module accepts that on faith instead of re-deriving it, so nothing else has to. */
export function metaOf<C extends IamError.Code>(err: IamError, code: C): IamError.Meta<C> {
  return err.meta as IamError.Meta<C>
}

/**
 * True when `err` carries `code`, checked by property rather than `instanceof IamError` — so it still matches an
 * `IamError` thrown by a duplicated copy of this package (a possible outcome of hoisting in a monorepo, or of an
 * adapter published and installed separately from core). `adapters/redis`'s old `isCorruptAttributes` and every
 * server adapter's old `iamIsValidationError` matched by `.name` for exactly this reason — this is their
 * replacement, generalised to any code rather than one class per code. `instanceof IamError` stays right
 * everywhere the throw site and the catch site are compiled together (every other retrofit in this plan, e.g.
 * `engine.ts` catching what `compiled.compile.ts` throws): reach for this only where that is not guaranteed.
 * Narrows all the way to `.meta`, so a caller never needs a separate `metaOf` call after it.
 */
export function hasIamErrorCode<C extends IamError.Code>(
  err: unknown,
  code: C,
): err is Error & { readonly meta: IamError.Meta<C> } {
  return err instanceof Error && 'code' in err && err.code === code
}

/** Throw a typed IamError, so no caller constructs `new IamError(...)` directly. */
export function throwIamError<C extends IamError.Code>(code: C, ...args: IamError.Args<C>): never {
  throw new IamError(code, ...args)
}

/** An already-typed error as it stands, anything else under the fallback code with what actually failed on
 *  `cause`. The one place an unknown failure becomes a typed one. */
export function asIamError<C extends IamError.Code>(error: unknown, code: C, ...args: IamError.Args<C>): IamError {
  if (error instanceof IamError) return error
  const typed = new IamError(code, ...args)
  typed.cause = error
  return typed
}

/** {@link asIamError}, thrown rather than returned. */
export function rethrowIamError<C extends IamError.Code>(error: unknown, code: C, ...args: IamError.Args<C>): never {
  throw asIamError(error, code, ...args)
}

export namespace IamError {
  /** Every code, at the meta it declared. */
  export type Code = keyof typeof IAM_ERRORS

  /** Extra fields for a given error code: everything the code itself does not say. */
  export type Meta<C extends IamError.Code> = MetaOf<(typeof IAM_ERRORS)[C]>

  /** The codes as a union a caller can match on, each with what it carries. */
  export type Error = { [C in Code]: { code: C } & Meta<C> }[Code]

  /** True when T has at least one non-optional key. */
  export type HasRequired<T> = { [K in keyof T]-?: undefined extends T[K] ? never : K }[keyof T]

  /** The codes an adapter answers with: what a store raises itself. */
  export type Faults = { [C in Code]: (typeof IAM_ERRORS)[C] extends Fault ? C : never }[Code]

  /** A code that needs nothing beyond itself. */
  export type Bare = { [C in Code]: [HasRequired<Meta<C>>] extends [never] ? C : never }[Code]

  /** Conditional rest args: meta optional when no required fields, required otherwise. */
  export type Args<C extends IamError.Code> = [HasRequired<Meta<C>>] extends [never]
    ? [meta?: Meta<C>]
    : [meta: Meta<C>]
}
