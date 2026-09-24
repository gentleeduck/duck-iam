import type { Carries, Fault, MetaOf } from './brand'
import { scrubMeta } from './scrub'

export namespace ErrorKit {
  export type Registry = Record<string, number>

  /** Every code in a registry, as a string union. */
  export type Code<R extends Registry> = keyof R & string

  /** Extra fields for a given code: everything the code itself does not say. */
  export type Meta<R extends Registry, C extends Code<R>> = MetaOf<R[C]>

  /** True when T has at least one non-optional key. */
  export type HasRequired<T> = { [K in keyof T]-?: undefined extends T[K] ? never : K }[keyof T]

  /** The codes a store/adapter answers with itself. */
  export type Faults<R extends Registry> = { [C in Code<R>]: R[C] extends Fault ? C : never }[Code<R>]

  /** A code that needs nothing beyond itself. */
  export type Bare<R extends Registry> = {
    [C in Code<R>]: [HasRequired<Meta<R, C>>] extends [never] ? C : never
  }[Code<R>]

  /** Conditional rest args: no argument at all for a code with no declared shape (a plain number or a
   *  bare `fault()`), optional when its declared shape has no required fields, required otherwise. A code
   *  with no declared shape resolves `Meta` to `{}`, which would otherwise accept any object as meta since
   *  `{}` has no properties for excess-property checking to reject; gating on the registry value's own
   *  `Carries` brand catches that case before it reaches `Meta` at all. */
  export type Args<R extends Registry, C extends Code<R>> =
    R[C] extends Carries<any>
      ? [HasRequired<Meta<R, C>>] extends [never]
        ? [meta?: Meta<R, C>]
        : [meta: Meta<R, C>]
      : []
}

/** The shape every kit's error instances have, independent of which kit built them. */
export interface KitError<R extends ErrorKit.Registry, C extends ErrorKit.Code<R> = ErrorKit.Code<R>> extends Error {
  readonly code: C
  readonly status: number
  /** Same value as `status`, under the name Nest's base exception filter reads. */
  readonly statusCode: number
  readonly meta: Record<string, unknown>
  toJSON(): { ok: false; error: { code: C; status: number } & Record<string, unknown> }
}

export interface ErrorKit<R extends ErrorKit.Registry, Name extends string> {
  /** A fresh class, distinct from every other kit's — never shared, so `instanceof` never crosses kits. */
  readonly ErrorClass: new <C extends ErrorKit.Code<R> = ErrorKit.Code<R>>(
    code: C,
    ...args: ErrorKit.Args<R, C>
  ) => KitError<R, C>
  /** Constructs and returns (never throws) a typed instance. */
  fail<C extends ErrorKit.Code<R>>(code: C, ...args: ErrorKit.Args<R, C>): KitError<R, C>
  /** Throws a typed instance. */
  throwError<C extends ErrorKit.Code<R>>(code: C, ...args: ErrorKit.Args<R, C>): never
  /** An already-typed error as it stands; anything else wrapped under the fallback code with the original on `cause`. */
  asError<C extends ErrorKit.Code<R>>(error: unknown, code: C, ...args: ErrorKit.Args<R, C>): KitError<R>
  /** {@link ErrorKit.asError}, thrown rather than returned. */
  rethrowError<C extends ErrorKit.Code<R>>(error: unknown, code: C, ...args: ErrorKit.Args<R, C>): never
  /** True when `err` carries `code`, checked by property rather than `instanceof` — matches an instance built by a
   *  duplicated copy of this package too (hoisting, or a dependency installed separately from its consumer). */
  hasErrorCode<C extends ErrorKit.Code<R>>(err: unknown, code: C): err is Error & { readonly meta: ErrorKit.Meta<R, C> }
  /** Reads `err.meta` at the shape `code` declares. Safe once the caller has confirmed `err.code === code`. */
  metaOf<C extends ErrorKit.Code<R>>(err: KitError<R>, code: C): ErrorKit.Meta<R, C>
}

/**
 * Builds a fresh, registry-typed error class plus its construct/throw helpers. Each call declares its own
 * `class` — never a shared generic one — so two kits' instances never satisfy each other's `instanceof`, the
 * same way two hand-written classes wouldn't. `name` becomes both the class's runtime `.name` and the identity
 * a consumer sees in a stack trace.
 */
export function createErrorKit<const R extends ErrorKit.Registry, Name extends string>(
  name: Name,
  registry: R,
): ErrorKit<R, Name> {
  class KitErrorImpl<C extends ErrorKit.Code<R> = ErrorKit.Code<R>> extends Error {
    readonly code: C
    readonly status: number
    readonly statusCode: number
    readonly meta: Record<string, unknown>

    constructor(code: C, ...args: ErrorKit.Args<R, C>) {
      super(code)
      this.name = name
      this.code = code
      // The one cast this kit needs: `code` is `ErrorKit.Code<R>`, a subset of `keyof R`, so the lookup is
      // total in fact; `noUncheckedIndexedAccess` cannot see that through a generic `R`, only through a
      // concrete `const` object (which is what every real registry actually is at its own call site).
      this.status = registry[code] as number
      this.statusCode = this.status
      const [meta] = args
      this.meta = { ...meta }
    }

    toJSON(): { ok: false; error: { code: C; status: number } & Record<string, unknown> } {
      return { ok: false, error: { code: this.code, status: this.status, ...scrubMeta(this.meta) } }
    }
  }

  function fail<C extends ErrorKit.Code<R>>(code: C, ...args: ErrorKit.Args<R, C>): KitError<R, C> {
    return new KitErrorImpl<C>(code, ...args)
  }

  function throwError<C extends ErrorKit.Code<R>>(code: C, ...args: ErrorKit.Args<R, C>): never {
    throw fail(code, ...args)
  }

  function asError<C extends ErrorKit.Code<R>>(error: unknown, code: C, ...args: ErrorKit.Args<R, C>): KitError<R> {
    if (error instanceof KitErrorImpl) return error
    const typed = fail(code, ...args)
    typed.cause = error
    return typed
  }

  function rethrowError<C extends ErrorKit.Code<R>>(error: unknown, code: C, ...args: ErrorKit.Args<R, C>): never {
    throw asError(error, code, ...args)
  }

  function hasErrorCode<C extends ErrorKit.Code<R>>(
    err: unknown,
    code: C,
  ): err is Error & { readonly meta: ErrorKit.Meta<R, C> } {
    return err instanceof Error && 'code' in err && err.code === code
  }

  function metaOf<C extends ErrorKit.Code<R>>(err: KitError<R>, code: C): ErrorKit.Meta<R, C> {
    return err.meta as ErrorKit.Meta<R, C>
  }

  return { ErrorClass: KitErrorImpl, fail, throwError, asError, rethrowError, hasErrorCode, metaOf }
}
