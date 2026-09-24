import type { Carries, Fault, MetaOf } from './brand'
import { scrubMeta } from './scrub'

export namespace ErrorKit {
  export type Registry = Record<string, number>

  export type Code<R extends Registry> = keyof R & string

  export type Meta<R extends Registry, C extends Code<R>> = MetaOf<R[C]>

  /** True when T has at least one non-optional key. */
  export type HasRequired<T> = { [K in keyof T]-?: undefined extends T[K] ? never : K }[keyof T]

  export type Faults<R extends Registry> = { [C in Code<R>]: R[C] extends Fault ? C : never }[Code<R>]

  /** A code that needs nothing beyond itself. */
  export type Bare<R extends Registry> = {
    [C in Code<R>]: [HasRequired<Meta<R, C>>] extends [never] ? C : never
  }[Code<R>]

  /** No args for a bare code, else optional/required per Meta's required keys — gated on the value's own Carries brand, not on Meta, since a bare code's Meta resolves to `{}` which anything would satisfy. */
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

export interface ErrorKit<R extends ErrorKit.Registry> {
  /** For instanceof checks or subclassing — see createErrorKit for why it's never shared across kits. */
  readonly ErrorClass: new <C extends ErrorKit.Code<R> = ErrorKit.Code<R>>(
    code: C,
    ...args: ErrorKit.Args<R, C>
  ) => KitError<R, C>
  /** Constructs and returns (never throws) a typed instance. */
  fail<C extends ErrorKit.Code<R>>(code: C, ...args: ErrorKit.Args<R, C>): KitError<R, C>
  throwError<C extends ErrorKit.Code<R>>(code: C, ...args: ErrorKit.Args<R, C>): never
  /** An already-typed error as it stands; anything else wrapped under the fallback code with the original on `cause`. */
  asError<C extends ErrorKit.Code<R>>(error: unknown, code: C, ...args: ErrorKit.Args<R, C>): KitError<R>
  /** {@link ErrorKit.asError}, thrown rather than returned. */
  rethrowError<C extends ErrorKit.Code<R>>(error: unknown, code: C, ...args: ErrorKit.Args<R, C>): never
  /** Checked by property, not instanceof, so a duplicated copy of this package still matches; meta is checked too, since code alone could narrow to a meta that isn't actually there. */
  hasErrorCode<C extends ErrorKit.Code<R>>(err: unknown, code: C): err is Error & { readonly meta: ErrorKit.Meta<R, C> }
  /** Reads `err.meta` at the shape `code` declares. Safe once the caller has confirmed `err.code === code`. */
  metaOf<C extends ErrorKit.Code<R>>(err: KitError<R>, code: C): ErrorKit.Meta<R, C>
}

/** Each call declares its own class (never shared), so two kits' instances never satisfy each other's instanceof; name becomes both the runtime `.name` and the stack-trace identity. */
export function createErrorKit<const R extends ErrorKit.Registry, Name extends string>(
  name: Name,
  registry: R,
): ErrorKit<R> {
  class KitErrorImpl<C extends ErrorKit.Code<R> = ErrorKit.Code<R>> extends Error {
    readonly code: C
    readonly status: number
    readonly statusCode: number
    readonly meta: Record<string, unknown>

    constructor(code: C, ...args: ErrorKit.Args<R, C>) {
      super(code)
      this.name = name
      this.code = code
      // Total in fact (code is keyof R), but noUncheckedIndexedAccess can't see that through a generic R.
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
    return err instanceof Error && 'code' in err && err.code === code && 'meta' in err
  }

  // biome-ignore lint/correctness/noUnusedFunctionParameters: code pins C so the call site infers Meta<R, C>
  function metaOf<C extends ErrorKit.Code<R>>(err: KitError<R>, code: C): ErrorKit.Meta<R, C> {
    return err.meta as ErrorKit.Meta<R, C>
  }

  return { ErrorClass: KitErrorImpl, fail, throwError, asError, rethrowError, hasErrorCode, metaOf }
}
