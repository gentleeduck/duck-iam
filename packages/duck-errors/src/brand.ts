/** Required, not optional — optional is satisfied by any plain number; plain key, not unique symbol, to avoid TS4023 in a consumer's own build. */
export type Carries<M extends object> = number & { readonly __carries: M }

/** A status whose code a store/adapter can answer with, rather than one only flow or validation logic raises. */
export type Fault = number & { readonly __fault: true }

/** What a status says its code hands back. A plain status says nothing, which is a meta with no keys. */
export type MetaOf<S> = S extends Carries<infer M> ? M : Record<never, never>

/** M can't be inferred (no parameter uses it), so it defaults to never, not object — object would silently accept any meta shape. */
export function detail<M extends object = never>(status: number): Carries<M> {
  return status as Carries<M>
}

export function fault(status: number): Fault
export function fault<M extends object>(status: number): Carries<M> & Fault
export function fault<M extends object>(status: number): Carries<M> & Fault {
  return status as Carries<M> & Fault
}
