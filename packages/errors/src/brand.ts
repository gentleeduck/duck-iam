declare const CARRIES: unique symbol
declare const FAULT: unique symbol

/** A status that also says what its code hands back. The brand is required rather than optional: an optional
 *  one is satisfied structurally by any plain `number`, and every code would then look like it carried something. */
export type Carries<M extends object> = number & { readonly [CARRIES]: M }

/** A status whose code a store/adapter can answer with, rather than one only flow or validation logic raises. */
export type Fault = number & { readonly [FAULT]: true }

/** What a status says its code hands back. A plain status says nothing, which is a meta with no keys. */
export type MetaOf<S> = S extends Carries<infer M> ? M : Record<never, never>

/** A code's status and what it hands back with it, in one declaration. It is the status and nothing else at
 *  runtime, so a registry built from it stays a plain `Record<string, number>`. */
export function detail<M extends object>(status: number): Carries<M> {
  return status as Carries<M>
}

/** The same declaration for a code a store/adapter can answer with itself. */
export function fault(status: number): Fault
export function fault<M extends object>(status: number): Carries<M> & Fault
export function fault<M extends object>(status: number): Carries<M> & Fault {
  return status as Carries<M> & Fault
}
