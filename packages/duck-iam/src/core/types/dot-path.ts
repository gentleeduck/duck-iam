import type { AttributeValue } from './primitives'

/**
 * Recursively generates a union of all valid dot-separated paths through an object type.
 *
 * Given a nested object type `T`, produces string literal types for every
 * reachable property path. For example, `{ a: { b: string } }` yields
 * `'a' | 'a.b'`.
 *
 * Bails out to `string` when `T` has a string index signature (i.e. `Record<string, ...>`)
 * to prevent infinite recursion.
 *
 * @template T      - The object type to extract paths from
 * @template Prefix - Internal accumulator for the current path prefix (do not set manually)
 *
 * @example
 * ```ts
 * type Ctx = { subject: { id: string; attributes: { status: string } } }
 * type Paths = DotPaths<Ctx>
 * // = 'subject' | 'subject.id' | 'subject.attributes' | 'subject.attributes.status'
 * ```
 */
export type DotPaths<T, Prefix extends string = ''> = string extends keyof T
  ? string // bail out for types with string index signatures
  : {
      [K in keyof T & string]: T[K] extends object
        ? `${Prefix}${K}` | DotPaths<T[K], `${Prefix}${K}.`>
        : `${Prefix}${K}`
    }[keyof T & string]

/**
 * Resolves the value type at a dot-separated path within an object type.
 *
 * Walks through `T` following the dot-separated segments in `P` and returns
 * the type found at the end of the path. Returns `never` if the path is invalid.
 *
 * @template T - The object type to resolve within
 * @template P - A dot-separated path string (e.g. `'subject.attributes.status'`)
 *
 * @example
 * ```ts
 * type Ctx = { subject: { attributes: { status: 'active' | 'banned' } } }
 * type V = PathValue<Ctx, 'subject.attributes.status'>
 * // = 'active' | 'banned'
 * ```
 */
export type PathValue<T, P extends string> = P extends `${infer K}.${infer Rest}`
  ? K extends keyof T
    ? PathValue<T[K], Rest>
    : never
  : P extends keyof T
    ? T[P]
    : never

/**
 * Resolves the value type at a dot-path, falling back to {@link AttributeValue}
 * if the resolved type is not a valid attribute value.
 *
 * Used by the `When.check()` method to constrain the `value` parameter to the
 * type found at the given path in the context.
 *
 * @template TContext - The full evaluation context type
 * @template P       - A dot-separated path string
 */
export type FieldValue<TContext, P extends string> =
  PathValue<TContext, P> extends AttributeValue ? PathValue<TContext, P> : AttributeValue

/**
 * Extracts the subject's attribute type from a context.
 *
 * Given a context with `{ subject: { attributes: A } }`, returns `A`.
 * Returns `never` if the context does not have that shape.
 *
 * Used by `When.attr()` to constrain attribute keys and values.
 */
export type SubjectAttrs<TContext> = TContext extends { subject: { attributes: infer A } } ? A : never

/**
 * Extracts the resource's attribute type from a context.
 *
 * Given a context with `{ resource: { attributes: A } }`, returns `A`.
 * Returns `never` if the context does not have that shape.
 *
 * Used as a fallback by `When.resourceAttr()` when no `resourceAttributes` map is declared.
 */
export type ResourceAttrs<TContext> = TContext extends { resource: { attributes: infer A } } ? A : never

/**
 * Extracts the environment type from a context.
 *
 * Given a context with `{ environment: E }`, returns `E`.
 * Returns `never` if the context does not have that shape.
 *
 * Used by `When.env()` to constrain environment attribute keys and values.
 */
export type EnvAttrs<TContext> = TContext extends { environment: infer E } ? E : never

/**
 * Extracts the per-resource attribute map from the context, if declared.
 *
 * When the context includes a `resourceAttributes` field mapping resource type
 * names to their attribute types, this type extracts that map. Returns `never`
 * if the context does not declare `resourceAttributes`.
 *
 * @example
 * ```ts
 * interface AppContext {
 *   resourceAttributes: {
 *     post: { ownerId: string; status: 'draft' | 'published' }
 *     comment: { ownerId: string; body: string }
 *   }
 * }
 * type Map = ResourceAttrMap<AppContext>
 * // = { post: { ownerId: string; status: ... }; comment: { ownerId: string; body: string } }
 * ```
 */
export type ResourceAttrMap<TContext> = TContext extends { resourceAttributes: infer M extends Record<string, any> }
  ? M
  : never

/**
 * Collects all attribute key names from every resource in the attribute map.
 *
 * Internal helper for {@link MergedResourceAttrs}. Distributes over the map's
 * values and unions all their keys.
 */
type AllResourceKeys<M> = M[keyof M] extends infer U ? (U extends Record<string, any> ? keyof U & string : never) : never

/**
 * For a given attribute key, collects the value type from whichever resources declare it.
 *
 * Internal helper for {@link MergedResourceAttrs}. If key `K` appears on
 * multiple resources, the resulting type is the union of all their value types.
 */
type ResourceKeyValue<M, K extends string> =
  { [R in keyof M]: K extends keyof M[R] ? M[R][K] : never }[keyof M]

/**
 * Merges all per-resource attribute types into a single object with all keys.
 *
 * Internal helper for the `'*'` wildcard case in {@link ResolvedResourceAttrs}.
 * Each key maps to the union of its value types across all resources that declare it.
 *
 * @example
 * ```ts
 * // Given resourceAttributes: { post: { title: string }, comment: { body: string } }
 * // MergedResourceAttrs = { title: string; body: string }
 * ```
 */
type MergedResourceAttrs<M> = { [K in AllResourceKeys<M>]: ResourceKeyValue<M, K> }

/**
 * Resolves resource attributes for a specific resource type, a union of types, or the `'*'` wildcard.
 *
 * This is the core type that powers per-resource attribute narrowing in `When.resourceAttr()`.
 *
 * Resolution strategy:
 * 1. If the context declares `resourceAttributes`, attributes are looked up per resource.
 *    - A specific resource like `'post'` returns only post's attribute type.
 *    - `'*'` or unknown keys return a merged type with all keys from all resources.
 * 2. If no `resourceAttributes` map exists, falls back to `ResourceAttrs<TContext>`.
 *
 * @template TContext   - The full evaluation context type
 * @template TResource  - The resource type string (or `'*'` for all resources)
 *
 * @example
 * ```ts
 * // With resourceAttributes declared:
 * type PostAttrs = ResolvedResourceAttrs<AppContext, 'post'>
 * // = { ownerId: string; status: 'draft' | 'published'; title: string }
 *
 * type AllAttrs = ResolvedResourceAttrs<AppContext, '*'>
 * // = { ownerId: string; status: ...; title: string; body: string; email: string; name: string }
 * ```
 */
export type ResolvedResourceAttrs<TContext, TResource extends string> =
  ResourceAttrMap<TContext> extends never
    ? ResourceAttrs<TContext>
    : TResource extends keyof ResourceAttrMap<TContext>
      ? ResourceAttrMap<TContext>[TResource]
      : MergedResourceAttrs<ResourceAttrMap<TContext>>

/**
 * Resolves the value type for an attribute key within an attribute bag.
 *
 * If `K` is a key of `TAttrs` and its value extends {@link AttributeValue}, returns
 * the exact type. Otherwise falls back to `AttributeValue`.
 *
 * Used by `When.attr()`, `When.resourceAttr()`, and `When.env()` to constrain
 * the `value` parameter based on the attribute key.
 *
 * @template TAttrs - The attribute bag type
 * @template K      - The attribute key string
 */
export type AttrValue<TAttrs, K extends string> =
  TAttrs extends Record<string, unknown>
    ? K extends keyof TAttrs
      ? TAttrs[K] extends AttributeValue
        ? TAttrs[K]
        : AttributeValue
      : AttributeValue
    : AttributeValue

/**
 * Marker interface for open-ended attribute bags.
 *
 * Using an interface with a string index (instead of `Record<string, ...>`)
 * gives `keyof AnyAttributes = string` while preventing {@link DotPaths}
 * from recursing into every possible string key. The index signature returns
 * `AttributeValue` so that `.attr()` / `.env()` calls infer the correct
 * value type.
 *
 * Used as the default attribute type in {@link DefaultContext} when no
 * custom context is provided.
 */
export interface AnyAttributes {
  [key: string]: AttributeValue
}

/**
 * The default evaluation context used when no custom context type is provided.
 *
 * Provides the minimal shape that the engine expects. All attribute bags use
 * {@link AnyAttributes}, which accepts any string key without compile-time
 * narrowing. For full type-safe intellisense, extend `DefaultContext` with
 * your application's specific attribute types and pass it to
 * `createAccessConfig({ context: {} as unknown as YourContext })`.
 */
export interface DefaultContext {
  /** The action being performed (e.g. `'read'`, `'update'`). */
  action: string
  /** The authenticated subject making the request. */
  subject: {
    /** Unique subject identifier. */
    id: string
    /** Flat list of effective role IDs. */
    roles: string[]
    /** Subject attribute bag (e.g. `{ department: 'engineering', status: 'active' }`). */
    attributes: AnyAttributes
  }
  /** The target resource being accessed. */
  resource: {
    /** Resource type string (e.g. `'post'`, `'comment'`). */
    type: string
    /** Optional resource instance ID. */
    id?: string
    /** Resource attribute bag (e.g. `{ ownerId: 'user-1', status: 'published' }`). */
    attributes: AnyAttributes
  }
  /** Environment attribute bag (e.g. `{ hour: 14, maintenanceMode: false }`). */
  environment: AnyAttributes
  /** Authorization scope for multi-tenant applications (e.g. `'org-acme'`). */
  scope: string
}
