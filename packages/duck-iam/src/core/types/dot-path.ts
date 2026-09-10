import type { IamPrimitives } from './primitives'

/** Dot-path type machinery: context-wide paths (`DotPaths`, `PathValue`, `DollarPaths`) and attribute-bag paths. */
export namespace DotPath {
  /**
   * String-literal union of every reachable path through `T`; arrays are leaves; index-signatures bail to `never`.
   *
   * @template T      - The object type to extract paths from.
   * @template Prefix - Internal accumulator for the current path prefix (do not set manually).
   *
   * @example
   * ```ts
   * type Ctx = { subject: { id: string; attributes: { status: string } } }
   * type Paths = DotPath.DotPaths<Ctx>
   * // = 'subject' | 'subject.id' | 'subject.attributes' | 'subject.attributes.status'
   * ```
   */
  export type DotPaths<T, Prefix extends string = ''> = string extends keyof T
    ? never
    : {
        [K in keyof T & string]: T[K] extends readonly any[]
          ? `${Prefix}${K}`
          : T[K] extends (...args: any[]) => any
            ? never
            : T[K] extends object
              ? `${Prefix}${K}` | DotPaths<T[K], `${Prefix}${K}.`>
              : `${Prefix}${K}`
      }[keyof T & string]

  /**
   * Value type at a context-wide dot path within `T`; `never` if the path does not exist.
   *
   * @template T - The object type to resolve within.
   * @template P - A dot-separated path string (e.g. `'subject.attributes.status'`).
   *
   * @example
   * ```ts
   * type Ctx = { subject: { attributes: { status: 'active' | 'banned' } } }
   * type V = DotPath.PathValue<Ctx, 'subject.attributes.status'>
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
   * Context-wide path: typed paths only when closed; accepts `string` when an open attribute bag is present.
   *
   * @template T - The context type to extract paths from.
   *
   * @example
   * ```ts
   * type ClosedCtx = { subject: { id: string } }
   * type Paths1 = DotPath.FlexibleDotPaths<ClosedCtx>     // = 'subject' | 'subject.id'
   *
   * type OpenCtx = { subject: { attributes: DotPath.IAnyAttributes } }
   * type Paths2 = DotPath.FlexibleDotPaths<OpenCtx>       // accepts any string too
   * ```
   */
  export type FlexibleDotPaths<T> = true extends HasOpenIndex<T> ? DotPaths<T> | (string & {}) : DotPaths<T>

  /**
   * `$`-prefixed context paths for cross-references; e.g. `'$subject.id'`.
   *
   * @template TContext - The full evaluation context type.
   *
   * @example
   * ```ts
   * type Ctx = { subject: { id: string; roles: string[] } }
   * type Refs = DotPath.DollarPaths<Ctx>
   * // = '$subject' | '$subject.id' | '$subject.roles'
   * ```
   */
  export type DollarPaths<TContext> = `$${DotPaths<TContext>}`

  /**
   * {@link DollarPaths} with autocomplete that still accepts any string.
   * NOTE: use it directly in a method signature; nested in a computed type the IDE drops the suggestions.
   *
   * @template TContext - The full evaluation context type.
   */
  export type FlexibleDollarPaths<TContext> = DollarPaths<TContext> | (string & {})

  // Condition value adapters

  /**
   * Builder input for an attribute value: string-capable values also accept {@link DollarPaths} references.
   *
   * @template TContext - The full evaluation context type.
   * @template TValue   - The attribute-compatible value type accepted by the builder.
   */
  export type ConditionValue<TContext, TValue extends IamPrimitives.AttributeValue> =
    | Exclude<TValue, string>
    | (Extract<TValue, string> extends never ? never : StringConditionValue<TContext, Extract<TValue, string>>)

  /**
   * Value at a context dot-path; falls back to {@link IamPrimitives.AttributeValue} on mismatch.
   *
   * @template TContext - The full evaluation context type.
   * @template P        - A dot-separated path string.
   */
  export type FieldValue<TContext, P extends string> =
    PathValue<TContext, P> extends IamPrimitives.AttributeValue
      ? ConditionValue<TContext, PathValue<TContext, P>>
      : ConditionValue<TContext, IamPrimitives.AttributeValue>

  // Attribute bag shape extractors

  /**
   * Subject attribute-bag from a context; `never` when missing.
   *
   * @template TContext - The full evaluation context type.
   */
  export type SubjectAttrShape<TContext> = TContext extends { subject: { attributes: infer A } } ? A : never

  /**
   * Resource attribute-bag from a context; `never` when missing.
   *
   * @template TContext - The full evaluation context type.
   */
  export type ResourceAttrShape<TContext> = TContext extends { resource: { attributes: infer A } } ? A : never

  /**
   * Environment bag from a context; `never` when missing.
   *
   * @template TContext - The full evaluation context type.
   */
  export type EnvAttrShape<TContext> = TContext extends { environment: infer E } ? E : never

  // Attribute-bag dot-path key extractors

  /**
   * Dot-paths into subject attribute bag (used by `When.attr()`).
   *
   * @template TContext - The full evaluation context type.
   *
   * @example
   * ```ts
   * type Ctx = { subject: { attributes: { profile: { tier: string } } } }
   * type Keys = DotPath.SubjectAttrs<Ctx>     // = 'profile' | 'profile.tier'
   * ```
   */
  export type SubjectAttrs<TContext> = AttrPaths<SubjectAttrShape<TContext>>

  /**
   * Dot-paths into resource attribute bag (used by `When.resourceAttr()`); see {@link ResolvedResourceAttrPaths}.
   *
   * @template TContext - The full evaluation context type.
   *
   * @example
   * ```ts
   * type Ctx = { resource: { attributes: { ownerId: string; status: 'draft' | 'live' } } }
   * type Keys = DotPath.ResourceAttrs<Ctx>    // = 'ownerId' | 'status'
   * ```
   */
  export type ResourceAttrs<TContext> = AttrPaths<ResourceAttrShape<TContext>>

  /**
   * Dot-paths into environment (used by `When.env()`).
   *
   * @template TContext - The full evaluation context type.
   */
  export type EnvAttrs<TContext> = AttrPaths<EnvAttrShape<TContext>>

  // Per-resource attribute narrowing

  /**
   * Per-resource attribute map declared via `resourceAttributes`; `never` when absent.
   *
   * @template TContext - The full evaluation context type.
   */
  export type ResourceAttrMap<TContext> = TContext extends { resourceAttributes: infer M extends Record<string, any> }
    ? M
    : never

  /**
   * Resource attribute shape narrowed to `TResource`; falls back to merged union for `'*'` / unknown.
   *
   * @template TContext  - The full evaluation context type.
   * @template TResource - The resource type string (or `'*'` for all resources).
   */
  export type ResolvedResourceAttrs<TContext, TResource extends string> =
    ResourceAttrMap<TContext> extends never
      ? ResourceAttrShape<TContext>
      : TResource extends keyof ResourceAttrMap<TContext>
        ? ResourceAttrMap<TContext>[TResource]
        : MergedResourceAttrs<ResourceAttrMap<TContext>>

  /**
   * Dot-paths into {@link ResolvedResourceAttrs}; typed `key` for `When.resourceAttr()`.
   *
   * @template TContext  - The full evaluation context type.
   * @template TResource - The resource type string (or `'*'` for all resources).
   */
  export type ResolvedResourceAttrPaths<TContext, TResource extends string> = AttrPaths<
    ResolvedResourceAttrs<TContext, TResource>
  >

  // Attribute-bag value resolution

  /**
   * Value at a dot-path inside an attribute-bag; `never` on invalid path.
   *
   * @template T - The attribute-bag object type.
   * @template P - The dot-separated path string.
   */
  export type AttrValueAt<T, P extends string> = P extends `${infer K}.${infer Rest}`
    ? K extends keyof T
      ? AttrValueAt<T[K], Rest>
      : never
    : P extends keyof T
      ? T[P]
      : never

  /**
   * Constrained value lookup at `P` in attribute bag `T`; falls back to {@link IamPrimitives.AttributeValue}.
   *
   * @template T - The attribute-bag object type.
   * @template P - The dot-separated path string.
   *
   * @example
   * ```ts
   * type Bag = { profile: { tier: 'gold' | 'silver' } }
   * type V = DotPath.AttrValue<Bag, 'profile.tier'>     // = 'gold' | 'silver'
   * ```
   */
  export type AttrValue<T, P extends string> =
    T extends Record<string, unknown>
      ? AttrValueAt<T, P> extends IamPrimitives.AttributeValue
        ? Exclude<AttrValueAt<T, P>, undefined>
        : IamPrimitives.AttributeValue
      : IamPrimitives.AttributeValue

  // Default attribute bag + context shapes

  /** Marker for open-ended attribute bags; index signature returns {@link IamPrimitives.AttributeValue}. */
  export interface IAnyAttributes {
    [key: string]: IamPrimitives.AttributeValue
  }

  /**
   * Default evaluation context shape with open attribute bags.
   *
   * @example
   * ```ts
   * const ctx: DotPath.IDefaultContext = {
   *   action: 'read',
   *   subject: { id: 'u-1', roles: ['editor'], attributes: { tier: 'gold' } },
   *   resource: { type: 'post', id: 'p-42', attributes: { ownerId: 'u-1' } },
   *   environment: { hour: 14 },
   *   scope: 'org-acme',
   * }
   * ```
   */
  export interface IDefaultContext {
    /** The action being performed (e.g. `'read'`, `'update'`). */
    action: string
    /** The authenticated subject making the request. */
    subject: {
      /** Unique subject identifier. */
      id: string
      /** Flat list of effective role IDs. */
      roles: string[]
      /** Subject attribute bag (e.g. `{ department: 'engineering', status: 'active' }`). */
      attributes: IAnyAttributes
    }
    /** The target resource being accessed. */
    resource: {
      /** Resource type string (e.g. `'post'`, `'comment'`). */
      type: string
      /** Optional resource instance ID. */
      id?: string
      /** Resource attribute bag (e.g. `{ ownerId: 'user-1', status: 'published' }`). */
      attributes: IAnyAttributes
    }
    /** Environment attribute bag (e.g. `{ hour: 14, maintenanceMode: false }`). */
    environment: IAnyAttributes
    /** Authorization scope for multi-tenant applications (e.g. `'org-acme'`). */
    scope: string
  }

  // Internal helpers

  /** Dot-path union into attribute bag `T`; widens to `string` for open bags. */
  type AttrPaths<T> =
    T extends Record<string, unknown>
      ? string extends keyof T
        ? string
        : {
            [K in keyof T & string]: IsPlainObject<T[K]> extends true ? K | `${K}.${AttrPaths<T[K]>}` : K
          }[keyof T & string]
      : never

  /** Whether `T` is a plain object worth recursing into; arrays, functions, `Date`, `Map` and `Set` are leaves. */
  type IsPlainObject<T> = T extends object
    ? T extends readonly unknown[]
      ? false
      : T extends (...args: unknown[]) => unknown
        ? false
        : T extends Date
          ? false
          : T extends Map<unknown, unknown>
            ? false
            : T extends Set<unknown>
              ? false
              : true
    : false

  /** Whether any branch of `T` has a string index signature; decides {@link FlexibleDotPaths}'s `string` fallback. */
  type HasOpenIndex<T> = string extends keyof T
    ? true
    : true extends {
          [K in keyof T & string]: T[K] extends object ? HasOpenIndex<T[K]> : false
        }[keyof T & string]
      ? true
      : false

  /** Adds `$`-paths to a string input: `string` becomes `$`-paths only, a literal union keeps its literals too. */
  type StringConditionValue<TContext, TValue extends string> = string extends TValue
    ? DollarPaths<TContext>
    : TValue | DollarPaths<TContext>

  /** Every attribute key declared across the per-resource map. */
  type AllResourceKeys<M> = M[keyof M] extends infer U
    ? U extends Record<string, any>
      ? keyof U & string
      : never
    : never

  /** Union of `K`'s value type across every resource that declares it. */
  type ResourceKeyValue<M, K extends string> = { [R in keyof M]: K extends keyof M[R] ? M[R][K] : never }[keyof M]

  /** All per-resource attributes merged into one shape, for the `'*'` case of {@link ResolvedResourceAttrs}. */
  type MergedResourceAttrs<M> = { [K in AllResourceKeys<M>]: ResourceKeyValue<M, K> }
}
