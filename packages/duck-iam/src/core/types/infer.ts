/**
 * Extracts the union of action strings from a config input.
 *
 * @example
 * ```ts
 * type Actions = InferAction<typeof configInput>
 * // = 'create' | 'read' | 'update' | 'delete'
 * ```
 */
export type InferAction<S extends { actions: readonly string[] }> = S['actions'][number]

/**
 * Extracts the union of resource strings from a config input.
 *
 * @example
 * ```ts
 * type Resources = InferResource<typeof configInput>
 * // = 'post' | 'comment' | 'user'
 * ```
 */
export type InferResource<S extends { resources: readonly string[] }> = S['resources'][number]

/**
 * Extracts the union of scope strings from a config input.
 *
 * @example
 * ```ts
 * type Scopes = InferScope<typeof configInput>
 * // = 'org-acme' | 'org-globex'
 * ```
 */
export type InferScope<S extends { scopes: readonly string[] }> = S['scopes'][number]

/**
 * Extracts the union of role strings from a config input.
 *
 * @example
 * ```ts
 * type Roles = InferRole<typeof configInput>
 * // = 'viewer' | 'editor' | 'admin'
 * ```
 */
export type InferRole<S extends { roles: readonly string[] }> = S['roles'][number]
