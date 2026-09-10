/**
 * Adapter-boundary guard for the scope argument of `assignRole` / `revokeRole`.
 *
 * `''` was accepted by five of the six adapters and produced five different
 * outcomes: memory, prisma and drizzle stored a grant scoped to a value nothing
 * can match; file stored one that became unreadable at the next restart; http
 * accepted the write and then dropped the row on every read, because its read
 * parser requires `scope.length > 0`; only redis refused it. An operator
 * submitting an empty form field therefore got an error, a scoped grant, a
 * vanishing grant, or a grant with a shelf life, depending on the backend.
 *
 * Redis had the right answer for the right reason - its encoding spells "no
 * scope" as the empty string, so storing a literal one would decode as a
 * *global* grant, strictly more power than was asked for - but the decision
 * belonged here rather than in one adapter. `undefined` is how the contract
 * spells "global"; `''` is not a second spelling of it, which is the same rule
 * `validateRole` applies to a role's declared scope and `createAdmin`'s
 * `assertTriple` applies to the same argument one layer up.
 *
 * `'*'` is refused for the same reason, but only when a grant is being
 * *created*. This package spells "every scope" as `'*'` on the scope a role or
 * a permission declares - `IPermission.scope` is typed `TScope | '*'`, and
 * `matchesScope` / `scopeCovers` / `effectiveScopeOf` all read it as global -
 * so writing `assignRole(u, r, '*')` beside a role declared `scope: '*'` is the
 * obvious move. It does not mean that. A scoped *assignment* is matched by
 * `enrichSubjectWithScopedRoles`, which compares the stored scope literally
 * (exact match under `flat`, an ancestor prefix under `hierarchical`), and no
 * ordinary request scope is the string `'*'`. The row lands, `assignRole`
 * resolves, `admin.assignRoles` reports `ok: true, applied: 1`, and the grant is
 * invisible to every request the operator meant it for - `getEffectiveRoles`
 * returns `[]` for every real scope and for the unscoped request.
 *
 * It is not literally dead. A request that passes the string `'*'` as its own
 * scope matches the row, because `enrichSubjectWithScopedRoles` compares plain
 * strings at both ends - the same coincidence
 * `e2e-scope-inheritance.e2e.test.ts` pins one test earlier, where a caller
 * passing `'*'` as the request scope is handed a role held at no real scope.
 * That is a second instance of the confusion, not a use for the grant: the
 * operator who writes `'*'` means "every scope", and what they get is "the one
 * tenant literally named `*`". Measured on the memory adapter and on Postgres,
 * not inferred.
 *
 * That is the same silent success `iamAssertNoAssignOptions` refuses for a
 * dropped `expiresAt` and `iamAssertRoleExists` refuses for a role id nothing
 * is stored under, and `assignRole`'s own contract already says a grant
 * `resolveSubject` will drop must throw rather than read back as success.
 * `undefined` is how the contract spells "global"; `'*'` is not a second
 * spelling of it any more than `''` is.
 *
 * Lookups are exempt. `revokeRole` and the redis member encoder address a row
 * that already exists, and an operator holding `'*'` rows written before this
 * guard has to be able to delete them.
 *
 * @param adapter - Adapter name for the error message, e.g. `'memory'`.
 * @param scope   - The scope argument as the caller passed it.
 * @param intent  - `'grant'` (default) when a new assignment is being written;
 *                  `'lookup'` when addressing a row that may already exist.
 * @throws When `scope` is the empty string, or `'*'` on a `'grant'`.
 */
export function iamAssertAssignableScope(adapter: string, scope: unknown, intent: 'grant' | 'lookup' = 'grant'): void {
  if (scope === '') {
    throw new Error(`[@gentleduck/iam:${adapter}] scope must not be an empty string; omit it for a global assignment`)
  }
  if (scope === '*' && intent === 'grant') {
    throw new Error(
      `[@gentleduck/iam:${adapter}] scope must not be "*"; a scoped assignment is matched literally, so this grant ` +
        'would be stored and answer only a request whose own scope is the string "*". Omit the scope for a global ' +
        'assignment.',
    )
  }
}
