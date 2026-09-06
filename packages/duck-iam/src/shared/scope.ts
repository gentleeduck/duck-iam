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
 * @param adapter - Adapter name for the error message, e.g. `'memory'`.
 * @param scope   - The scope argument as the caller passed it.
 * @throws When `scope` is the empty string.
 */
export function iamAssertAssignableScope(adapter: string, scope: unknown): void {
  if (scope === '') {
    throw new Error(`[@gentleduck/iam:${adapter}] scope must not be an empty string; omit it for a global assignment`)
  }
}
