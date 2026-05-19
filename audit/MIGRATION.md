# duck-iam migration notes

Tracks data-shape changes that affect persisted stores. Operators upgrading
across one of these versions need to plan for the migration described here.

## SEC-019 — Redis assignment separator (P0)

**Affected releases:** every version prior to the `security/p3-deny-flip-redos-fix`
fix.

**What changed.** The `RedisAdapter` stores role assignments as set members
encoded as `${roleId}<SEP>${scope}`. The intended separator was a NUL byte
(`0x00`), but the code shipped a literal space (`0x20`) while the surrounding
comment claimed NUL. The result: any `roleId` or `scope` containing whitespace
silently collided on decode, e.g. `assignRole('user', 'admin user')` round-
tripped as `{ role: 'admin', scope: 'user ' }` — a privilege-drift bug.

**The fix.** The encoder now uses a real `'\0'` between role and scope, and
the runtime guard that rejects `\0` in role/scope inputs is now checking the
actual separator.

**Migration path.** The adapter performs a transparent, idempotent migration
on first read. Any set member that has no `\0` byte and exactly one space is
treated as a legacy encoding: the adapter decodes it, re-encodes it with the
new separator, `SADD`s the new form, and `SREM`s the legacy form. Errors
during migration are surfaced through `onPolicyError` and the legacy entry is
left in place to be retried.

For operators who want to force the migration ahead of traffic, a one-shot
read of `getSubjectRoles` / `getSubjectScopedRoles` for every subject ID is
sufficient. Run with `keyPrefix` set to whatever your deployment uses:

```ts
const adapter = new RedisAdapter({ client, keyPrefix: 'iam:' })
// Walk every assignments:* key (SCAN MATCH) and call getSubjectRoles on the
// extracted subjectId. Idempotent - safe to re-run.
```

**Edge cases.** A legacy entry whose roleId or scope itself contained a NUL
(impossible under the prior encoder, which would have collided differently)
will not be detected as legacy. A legacy entry whose roleId or scope
contained multiple spaces is also not migrated automatically (operators must
re-issue the `assignRole` call explicitly); the adapter falls through to
treating such a member as a single role string with no scope, matching the
prior buggy behaviour rather than guessing the boundary.

## SEC-003 — File adapter path constraints (P0)

**Affected releases:** every version prior to the `security/p3-deny-flip-redos-fix`
fix.

**What changed.** `FileAdapter` previously passed `init.path` verbatim to
`readFile` / `writeFile` / `mkdir({ recursive: true })`. If a caller derived
the path from untrusted input the adapter became an arbitrary read/write
primitive. The fix:

- `init.path` is resolved with `path.resolve()` at construction.
- A non-absolute or `..`-containing path is rejected at construction.
- An optional `init.rootDir` containment check rejects paths that escape the
  configured root directory (after `realpath` resolution on Node, when the
  injected `IFS` exposes one).
- `mkdir({ recursive: true })` is replaced with a single-level `mkdir` of
  the immediate parent directory, so a typo in `init.path` cannot
  accidentally build a deep tree.

**Migration path.** Existing callers passing an absolute, normalised path
under their data directory keep working with no changes. Callers that:

1. Pass a relative path — now throw at adapter construction. Resolve the path
   ahead of time, e.g. `path.resolve(process.cwd(), 'store.json')`.
2. Pass a path containing `..` segments — now throw at adapter construction.
   Normalise the path, or pass the resolved-and-normalised absolute form.
3. Want defence-in-depth — pass `init.rootDir` to bound the legal write area.
   When omitted the adapter logs a one-shot `console.warn` at construction so
   existing callers do not break silently.

The `IFS` interface now optionally exposes a `realpath(path)` method. When
present (real `node:fs/promises` provides it) the adapter uses it to follow
symlinks during the `rootDir` containment check; when absent (in-memory test
fakes) the symlink check is skipped.

## SEC-007 — Resource pattern hierarchy is no longer implicit (P1)

**Affected releases:** every version prior to the `security/p6-p1-cleanup` fix.

**What changed.** `matchesResource` and `matchesResourceHierarchical`
(`src/core/resolve/resolve.ts`) previously treated a bare-literal pattern as
an implicit parent over every sub-resource. So a rule scoped to
`resources: ['org']` silently applied to `org:project`, `org:project:doc`,
`org.users.settings`, and so on. A typo in a `resources` entry — or a
copy-paste of a parent name intended to be a literal — became an org-wide
grant.

The new semantics require the recursive intent to be **explicit**:

| Pattern             | Matches                                  | No longer matches               |
| ------------------- | ---------------------------------------- | ------------------------------- |
| `org`               | `org`                                    | `org:project`, `org:secrets:x`  |
| `org:*`             | `org`, `org:project`, `org:project:doc`  | `organisation`                  |
| `org:billing:*`     | `org:billing:invoice`                    | `org:secrets:invoice`           |
| `dashboard`         | `dashboard`                              | `dashboard.users`               |
| `dashboard.*`       | `dashboard.users`, `dashboard.users.x`   | `dashboard`                     |

The fast-path index in `src/core/evaluate/evaluate.ts` no longer walks parent
prefixes for literal-keyed buckets, so this change applies to both the
trace path (`evaluatePolicy`) and the production hot path (`evaluatePolicyFast`).

**Migration path.** Audit every `resources:` array (rules + policy targets)
for entries that depend on the old implicit hierarchy:

```diff
- resources: ['org']            // used to grant on org + every sub-resource
+ resources: ['org', 'org:*']   // explicit literal + recursive children
```

If a rule was always intended to be recursive, replace the bare name with the
`:*` / `.*` form. If a rule was always intended to be a literal-only match
(probably the common case), no change is required — but verify against your
test suite, because the behaviour is now stricter than before.

`matchesAction` is unchanged: it never had the implicit hierarchical arm.
