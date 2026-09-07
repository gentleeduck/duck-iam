---
'@gentleduck/iam': major
---

Close five ways the policy builder could emit something other than what the author wrote.

**A condition callback that returns a group is no longer discarded.**
`RuleBuilder.when()`, `RuleBuilder.whenAny()`, `RoleBuilder.grantWhen()` and
`PolicyBuilder.rule()` used the builder they passed in and ignored the callback's
return value. The reusable-group idiom returns one, so
`.when(() => sharedOwnerOrAdmin())` authored to `{ all: [] }` - and `all` of
nothing is true, making the rule fire unconditionally: an allow rule granted to
everybody, a deny rule denied everybody. The returned builder is now honoured. A
callback that both chains onto its argument *and* returns a different builder
throws, because there is no answer to which group was meant.

**Built condition groups no longer alias the builder's array.** `buildAll()`,
`buildAny()` and `buildNone()` snapshot. Reusing a `When` after building used to
reach back into rules that were already finished.

**`When.roles()`, `When.scopes()` and `When.resourceType()` refuse zero
arguments.** They emitted a membership test against an empty list, which can
never match - on a deny rule that removes the guard. Pass at least one value, or
`.in(field, list)` when the list is computed and may legitimately be empty.

**The builders emit absent optional keys, not keys holding `undefined`.**
`description`, `targets` and `version` on policies, `description`/`metadata` on
rules, `description`/`inherits`/`scope`/`metadata` on roles. A key holding
`undefined` survived in the memory, file and http stores and disappeared through
every JSON- or `jsonb`-backed one, so the same authored policy read back unequal
depending on where it had been. `version` in particular is now left out when
unset: the `version: 1` default belongs to the store, and a builder that
pre-empted it made "never set" indistinguishable from "set to 1".

**Breaking:** `when()`'s type parameters were reordered to
`when<TAction, TResource, TRole, TScope, TContext, TActiveResource>` so they name
the slots they fill. They previously ran `TAction, TResource, TScope, TRole`,
which let a scope be passed to `.role()` and a role to `.scope()`. Only callers
who pass all four explicitly are affected; inference is unchanged.
