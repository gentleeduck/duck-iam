---
'@gentleduck/iam': patch
---

Fix `resolveSubject` mistagging a role reached through cross-scope inheritance with the source assignment's scope instead of the role's own declared scope. A role assigned at one scope that `.inherits()` a role defined at another scope (e.g. a company-level role inheriting a marketplace-level role) had the inherited role silently invisible at the scope it actually belongs to - `enrichSubjectWithScopedRoles` filtered it out because it carried the wrong scope tag, so a policy check at the inherited-into scope only ever saw whatever lower-privilege role was directly assigned there, if any.

Each role visited during the inheritance walk is now tagged with its own `IRole.scope`, falling back to the assignment row's scope only when the role declares none of its own - a no-op for roles with no cross-scope inheritance.
