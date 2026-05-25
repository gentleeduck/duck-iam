/**
 * Default impersonation policy — admin-only. Apps wanting to grant the
 * 'impersonate' action to other roles override by registering their own policy.
 *
 * DESIGN §38 — refuses self-impersonation (defeats audit trail) and refuses
 * blanket allow. iam evaluation must produce `allowed: true` before
 * `auth.flows.impersonate()` will issue the actingAs session.
 *
 * Returns the policy as `unknown` for now — iam's full `AccessControl.IPolicy`
 * import lands when the bridge types are fully wired (v0.2.0).
 */
export const impersonationPolicy = {
  id: 'auth:impersonate:admin-only',
  name: 'Impersonate — admin only',
  algorithm: 'deny-overrides' as const,
  rules: [
    {
      id: 'allow-admin',
      effect: 'allow' as const,
      priority: 100,
      actions: ['impersonate'],
      resources: ['auth:identity'],
      conditions: {
        all: [
          {
            field: 'subject.attributes.roles',
            operator: 'contains',
            value: 'admin',
          },
        ],
      },
    },
  ],
}
