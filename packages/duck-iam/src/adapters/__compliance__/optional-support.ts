/**
 * Optional adapter methods; `OPTIONAL_SUPPORT` records which shipped adapter implements each.
 * NOTE: declared, not probed; `optional-method-matrix.test.ts` checks the table, so a lost method fails, not skips.
 */
export const OPTIONAL_METHODS = [
  'getSubjectScopedRoles',
  'updateAssignmentScope',
  'getSubjectGrantBoundary',
  'assignRoleMany',
  'revokeRoleMany',
  'withClient',
] as const

export type OptionalMethod = (typeof OPTIONAL_METHODS)[number]

/** `true` where the adapter implements the method itself. */
export type OptionalSupport = Readonly<Record<OptionalMethod, boolean>>

/**
 * Support matrix for the six shipped adapters; third-party adapters pass their own literal.
 * Gates adapter-level clauses only: `runEngineCapabilityCompliance` pins the engine-fallback methods on all six.
 */
export const OPTIONAL_SUPPORT = {
  // Only drizzle stores a validity window, so only it answers a grant boundary; it alone has batch writes too.
  IamDrizzleAdapter: {
    assignRoleMany: true,
    getSubjectGrantBoundary: true,
    getSubjectScopedRoles: true,
    revokeRoleMany: true,
    updateAssignmentScope: true,
    withClient: true,
  },
  IamFileAdapter: {
    assignRoleMany: false,
    getSubjectGrantBoundary: false,
    getSubjectScopedRoles: true,
    revokeRoleMany: false,
    updateAssignmentScope: true,
    withClient: false,
  },
  // http and redis have no `updateAssignmentScope`; the engine falls back to revoke-then-assign.
  IamHttpAdapter: {
    assignRoleMany: false,
    getSubjectGrantBoundary: false,
    getSubjectScopedRoles: true,
    revokeRoleMany: false,
    updateAssignmentScope: false,
    withClient: false,
  },
  IamMemoryAdapter: {
    assignRoleMany: false,
    getSubjectGrantBoundary: false,
    getSubjectScopedRoles: true,
    revokeRoleMany: false,
    updateAssignmentScope: true,
    withClient: false,
  },
  IamPrismaAdapter: {
    assignRoleMany: false,
    getSubjectGrantBoundary: false,
    getSubjectScopedRoles: true,
    revokeRoleMany: false,
    updateAssignmentScope: true,
    withClient: true,
  },
  IamRedisAdapter: {
    assignRoleMany: false,
    getSubjectGrantBoundary: false,
    getSubjectScopedRoles: true,
    revokeRoleMany: false,
    updateAssignmentScope: false,
    withClient: false,
  },
} as const satisfies Record<string, OptionalSupport>

export type ShippedAdapterName = keyof typeof OPTIONAL_SUPPORT
