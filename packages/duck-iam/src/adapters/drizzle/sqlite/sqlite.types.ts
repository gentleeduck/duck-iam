import type { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from './sqlite.schema'

/** Row types for the duck-iam drizzle sqlite schema. */
export namespace Sqlite {
  export type PolicyRow = typeof iamPolicies.$inferSelect
  export type RoleRow = typeof iamRoles.$inferSelect
  export type AssignmentRow = typeof iamAssignments.$inferSelect
  export type AttrRow = typeof iamSubjectAttrs.$inferSelect
}
