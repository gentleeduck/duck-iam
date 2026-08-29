import type { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from './mysql.schema'

/** Row types for the duck-iam drizzle mysql schema. */
export namespace Mysql {
  export type PolicyRow = typeof iamPolicies.$inferSelect
  export type RoleRow = typeof iamRoles.$inferSelect
  export type AssignmentRow = typeof iamAssignments.$inferSelect
  export type AttrRow = typeof iamSubjectAttrs.$inferSelect
}
