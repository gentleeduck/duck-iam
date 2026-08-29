import type { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from './pg.schema'

/** Row types for the duck-iam drizzle pg schema. */
export namespace Pg {
  export type PolicyRow = typeof iamPolicies.$inferSelect
  export type RoleRow = typeof iamRoles.$inferSelect
  export type AssignmentRow = typeof iamAssignments.$inferSelect
  export type AttrRow = typeof iamSubjectAttrs.$inferSelect
}
