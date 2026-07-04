export {
  authCredentialsTable as authCredentials,
  authIdentitiesTable as authIdentities,
  authSessionsTable as authSessions,
} from '@gentleduck/auth/adapters/drizzle/sqlite'

export {
  iamAssignments,
  iamPolicies,
  iamRoles,
  iamSubjectAttrs,
} from '@gentleduck/iam/adapters/drizzle/schema/sqlite'
