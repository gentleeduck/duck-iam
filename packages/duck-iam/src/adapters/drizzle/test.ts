/**
 * Company (internal/staff) IAM engine.
 *
 * This is the COMPANY-facing permission domain: gentleduck staff operating the
 * platform -- organizations, billing, subscriptions, customer/staff users,
 * audit logs, API keys. Entirely separate from the end-user guild domain
 * in `../guild`.
 *
 * Every role and policy ID here is prefixed `company:` so it shares the
 * physical IAM tables with the guild domain without ever colliding on an ID.
 */

import { createIam } from '@gentleduck/iam'
import { IamDrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '@gentleduck/iam/adapters/drizzle/schema/pg'
import { and, eq } from 'drizzle-orm'
import { drizzle as pg } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'

const pool = new Pool()
const db = pg(pool, {
  schema: {
    iamPolicies: iamPolicies,
    iamRoles: iamRoles,
    iamAssignments: iamAssignments,
    iamSubjectAttrs: iamSubjectAttrs,
  },
})

// ==========================================
// 1. Access Control Definitions
// ==========================================

export const companyAccess = createIam({
  actions: ['read', 'create'] as const,
  resources: ['organizations', 'billing'] as const,
  roles: ['company:readonly', 'company:support'] as const,
})

export namespace ICompanyIam {
  export type IAction = (typeof companyAccess.actions)[number]
  export type IResource = (typeof companyAccess.resources)[number]
  export type IRole = (typeof companyAccess.roles)[number]
  export type IScope = (typeof companyAccess.scopes)[number]
}

// ==========================================
// 2. Adapter & Engine Instantiation
// ==========================================

export const companyAdapter = new IamDrizzleAdapter<
  ICompanyIam.IAction,
  ICompanyIam.IResource,
  ICompanyIam.IRole,
  ICompanyIam.IScope
>({
  db: db,
  tables: {
    policies: iamPolicies,
    roles: iamRoles,
    assignments: iamAssignments,
    attrs: iamSubjectAttrs,
  },
  ops: { eq, and },
})

export const companyEngine = companyAccess.createEngine({
  adapter: companyAdapter,
  cacheTTL: 30,
})
