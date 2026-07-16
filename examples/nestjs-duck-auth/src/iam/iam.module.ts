import { createIam } from '@gentleduck/iam'
import { IamDrizzleAdapter } from '@gentleduck/iam/adapters/drizzle'
import { createIamEngineProvider, IAM_ACCESS_ENGINE_TOKEN } from '@gentleduck/iam/server/nest'
import { Global, Module } from '@nestjs/common'
import { and, eq } from 'drizzle-orm'
import { db } from '../db'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../db/schema'
import { IamAdminController } from './iam.admin.controller'
import { IamGuard } from './iam.guard'

export { IAM_ACCESS_ENGINE_TOKEN }

export const access = createIam({
  roles: ['viewer', 'editor', 'admin'] as const,
  actions: ['create', 'read', 'update', 'delete'] as const,
  resources: ['post', 'user', 'settings'] as const,
  scopes: [] as const,
})

export type AppAction = (typeof access.actions)[number]
export type AppResource = (typeof access.resources)[number]
export type AppRole = (typeof access.roles)[number]

export const roleViewer = access.defineRole('viewer').name('Viewer').grant('read', 'post').build()

export const roleEditor = access
  .defineRole('editor')
  .name('Editor')
  .inherits('viewer')
  .grant('create', 'post')
  .grant('update', 'post')
  .build()

export const roleAdmin = access
  .defineRole('admin')
  .name('Admin')
  .inherits('editor')
  .grant('delete', 'post')
  .grant('create', 'user')
  .grant('read', 'user')
  .grant('update', 'user')
  .grant('delete', 'user')
  .grant('read', 'settings')
  .grant('update', 'settings')
  .build()

export const allRoles = [roleViewer, roleEditor, roleAdmin]

const engineProvider = createIamEngineProvider(() => {
  const adapter = new IamDrizzleAdapter<AppAction, AppResource, AppRole, never, typeof db, 'sqlite'>({
    db,
    tables: { policies: iamPolicies, roles: iamRoles, assignments: iamAssignments, attrs: iamSubjectAttrs },
    ops: { eq, and },
    json: 'string',
  })

  return access.createEngine({ adapter, cacheTTL: 30 })
})

@Global()
@Module({
  controllers: [IamAdminController],
  providers: [engineProvider, IamGuard],
  exports: [IAM_ACCESS_ENGINE_TOKEN, IamGuard],
})
export class IamModule {}
