import {
  ANONYMOUS_SUBJECT_ID,
  type AppAction,
  type AppResource,
  type AppRole,
  type AppScope,
  access,
  buildEngine,
} from '@examples/duck-iam-shared/iam'
import { createIamEngineProvider, IAM_ACCESS_ENGINE_TOKEN } from '@gentleduck/iam/server/nest'
import { Global, Module } from '@nestjs/common'
import { db } from '../db'
import { IamGuard } from './iam.guard'

export type { AppAction, AppResource, AppRole, AppScope }
export { ANONYMOUS_SUBJECT_ID, access, IAM_ACCESS_ENGINE_TOKEN }

const engineProvider = createIamEngineProvider(() => buildEngine(db))

@Global()
@Module({
  providers: [engineProvider, IamGuard],
  exports: [IAM_ACCESS_ENGINE_TOKEN, IamGuard],
})
export class IamModule {}
