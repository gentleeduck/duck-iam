import { engine } from '@blogduck/shared'
import { createIamEngineProvider } from '@gentleduck/iam/server/nest'
import { Global, Module } from '@nestjs/common'
import { AccessGuard } from './access.guard'

const engineProvider = createIamEngineProvider(() => engine)

@Global()
@Module({
  providers: [engineProvider, AccessGuard],
  exports: [engineProvider, AccessGuard],
})
export class AccessModule {}
