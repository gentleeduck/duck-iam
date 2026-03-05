import { engine } from '@gentleduck/example-shared'
import { Global, Module } from '@nestjs/common'
import { ACCESS_ENGINE_TOKEN, createEngineProvider } from 'duck-iam/server/nest'

@Global()
@Module({
  providers: [createEngineProvider(() => engine)],
  exports: [ACCESS_ENGINE_TOKEN],
})
export class AccessModule {}
