import { Module } from '@nestjs/common'
import { MfaController } from './mfa.controller'

@Module({
  controllers: [MfaController],
})
export class MfaModule {}
