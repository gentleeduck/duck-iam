import 'reflect-metadata'
import { Module } from '@nestjs/common'
import { AuthModule } from './auth/auth.module'
import { MeModule } from './me/me.module'
import { MfaModule } from './mfa/mfa.module'

@Module({
  imports: [AuthModule, MfaModule, MeModule],
})
export class AppModule {}
