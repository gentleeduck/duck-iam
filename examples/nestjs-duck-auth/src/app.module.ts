import 'reflect-metadata'
import { Module } from '@nestjs/common'
import { AuthModule } from './auth/auth.module'
import { IamModule } from './iam/iam.module'
import { UsersModule } from './users/users.module'

@Module({
  imports: [AuthModule, IamModule, UsersModule],
})
export class AppModule {}
