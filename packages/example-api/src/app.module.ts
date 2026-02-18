import { Module } from '@nestjs/common'
import { APP_GUARD } from '@nestjs/core'
import { AccessGuard } from './access/access.guard'
import { AccessModule } from './access/access.module'
import { AdminModule } from './admin/admin.module'
import { PermissionsModule } from './permissions/permissions.module'
import { PostsModule } from './posts/posts.module'

@Module({
  imports: [AccessModule, PostsModule, AdminModule, PermissionsModule],
  providers: [
    // Register access guard globally — it only enforces on @Authorize() routes
    {
      provide: APP_GUARD,
      useClass: AccessGuard,
    },
  ],
})
export class AppModule {}
