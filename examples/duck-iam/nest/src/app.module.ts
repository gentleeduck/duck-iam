import 'reflect-metadata'
import { type MiddlewareConsumer, Module, type NestModule } from '@nestjs/common'
import { AuthModule } from './auth/auth.module'
import { CompaniesModule } from './companies/companies.module'
import { HealthModule } from './health/health.module'
import { IamModule } from './iam/iam.module'
import { OrdersModule } from './orders/orders.module'
import { PermissionsModule } from './permissions/permissions.module'
import { ProductsModule } from './products/products.module'
import { SessionMiddleware } from './session/session'
import { UsersModule } from './users/users.module'

@Module({
  imports: [
    IamModule,
    HealthModule,
    AuthModule,
    PermissionsModule,
    CompaniesModule,
    UsersModule,
    ProductsModule,
    OrdersModule,
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(SessionMiddleware).forRoutes('*')
  }
}
