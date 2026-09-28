import { Module } from '@nestjs/common'
import { CompaniesController } from './companies.controller'

@Module({
  controllers: [CompaniesController],
})
export class CompaniesModule {}
