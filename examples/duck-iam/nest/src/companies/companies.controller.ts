import { readTrimmedString } from '@examples/duck-iam-shared/body'
import { companyHasUsers } from '@examples/duck-iam-shared/deletion-guards'
import { companies } from '@examples/duck-iam-shared/schema'
import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Delete,
  Get,
  NotFoundException,
  Param,
  Patch,
  Req,
  UseGuards,
} from '@nestjs/common'
import { eq } from 'drizzle-orm'
import type { Request } from 'express'
import { CsrfGuard } from '../auth/csrf.guard'
import { db } from '../db'
import { Authorize } from '../iam/iam.decorators'
import { IamGuard } from '../iam/iam.guard'
import { sessionOf } from '../session/session'

// IAM only checks the action/resource grant, not which row `:id` names — filter the row explicitly.
function isOwnCompany(req: Request, id: string): boolean {
  return id === sessionOf(req)?.companyId
}

@Controller('companies')
@UseGuards(CsrfGuard, IamGuard)
export class CompaniesController {
  @Get(':id')
  @Authorize({ action: 'read', resource: 'companies' })
  async getOne(@Req() req: Request, @Param('id') id: string) {
    if (!isOwnCompany(req, id)) throw new NotFoundException({ error: 'not found' })
    const [row] = await db.select().from(companies).where(eq(companies.id, id)).limit(1)
    if (!row) throw new NotFoundException({ error: 'not found' })
    return row
  }

  @Patch(':id')
  @Authorize({ action: 'update', resource: 'companies' })
  async update(@Req() req: Request, @Param('id') id: string, @Body() body: unknown) {
    if (!isOwnCompany(req, id)) throw new NotFoundException({ error: 'not found' })
    const name = readTrimmedString(body, 'name')
    if (!name) throw new BadRequestException({ error: 'name required' })
    await db.update(companies).set({ name }).where(eq(companies.id, id))
    return { ok: true }
  }

  @Delete(':id')
  @Authorize({ action: 'delete', resource: 'companies' })
  async remove(@Req() req: Request, @Param('id') id: string) {
    if (!isOwnCompany(req, id)) throw new NotFoundException({ error: 'not found' })
    // Postgres would refuse this with an unhandled FK-violation 500 anyway (see deletion-guards.ts);
    // check first so the caller gets a clean, actionable response instead.
    if (await companyHasUsers(db, id))
      throw new ConflictException({ error: 'cannot delete a company that still has users' })
    await db.delete(companies).where(eq(companies.id, id))
    return { ok: true }
  }
}
