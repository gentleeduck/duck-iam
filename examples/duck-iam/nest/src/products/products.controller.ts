import { randomUUID } from 'node:crypto'
import { readInt, readTrimmedString } from '@examples/duck-iam-shared/body'
import { products } from '@examples/duck-iam-shared/schema'
import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  NotFoundException,
  Param,
  Patch,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common'
import { and, eq } from 'drizzle-orm'
import type { Request } from 'express'
import { CsrfGuard } from '../auth/csrf.guard'
import { db } from '../db'
import { Authorize } from '../iam/iam.decorators'
import { IamGuard } from '../iam/iam.guard'
import { sessionOf } from '../session/session'

@Controller('products')
@UseGuards(CsrfGuard, IamGuard)
export class ProductsController {
  @Get()
  @Authorize({ action: 'read', resource: 'products' })
  async list(@Req() req: Request) {
    const companyId = sessionOf(req)?.companyId
    return companyId ? db.select().from(products).where(eq(products.companyId, companyId)) : []
  }

  @Post()
  @Authorize({ action: 'create', resource: 'products' })
  async create(@Req() req: Request, @Body() body: unknown) {
    const session = sessionOf(req)
    const name = readTrimmedString(body, 'name')
    const priceCents = readInt(body, 'priceCents', 0)
    if (!session?.companyId) throw new BadRequestException({ error: 'caller has no company scope' })
    if (!name || priceCents === undefined) {
      throw new BadRequestException({ error: 'name (string) and priceCents (non-negative integer) required' })
    }
    const id = randomUUID()
    await db.insert(products).values({ id, companyId: session.companyId, ownerId: session.id, name, priceCents })
    return { id, companyId: session.companyId, ownerId: session.id, name, priceCents }
  }

  // Same tenant-filter reasoning as companies.controller.ts.
  @Patch(':id')
  @Authorize({ action: 'update', resource: 'products' })
  async update(@Req() req: Request, @Param('id') id: string, @Body() body: unknown) {
    const companyId = sessionOf(req)?.companyId
    if (!companyId) throw new NotFoundException({ error: 'not found' })
    const patch: { name?: string; priceCents?: number } = {}
    const name = readTrimmedString(body, 'name')
    const priceCents = readInt(body, 'priceCents', 0)
    if (name !== undefined) patch.name = name
    if (priceCents !== undefined) patch.priceCents = priceCents
    // drizzle's `.set({})` throws "No values to set" rather than a clean response.
    if (Object.keys(patch).length === 0) {
      throw new BadRequestException({ error: 'name (string) or priceCents (non-negative integer) required' })
    }
    const updated = await db
      .update(products)
      .set(patch)
      .where(and(eq(products.id, id), eq(products.companyId, companyId)))
      .returning({ id: products.id })
    if (updated.length === 0) throw new NotFoundException({ error: 'not found' })
    return { ok: true }
  }

  @Delete(':id')
  @Authorize({ action: 'delete', resource: 'products' })
  async remove(@Req() req: Request, @Param('id') id: string) {
    const companyId = sessionOf(req)?.companyId
    if (!companyId) throw new NotFoundException({ error: 'not found' })
    const deleted = await db
      .delete(products)
      .where(and(eq(products.id, id), eq(products.companyId, companyId)))
      .returning({ id: products.id })
    if (deleted.length === 0) throw new NotFoundException({ error: 'not found' })
    return { ok: true }
  }
}
