import { randomUUID } from 'node:crypto'
import { readInt, readString } from '@examples/duck-iam-shared/body'
import { isOrderStatus, ORDER_STATUSES, orders, products } from '@examples/duck-iam-shared/schema'
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

@Controller('orders')
@UseGuards(CsrfGuard, IamGuard)
export class OrdersController {
  @Get()
  @Authorize({ action: 'read', resource: 'orders' })
  async list(@Req() req: Request) {
    const companyId = sessionOf(req)?.companyId
    return companyId ? db.select().from(orders).where(eq(orders.companyId, companyId)) : []
  }

  @Post()
  @Authorize({ action: 'create', resource: 'orders' })
  async create(@Req() req: Request, @Body() body: unknown) {
    const session = sessionOf(req)
    const productId = readString(body, 'productId')
    const quantity = readInt(body, 'quantity', 1)
    if (!session?.companyId) throw new BadRequestException({ error: 'caller has no company scope' })
    if (!productId || quantity === undefined) {
      throw new BadRequestException({ error: 'productId (string) and quantity (positive integer) required' })
    }
    // Confirms the product belongs to the caller's own company before ordering it.
    const [product] = await db
      .select({ id: products.id })
      .from(products)
      .where(and(eq(products.id, productId), eq(products.companyId, session.companyId)))
      .limit(1)
    if (!product) throw new NotFoundException({ error: 'no such product in your company' })
    const id = randomUUID()
    await db.insert(orders).values({ id, companyId: session.companyId, ownerId: session.id, productId, quantity })
    return { id, companyId: session.companyId, ownerId: session.id, productId, quantity }
  }

  @Patch(':id')
  @Authorize({ action: 'update', resource: 'orders' })
  async update(@Req() req: Request, @Param('id') id: string, @Body() body: unknown) {
    const companyId = sessionOf(req)?.companyId
    if (!companyId) throw new NotFoundException({ error: 'not found' })
    const status = readString(body, 'status')
    if (!status || !isOrderStatus(status)) {
      throw new BadRequestException({ error: `status must be one of ${ORDER_STATUSES.join(', ')}` })
    }
    const updated = await db
      .update(orders)
      .set({ status })
      .where(and(eq(orders.id, id), eq(orders.companyId, companyId)))
      .returning({ id: orders.id })
    if (updated.length === 0) throw new NotFoundException({ error: 'not found' })
    return { ok: true }
  }

  @Delete(':id')
  @Authorize({ action: 'delete', resource: 'orders' })
  async remove(@Req() req: Request, @Param('id') id: string) {
    const companyId = sessionOf(req)?.companyId
    if (!companyId) throw new NotFoundException({ error: 'not found' })
    const deleted = await db
      .delete(orders)
      .where(and(eq(orders.id, id), eq(orders.companyId, companyId)))
      .returning({ id: orders.id })
    if (deleted.length === 0) throw new NotFoundException({ error: 'not found' })
    return { ok: true }
  }
}
