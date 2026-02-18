// src/app/api/posts/[id]/route.ts

import { withAccess } from 'access-engine/server/next'
import { engine } from '@/lib/access'
import { getUserIdFromRequest } from '@/lib/auth'
import { prisma } from '@/lib/prisma'

const authOpts = { getUserId: getUserIdFromRequest }

// ── GET /api/posts/:id ──

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params
  const post = await prisma.post.findUnique({
    where: { id },
    include: { author: { select: { id: true, name: true } } },
  })
  if (!post) return Response.json({ error: 'Not found' }, { status: 404 })
  return Response.json(post)
}

// ── PUT /api/posts/:id (requires "update" on "post") ──

async function updateHandler(req: Request, ctx: { params: Promise<Record<string, string>> | Record<string, string> }) {
  const { id } = await ctx.params
  const userId = getUserIdFromRequest(req)
  const body = (await req.json()) as { title?: string; body?: string }

  const post = await prisma.post.findUnique({ where: { id } })
  if (!post) return Response.json({ error: 'Not found' }, { status: 404 })

  // Re-check with resource attributes for owner-based rules
  const allowed = await engine.can(userId!, 'update', {
    type: 'post',
    id: post.id,
    attributes: { ownerId: post.authorId },
  })
  if (!allowed) return Response.json({ error: 'Forbidden' }, { status: 403 })

  const updated = await prisma.post.update({
    where: { id },
    data: { title: body.title, body: body.body },
  })
  return Response.json(updated)
}
export const PUT = withAccess(engine, 'update', 'post', updateHandler, authOpts)

// ── DELETE /api/posts/:id (requires "delete" on "post") ──

async function deleteHandler(req: Request, ctx: { params: Promise<Record<string, string>> | Record<string, string> }) {
  const { id } = await ctx.params
  const userId = getUserIdFromRequest(req)

  const post = await prisma.post.findUnique({ where: { id } })
  if (!post) return Response.json({ error: 'Not found' }, { status: 404 })

  const allowed = await engine.can(userId!, 'delete', {
    type: 'post',
    id: post.id,
    attributes: { ownerId: post.authorId },
  })
  if (!allowed) return Response.json({ error: 'Forbidden' }, { status: 403 })

  await prisma.post.delete({ where: { id } })
  return Response.json({ deleted: true })
}
export const DELETE = withAccess(engine, 'delete', 'post', deleteHandler, authOpts)
