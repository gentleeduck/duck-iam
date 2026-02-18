/// <reference types="@cloudflare/workers-types" />
// src/api/hono-worker.ts
//
// Hono backend for Cloudflare Workers / Bun / Deno.
// Uses Drizzle + D1 instead of Prisma.
//
// wrangler.toml:
//   [[d1_databases]]
//   binding = "DB"
//   database_name = "my-app-db"
//   database_id = "xxx"

import { Engine } from 'access-engine'
import { DrizzleAdapter } from 'access-engine/adapters/drizzle'
import { and, eq } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/d1'
import type { Context, Next } from 'hono'
import { Hono } from 'hono'
import { accessAssignments, accessPolicies, accessRoles, accessSubjectAttrs, posts } from '../db/drizzle-schema'

interface Env {
  DB: D1Database
}

interface Variables {
  userId: string
}

type AppEnv = { Bindings: Env; Variables: Variables }
type AppContext = Context<AppEnv>

const app = new Hono<AppEnv>()

// ── Create engine per request (D1 binding is request-scoped) ──

function createEngine(db: D1Database) {
  const drizzleDb = drizzle(db)

  const adapter = new DrizzleAdapter({
    db: drizzleDb,
    tables: {
      policies: accessPolicies,
      roles: accessRoles,
      assignments: accessAssignments,
      attrs: accessSubjectAttrs,
    },
    ops: { eq, and },
  })

  return new Engine({ adapter, cacheTTL: 60 })
}

// ── Auth middleware ──

app.use('*', async (c: AppContext, next: Next) => {
  const token = c.req.header('authorization')?.replace('Bearer ', '')
  if (token) c.set('userId', token)
  await next()
})

// ── Routes ──

app.get('/api/posts', async (c: AppContext) => {
  const db = drizzle(c.env.DB)
  const allPosts = await db.select().from(posts).where(eq(posts.published, 1))
  return c.json(allPosts)
})

app.post('/api/posts', async (c: AppContext) => {
  const engine = createEngine(c.env.DB)
  const userId = c.get('userId')
  if (!userId) return c.json({ error: 'Unauthorized' }, 401)

  const allowed = await engine.can(userId, 'create', {
    type: 'post',
    attributes: {},
  })
  if (!allowed) return c.json({ error: 'Forbidden' }, 403)

  const body = await c.req.json()
  const db = drizzle(c.env.DB)
  await db.insert(posts).values({
    id: crypto.randomUUID(),
    title: body.title,
    body: body.body,
    authorId: userId,
  })

  return c.json({ created: true }, 201)
})

app.get('/api/me/permissions', async (c: AppContext) => {
  const userId = c.get('userId')
  if (!userId) return c.json({ error: 'Unauthorized' }, 401)

  const engine = createEngine(c.env.DB)
  const perms = await engine.permissions(userId, [
    { action: 'create', resource: 'post' },
    { action: 'read', resource: 'post' },
    { action: 'manage', resource: 'user' },
    { action: 'read', resource: 'analytics' },
    { action: 'access', resource: 'billing' },
  ])

  return c.json(perms)
})

export default app
