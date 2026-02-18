// src/api/express-server.ts
//
// Standalone Express server example.
// Shows: global middleware, per-route guards, admin API, and attribute sync.
//
// Run with: npx tsx src/api/express-server.ts

import { accessMiddleware, guard } from 'access-engine/server/express'
import { generatePermissionMap } from 'access-engine/server/generic'
import express from 'express'
import { engine, policies, roles, STANDARD_CHECKS } from '../lib/access'
import { prisma } from '../lib/prisma'

const app = express()
app.use(express.json())

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Auth middleware (runs before access engine)
// Replace with passport, express-jwt, clerk, etc.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

app.use((req, _res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (token) {
    // In real app: verify JWT, decode claims
    ;(req as any).user = { id: token }
  }
  next()
})

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Option A: Global access middleware (checks ALL routes)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Uncomment to enable globally:
// app.use(accessMiddleware(engine, {
//   getUserId: (req) => (req as any).user?.id,
// }));

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Option B: Per-route guards (more granular, recommended)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const getUserId = (req: any) => req.user?.id ?? null
const guardOpts = { getUserId }

// ── Public routes (no guard) ──

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' })
})

// ── Posts CRUD ──

app.get('/api/posts', async (req, res) => {
  const posts = await prisma.post.findMany({
    where: { published: true },
    include: { author: { select: { id: true, name: true } } },
  })
  res.json(posts)
})

app.post('/api/posts', guard(engine, 'create', 'post', guardOpts), async (req, res) => {
  const userId = (req as any).user.id
  const post = await prisma.post.create({
    data: {
      title: req.body.title,
      body: req.body.body,
      authorId: userId,
    },
  })
  res.status(201).json(post)
})

app.put(
  '/api/posts/:id',
  // For resource-specific checks, we need to load the resource first
  async (req, res) => {
    const userId = (req as any).user?.id
    if (!userId) return res.status(401).json({ error: 'Unauthorized' })

    const post = await prisma.post.findUnique({ where: { id: req.params.id } })
    if (!post) return res.status(404).json({ error: 'Not found' })

    // Check with resource attributes (ownerId) for owner-based rules
    const allowed = await engine.can(userId, 'update', {
      type: 'post',
      id: post.id,
      attributes: { ownerId: post.authorId, published: post.published },
    })

    if (!allowed) return res.status(403).json({ error: 'Forbidden' })

    const updated = await prisma.post.update({
      where: { id: req.params.id },
      data: { title: req.body.title, body: req.body.body },
    })
    res.json(updated)
  },
)

app.delete('/api/posts/:id', async (req, res) => {
  const userId = (req as any).user?.id
  if (!userId) return res.status(401).json({ error: 'Unauthorized' })

  const post = await prisma.post.findUnique({ where: { id: req.params.id } })
  if (!post) return res.status(404).json({ error: 'Not found' })

  const allowed = await engine.can(userId, 'delete', {
    type: 'post',
    id: post.id,
    attributes: { ownerId: post.authorId },
  })

  if (!allowed) return res.status(403).json({ error: 'Forbidden' })

  await prisma.post.delete({ where: { id: req.params.id } })
  res.json({ deleted: true })
})

app.post('/api/posts/:id/publish', guard(engine, 'publish', 'post', guardOpts), async (req, res) => {
  await prisma.post.update({
    where: { id: req.params!.id },
    data: { published: true },
  })
  res.json({ published: true })
})

// ── Admin routes ──

app.get('/api/admin/users', guard(engine, 'manage', 'user', guardOpts), async (_req, res) => {
  const users = await prisma.user.findMany({ include: { org: true } })
  res.json(users)
})

app.get('/api/analytics', guard(engine, 'read', 'analytics', guardOpts), async (_req, res) => {
  // Only pro+ users reach here (enforced by plan-gating policy)
  res.json({ views: 12345, posts: 42 })
})

// ── Permissions endpoint (client fetches this) ──

app.get('/api/me/permissions', async (req, res) => {
  const userId = (req as any).user?.id
  if (!userId) return res.status(401).json({ error: 'Unauthorized' })

  const perms = await generatePermissionMap(engine, userId, STANDARD_CHECKS)
  res.json(perms)
})

// ── Attribute sync endpoint ──
// Call this when user data changes (plan upgrade, org suspension, etc.)

app.post('/api/admin/sync-attributes/:userId', guard(engine, 'manage', 'user', guardOpts), async (req, res) => {
  const userId = req.params!.userId as string
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: { org: true },
  })

  if (!user) return res.status(404).json({ error: 'User not found' })

  // Sync user data → access-engine attributes
  await engine.admin.setAttributes(userId, {
    plan: user.plan,
    orgId: user.orgId,
    orgStatus: user.org?.status ?? 'unknown',
  })

  engine.invalidate() // clear cache after sync
  res.json({ synced: true })
})

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Start
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const PORT = process.env.PORT ?? 3001
app.listen(PORT, () => {
  console.log(`Express server running on http://localhost:${PORT}`)
  console.log(`\nTest with:`)
  console.log(`  curl -H "Authorization: Bearer user-alice" http://localhost:${PORT}/api/me/permissions`)
  console.log(`  curl -H "Authorization: Bearer user-dave" http://localhost:${PORT}/api/analytics`)
})
